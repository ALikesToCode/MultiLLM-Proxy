import os
import json
import logging
from flask import Flask, request, Response, jsonify, url_for, send_from_directory, render_template
from dotenv import load_dotenv
from services.proxy_service import ProxyService
from services.auth_service import AuthService
from services.cache_service import CacheService
from error_handlers import init_error_handlers, APIError
from config import DevelopmentConfig, ProductionConfig, Config
from proxy import PROVIDER_DETAILS

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

def create_app():
    """Create and configure the Flask application."""
    # Load environment variables first
    load_dotenv()
    
    # Create Flask app with template and static directories
    app = Flask(__name__,
                static_url_path='/static',
                template_folder='templates')
    
    # Ensure required directories exist
    for directory in ['static', 'templates']:
        dir_path = os.path.join(os.path.dirname(__file__), directory)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
    
    # Configure app
    flask_env = os.environ.get('FLASK_ENV', 'production')
    app.config.from_object(DevelopmentConfig if flask_env == 'development' else ProductionConfig)
    
    # Copy config values
    for key in dir(Config):
        if not key.startswith('_'):
            app.config[key] = getattr(Config, key)
    
    # Initialize error handlers
    init_error_handlers(app)
    
    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon"""
        return send_from_directory(
            os.path.join(app.root_path, 'static'),
            'favicon.ico',
            mimetype='image/vnd.microsoft.icon'
        )
    
    @app.route('/static/<path:filename>')
    def static_files(filename):
        """Serve static files"""
        return send_from_directory('static', filename)
    
    @app.before_request
    def handle_redirects():
        """Handle redirects for provider endpoints"""
        if request.path.rstrip('/') in [f'/{provider}' for provider in app.config['API_BASE_URLS']]:
            return proxy(request.path.strip('/').split('/')[-1])
    
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        try:
            return jsonify({
                "status": "healthy",
                "config": {
                    "host": os.environ.get('SERVER_HOST', Config.DEFAULT_HOST),
                    "port": int(os.environ.get('SERVER_PORT', Config.DEFAULT_PORT))
                }
            }), 200
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/')
    def status_page():
        """Status page showing available providers"""
        try:
            providers = {}
            errors = []
            
            def check_provider(provider, details):
                try:
                    if provider == 'googleai':
                        token = AuthService.get_google_token()
                        return {
                            'active': bool(token),
                            'base_url': app.config['API_BASE_URLS'][provider],
                            'endpoints': details.get('endpoints', []),
                            'status': 'ok'
                        }
                    else:
                        api_key = AuthService.get_api_key(provider)
                        return {
                            'active': bool(api_key),
                            'base_url': app.config['API_BASE_URLS'][provider],
                            'endpoints': details.get('endpoints', []),
                            'status': 'ok'
                        }
                except Exception as e:
                    logger.error(f"Error checking provider {provider}: {str(e)}")
                    return {
                        'active': False,
                        'base_url': app.config['API_BASE_URLS'].get(provider, ''),
                        'endpoints': details.get('endpoints', []),
                        'status': 'error',
                        'error': str(e)
                    }
            
            # Check each provider independently
            for provider, details in PROVIDER_DETAILS.items():
                try:
                    providers[provider] = check_provider(provider, details)
                except Exception as e:
                    logger.error(f"Failed to check {provider}: {str(e)}")
                    errors.append(f"Failed to check {provider}: {str(e)}")
                    providers[provider] = {
                        'active': False,
                        'status': 'error',
                        'error': str(e)
                    }

            # Return JSON or HTML based on Accept header
            if request.headers.get('Accept', '').find('application/json') != -1:
                return jsonify({
                    'status': 'running',
                    'providers': providers,
                    'errors': errors if errors else None
                })
            else:
                return render_template('status.html',
                                    providers=providers,
                                    errors=errors if errors else None)

        except Exception as e:
            logger.error(f"Status page error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/<api_provider>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    @app.route('/<api_provider>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    def proxy(api_provider, path=''):
        """Main proxy endpoint"""
        try:
            # Validate provider
            if api_provider not in app.config['API_BASE_URLS']:
                raise APIError(f"Unsupported API provider: {api_provider}", status_code=400)

            # Construct URL
            base_url = app.config['API_BASE_URLS'][api_provider]
            if api_provider == 'groq':
                if path.startswith('v1/'):
                    path = f'openai/{path}'
                elif path and not path.startswith('openai/'):
                    path = f'openai/v1/{path}'
                elif not path:
                    path = 'openai/v1'
            elif api_provider == 'googleai':
                if path == 'models':
                    # Use models endpoint for listing models
                    base_url = f"https://us-central1-aiplatform.googleapis.com/v1beta1/projects/{Config.PROJECT_ID}/locations/us-central1/models"
                    path = ''
            
            url = f"{base_url}/{path}" if path else base_url
            logger.info(f"Proxying request to: {url}")

            # Get auth token
            auth_token = None
            if api_provider == 'googleai':
                auth_token = AuthService.get_google_token()
            else:
                auth_token = AuthService.get_api_key(api_provider)
            
            if not auth_token:
                raise APIError(f"API key not configured for {api_provider}", status_code=500)

            # Check if request is streaming
            is_streaming = False
            if request.is_json:
                try:
                    body = request.get_json()
                    is_streaming = body.get('stream', False)
                except Exception:
                    pass

            # Make request
            headers = ProxyService.prepare_headers(request.headers, api_provider, auth_token)
            request_data = ProxyService.filter_request_data(api_provider, request.get_data())
            
            response = ProxyService.make_request(
                method=request.method,
                url=url,
                headers=headers,
                params=request.args,
                data=request_data,
                api_provider=api_provider,
                use_cache=request.method.upper() == 'GET' and not is_streaming
            )

            # Handle streaming response
            if is_streaming and response.headers.get('content-type', '').startswith('text/event-stream'):
                def generate():
                    try:
                        for chunk in response.iter_lines(decode_unicode=True):
                            if chunk:
                                # Together AI sends properly formatted SSE data
                                # Just forward it as-is
                                yield f"{chunk}\n"
                    except Exception as e:
                        logger.error(f"Error in streaming response: {str(e)}")
                        yield f"data: {json.dumps({'error': str(e)})}\n\n"
                
                return Response(
                    generate(),
                    status=response.status_code,
                    content_type='text/event-stream',
                    headers={
                        'Cache-Control': 'no-cache',
                        'Connection': 'keep-alive',
                        'X-Accel-Buffering': 'no'  # Disable nginx buffering
                    }
                )

            # Handle normal response
            return Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('content-type', 'application/json'),
                headers={k: v for k, v in response.headers.items() 
                        if k.lower() not in ['content-encoding', 'content-length', 'transfer-encoding']}
            )

        except Exception as e:
            logger.error(f"Proxy error for {api_provider}: {str(e)}")
            if isinstance(e, APIError):
                raise e
            raise APIError(f"Proxy error: {str(e)}", status_code=500)
    
    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 errors"""
        if request.path == '/favicon.ico':
            return send_from_directory('static', 'favicon.ico')
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors"""
        logger.error(f"Internal server error: {str(error)}")
        return render_template('500.html'), 500
    
    return app

# Create app instance
app = create_app()

if __name__ == '__main__':
    try:
        port = int(os.environ.get('SERVER_PORT', Config.DEFAULT_PORT))
        host = os.environ.get('SERVER_HOST', '0.0.0.0')
        logger.info(f"Starting server on {host}:{port}")
        app.run(
            host=host,
            port=port,
            threaded=True,
            use_reloader=False,
            debug=False
        )
    except Exception as e:
        logger.error(f"Server failed to start: {str(e)}")
        raise
