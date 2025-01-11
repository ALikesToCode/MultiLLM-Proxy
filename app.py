import os
import json
import time
import logging
import datetime
import psutil
from flask import (
    Flask, 
    request, 
    Response, 
    jsonify, 
    url_for, 
    send_from_directory, 
    render_template, 
    redirect, 
    session
)
from dotenv import load_dotenv
from services.proxy_service import ProxyService
from services.auth_service import AuthService
from services.cache_service import CacheService
from services.metrics_service import MetricsService
from error_handlers import init_error_handlers, APIError
from config import DevelopmentConfig, ProductionConfig, Config
from proxy import PROVIDER_DETAILS
from functools import wraps
from flask_wtf.csrf import CSRFProtect

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not AuthService.is_authenticated():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_provider(provider, details):
    """Check the status of a provider"""
    try:
        metrics_service = MetricsService.get_instance()
        provider_stats = metrics_service.get_provider_stats(provider)
        
        if provider == 'googleai':
            try:
                token = AuthService.get_google_token()
                if not token:
                    return {
                        'name': provider.upper(),
                        'description': details.get('description', ''),
                        'active': False,
                        'is_configured': False,
                        'base_url': app.config['API_BASE_URLS'].get(provider, ''),
                        'endpoints': details.get('endpoints', []),
                        'status': 'error',
                        'error': 'Google AI token not configured',
                        'requests_24h': provider_stats['requests_24h'],
                        'success_rate': provider_stats['success_rate'],
                        'avg_latency': provider_stats['avg_latency'],
                        'example_curl': details.get('example_curl', '')
                    }
            except Exception as auth_error:
                logger.error(f"Error getting Google AI token: {str(auth_error)}")
                return {
                    'name': provider.upper(),
                    'description': details.get('description', ''),
                    'active': False,
                    'is_configured': False,
                    'base_url': app.config['API_BASE_URLS'].get(provider, ''),
                    'endpoints': details.get('endpoints', []),
                    'status': 'error',
                    'error': f'Google AI authentication error: {str(auth_error)}',
                    'requests_24h': provider_stats['requests_24h'],
                    'success_rate': provider_stats['success_rate'],
                    'avg_latency': provider_stats['avg_latency'],
                    'example_curl': details.get('example_curl', '')
                }
            
            return {
                'name': provider.upper(),
                'description': details.get('description', ''),
                'active': bool(token),
                'is_configured': bool(token),
                'base_url': app.config['API_BASE_URLS'][provider],
                'endpoints': details.get('endpoints', []),
                'status': 'ok',
                'requests_24h': provider_stats['requests_24h'],
                'success_rate': provider_stats['success_rate'],
                'avg_latency': provider_stats['avg_latency'],
                'example_curl': details.get('example_curl', '')
            }
        else:
            try:
                api_key = AuthService.get_api_key(provider)
                if not api_key:
                    return {
                        'name': provider.upper(),
                        'description': details.get('description', ''),
                        'active': False,
                        'is_configured': False,
                        'base_url': app.config['API_BASE_URLS'].get(provider, ''),
                        'endpoints': details.get('endpoints', []),
                        'status': 'error',
                        'error': f'{provider.upper()} API key not configured',
                        'requests_24h': provider_stats['requests_24h'],
                        'success_rate': provider_stats['success_rate'],
                        'avg_latency': provider_stats['avg_latency'],
                        'example_curl': details.get('example_curl', '')
                    }
            except Exception as auth_error:
                logger.error(f"Error getting API key for {provider}: {str(auth_error)}")
                return {
                    'name': provider.upper(),
                    'description': details.get('description', ''),
                    'active': False,
                    'is_configured': False,
                    'base_url': app.config['API_BASE_URLS'].get(provider, ''),
                    'endpoints': details.get('endpoints', []),
                    'status': 'error',
                    'error': f'Authentication error: {str(auth_error)}',
                    'requests_24h': provider_stats['requests_24h'],
                    'success_rate': provider_stats['success_rate'],
                    'avg_latency': provider_stats['avg_latency'],
                    'example_curl': details.get('example_curl', '')
                }
            
            return {
                'name': provider.upper(),
                'description': details.get('description', ''),
                'active': bool(api_key),
                'is_configured': bool(api_key),
                'base_url': app.config['API_BASE_URLS'][provider],
                'endpoints': details.get('endpoints', []),
                'status': 'ok',
                'requests_24h': provider_stats['requests_24h'],
                'success_rate': provider_stats['success_rate'],
                'avg_latency': provider_stats['avg_latency'],
                'example_curl': details.get('example_curl', '')
            }
            
    except Exception as e:
        logger.error(f"Error checking provider {provider}: {str(e)}")
        return {
            'name': provider.upper(),
            'description': details.get('description', ''),
            'active': False,
            'is_configured': False,
            'base_url': app.config['API_BASE_URLS'].get(provider, ''),
            'endpoints': details.get('endpoints', []),
            'status': 'error',
            'error': str(e),
            'requests_24h': 0,
            'success_rate': 0,
            'avg_latency': 0,
            'example_curl': details.get('example_curl', '')
        }

def create_app():
    """Create and configure the Flask application."""
    # Load environment variables first
    load_dotenv()
    
    # Create Flask app with template and static directories
    app = Flask(__name__,
                static_url_path='/static',
                template_folder='templates')
    
    # Set secret key for sessions
    app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')  # Use environment variable in production
    
    # Initialize CSRF protection
    csrf = CSRFProtect()
    csrf.init_app(app)
    
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
    
    # Initialize auth service
    AuthService.initialize()
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Handle user login"""
        try:
            if request.method == 'POST':
                username = request.form.get('username')
                api_key = request.form.get('api_key')
                
                if AuthService.authenticate_user(username, api_key):
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('status_page'))
                else:
                    return render_template('login.html', error="Invalid username or API key")
            
            # For GET requests, just render the template
            logger.info("Rendering login template")
            return render_template(
                'login.html',
                error=None,
                config={
                    'server_url': Config.SERVER_BASE_URL,
                    'providers': list(Config.API_BASE_URLS.keys())
                }
            )
        except Exception as e:
            logger.exception("Error in login route")
            error_msg = f"Login error: {str(e)}"
            if request.method == 'GET':
                # For GET requests, try rendering a basic login form without any extra context
                try:
                    return render_template('login.html', error=error_msg)
                except Exception as inner_e:
                    logger.exception("Error rendering basic login template")
                    return f"Critical error: {str(inner_e)}", 500
            return jsonify({'error': error_msg}), 500
    
    @app.route('/logout')
    def logout():
        """Handle user logout"""
        AuthService.logout()
        return redirect(url_for('login'))
    
    @app.route('/users', methods=['GET', 'POST'])
    @login_required
    def manage_users():
        """User management page"""
        try:
            if request.method == 'POST':
                if not current_user.is_admin:
                    raise APIError("Only admin users can create new users", status_code=403)
                
                username = request.form.get('username')
                is_admin = request.form.get('is_admin') == 'on'
                
                if not username:
                    raise APIError("Username is required", status_code=400)
                
                user = AuthService.create_user(username, is_admin)
                return jsonify({
                    'status': 'success',
                    'message': 'User created successfully',
                    'user': user
                })
            
            # GET request - return user list
            users = AuthService.list_users()
            if request.headers.get('Accept', '').find('application/json') != -1:
                return jsonify({
                    'status': 'success',
                    'users': users
                })
            else:
                return render_template(
                    'users.html',
                    users=users,
                    current_user=AuthService.get_current_user()
                )
                
        except APIError as e:
            if request.headers.get('Accept', '').find('application/json') != -1:
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), e.status_code
            else:
                return render_template('error.html', error=str(e)), e.status_code
        except Exception as e:
            logger.error(f"Error in user management: {str(e)}")
            if request.headers.get('Accept', '').find('application/json') != -1:
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), 500
            else:
                return render_template('500.html', error=str(e)), 500
    
    @app.route('/users/<username>', methods=['DELETE'])
    @login_required
    def delete_user(username):
        """Delete a user"""
        try:
            AuthService.delete_user(username)
            return jsonify({'message': f'User {username} deleted successfully'})
        except APIError as e:
            return jsonify({'error': str(e)}), e.status_code
    
    @app.route('/users/<username>/rotate-key', methods=['POST'])
    @login_required
    def rotate_api_key(username):
        """Generate a new API key for a user"""
        try:
            result = AuthService.rotate_api_key(username)
            return jsonify(result)
        except APIError as e:
            return jsonify({'error': str(e)}), e.status_code
    
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
        # Skip auth check for login page and static files
        if request.endpoint in ['login', 'static_files', 'favicon'] or request.path.startswith('/static/'):
            return
            
        # Require authentication for all other routes
        if not AuthService.is_authenticated():
            if request.path == '/':
                return redirect(url_for('login'))
            elif request.is_json:
                raise APIError("Authentication required", status_code=401)
            else:
                return redirect(url_for('login', next=request.url))
                
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
    @login_required
    def status_page():
        """Status page showing available providers"""
        try:
            providers = {}
            errors = []
            metrics_service = MetricsService.get_instance()
            
            # Get system metrics
            system = {
                'cpu_usage': round(psutil.cpu_percent(interval=1), 1),
                'memory_usage': round(psutil.virtual_memory().percent, 1),
                'start_time': metrics_service.start_time  # Add start_time to initial data
            }

            # Get request statistics
            stats = metrics_service.get_stats()

            # Get user statistics
            users = {
                'total': len(AuthService.list_users()),
                'active_sessions': len(session.keys()) if session else 1,
                'recent_activity': len(metrics_service.get_recent_activity())
            }

            # Check each provider independently
            for provider, details in PROVIDER_DETAILS.items():
                try:
                    providers[provider] = check_provider(provider, details)
                except Exception as e:
                    logger.error(f"Failed to check {provider}: {str(e)}")
                    errors.append(f"Failed to check {provider}: {str(e)}")
                    providers[provider] = {
                        'name': provider.upper(),
                        'active': False,
                        'status': 'error',
                        'error': str(e)
                    }

            # Get recent activity
            recent_activity = metrics_service.get_recent_activity()

            # Return JSON or HTML based on Accept header
            if request.headers.get('Accept', '').find('application/json') != -1:
                return jsonify({
                    'status': 'running',
                    'system': system,
                    'stats': stats,
                    'users': users,
                    'providers': providers,
                    'recent_activity': recent_activity,
                    'errors': errors if errors else None,
                    'user': AuthService.get_current_user()
                })
            else:
                return render_template(
                    'status.html',
                    system=system,
                    stats=stats,
                    users=users,
                    providers=providers,
                    recent_activity=recent_activity,
                    errors=errors if errors else None,
                    user=AuthService.get_current_user()
                )

        except Exception as e:
            logger.error(f"Status page error: {str(e)}")
            if request.headers.get('Accept', '').find('application/json') != -1:
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), 500
            else:
                return render_template('500.html', error=str(e)), 500

    @app.route('/<api_provider>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    @app.route('/<api_provider>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    @login_required
    def proxy(api_provider, path=''):
        """Main proxy endpoint"""
        start_time = time.time()
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

            # Track request metrics
            response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            MetricsService.get_instance().track_request(
                provider=api_provider,
                status_code=response.status_code,
                response_time=response_time
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
            # Track failed request
            response_time = (time.time() - start_time) * 1000
            MetricsService.get_instance().track_request(
                provider=api_provider,
                status_code=500 if not isinstance(e, APIError) else e.status_code,
                response_time=response_time
            )
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
    
    @app.route('/status/updates')
    @login_required
    def status_updates():
        """Server-sent events endpoint for real-time status updates"""
        def generate_updates():
            metrics_service = MetricsService.get_instance()
            
            while True:
                try:
                    # System metrics (update every 5 seconds)
                    if int(time.time()) % 5 == 0:
                        system = {
                            'cpu_usage': round(psutil.cpu_percent(interval=1), 1),
                            'memory_usage': round(psutil.virtual_memory().percent, 1),
                            'start_time': metrics_service.start_time  # Send start_time instead of formatted string
                        }
                        yield f"event: system\ndata: {json.dumps(system)}\n\n"
                    
                    # Request statistics (update every 10 seconds)
                    if int(time.time()) % 10 == 0:
                        stats = metrics_service.get_stats()
                        yield f"event: stats\ndata: {json.dumps(stats)}\n\n"
                    
                    # Recent activity (update every 3 seconds)
                    if int(time.time()) % 3 == 0:
                        recent_activity = metrics_service.get_recent_activity()
                        yield f"event: activity\ndata: {json.dumps(recent_activity)}\n\n"
                    
                    # Provider status (update every 30 seconds)
                    if int(time.time()) % 30 == 0:
                        providers = {}
                        for provider, details in PROVIDER_DETAILS.items():
                            try:
                                provider_stats = metrics_service.get_provider_stats(provider)
                                if provider == 'googleai':
                                    token = AuthService.get_google_token()
                                    providers[provider] = {
                                        'active': bool(token),
                                        'status': 'ok',
                                        'requests_24h': provider_stats['requests_24h'],
                                        'success_rate': provider_stats['success_rate'],
                                        'avg_latency': provider_stats['avg_latency']
                                    }
                                else:
                                    api_key = AuthService.get_api_key(provider)
                                    providers[provider] = {
                                        'active': bool(api_key),
                                        'status': 'ok',
                                        'requests_24h': provider_stats['requests_24h'],
                                        'success_rate': provider_stats['success_rate'],
                                        'avg_latency': provider_stats['avg_latency']
                                    }
                            except Exception as e:
                                logger.error(f"Error checking provider {provider}: {str(e)}")
                                providers[provider] = {
                                    'active': False,
                                    'status': 'error',
                                    'error': str(e)
                                }
                        yield f"event: providers\ndata: {json.dumps(providers)}\n\n"
                    
                    time.sleep(1)  # Sleep for 1 second between checks
                    
                except GeneratorExit:
                    break
                except Exception as e:
                    logger.error(f"Error generating status updates: {str(e)}")
                    yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                    time.sleep(5)  # Wait a bit before retrying after an error
        
        return Response(
            generate_updates(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'
            }
        )
    
    @app.route('/api/backends/chat-completions/generate', methods=['POST'])
    @login_required
    def proxy_chat_completions():
        """Handle chat completion requests and proxy them to the appropriate backend"""
        try:
            # Get the request data
            data = request.get_json()
            if not data:
                raise APIError("No request data provided")

            # Get the selected provider from the request
            provider = data.get('provider', '').lower()
            if not provider:
                raise APIError("No provider specified")

            # Check if the provider is supported
            if provider not in PROVIDER_DETAILS:
                raise APIError(f"Unsupported provider: {provider}")

            # Check authentication based on provider
            if provider == 'googleai':
                token = AuthService.get_google_token()
                if not token:
                    raise APIError("Google AI authentication token not configured")
            else:
                api_key = AuthService.get_api_key(provider)
                if not api_key:
                    raise APIError(f"{provider.upper()} API key not configured")

            # Get the proxy service instance
            proxy_service = ProxyService.get_instance()

            # Forward the request to the appropriate provider
            response = proxy_service.forward_request(provider, data)

            # Track the request in metrics
            MetricsService.get_instance().track_request(
                provider=provider,
                endpoint='chat_completions',
                status='success',
                latency=response.get('latency', 0)
            )

            return jsonify(response)

        except APIError as e:
            # Track failed request in metrics
            if 'provider' in locals():
                MetricsService.get_instance().track_request(
                    provider=provider,
                    endpoint='chat_completions',
                    status='error',
                    error=str(e)
                )
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 401 if 'authentication' in str(e).lower() else 400

        except Exception as e:
            logger.error(f"Unexpected error in chat completions: {str(e)}")
            # Track failed request in metrics
            if 'provider' in locals():
                MetricsService.get_instance().track_request(
                    provider=provider,
                    endpoint='chat_completions',
                    status='error',
                    error=str(e)
                )
            return jsonify({
                'status': 'error',
                'message': f"Internal server error: {str(e)}"
            }), 500
    
    @app.route('/googleai/chat/completions', methods=['POST'])
    @login_required
    def google_chat_completions():
        """Handle Google AI chat completion requests"""
        try:
            # Get the request data
            data = request.get_json()
            if not data:
                raise APIError("No request data provided")

            # Check Google AI authentication
            token = AuthService.get_google_token()
            logger.info("Checking Google AI authentication...")
            
            # Log headers for debugging
            auth_header = request.headers.get('Authorization')
            logger.info(f"Received Authorization header: {auth_header}")

            if not token and not auth_header:
                raise APIError("Google AI authentication token not configured and no Authorization header provided")
            
            # If Authorization header is provided, use it instead of stored token
            if auth_header:
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                else:
                    token = auth_header

            # Get the proxy service instance
            proxy_service = ProxyService.get_instance()

            # Add the token to the request data
            data['auth_token'] = token

            # Forward the request to Google AI
            response = proxy_service.forward_request('googleai', data)

            # Track the request in metrics
            MetricsService.get_instance().track_request(
                provider='googleai',
                endpoint='chat_completions',
                status='success',
                latency=response.get('latency', 0)
            )

            return jsonify(response)

        except APIError as e:
            logger.error(f"API Error in Google chat completions: {str(e)}")
            # Track failed request in metrics
            MetricsService.get_instance().track_request(
                provider='googleai',
                endpoint='chat_completions',
                status='error',
                error=str(e)
            )
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 401 if 'authentication' in str(e).lower() else 400

        except Exception as e:
            logger.error(f"Unexpected error in Google chat completions: {str(e)}")
            # Track failed request in metrics
            MetricsService.get_instance().track_request(
                provider='googleai',
                endpoint='chat_completions',
                status='error',
                error=str(e)
            )
            return jsonify({
                'status': 'error',
                'message': f"Internal server error: {str(e)}"
            }), 500
    
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
