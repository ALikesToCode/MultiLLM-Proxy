from flask import Flask, request, Response, render_template, jsonify, send_from_directory
from dotenv import load_dotenv
from services.proxy_service import ProxyService
from services.auth_service import AuthService
from services.cache_service import CacheService
from error_handlers import init_error_handlers, APIError
from middleware.compression import compress_response
import os
from config import DevelopmentConfig, ProductionConfig, Config
from proxy import PROVIDER_DETAILS

def ensure_favicons():
    """Ensure favicon files exist, generate them if they don't"""
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    required_files = [
        'favicon.ico',
        'favicon-16x16.png',
        'favicon-32x32.png',
        'favicon-192x192.png',
        'favicon-512x512.png',
        'apple-touch-icon.png',
        'site.webmanifest'
    ]
    
    # Check if any required files are missing
    missing_files = [f for f in required_files if not os.path.exists(os.path.join(static_dir, f))]
    
    if missing_files:
        try:
            from scripts.generate_favicons import generate_favicons
            print("Generating favicon files...")
            generate_favicons()
            print("Favicon files generated successfully")
        except Exception as e:
            print(f"Warning: Failed to generate favicons: {str(e)}")

def ensure_static_directory():
    """Ensure static directory exists"""
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)
    return static_dir

def create_app():
    app = Flask(__name__, static_url_path='/static')
    
    load_dotenv()
    
    if os.environ.get('FLASK_ENV') == 'development':
        app.config.from_object(DevelopmentConfig)
    else:
        app.config.from_object(ProductionConfig)
    
    # Ensure static directory exists
    static_dir = ensure_static_directory()
    
    # Ensure favicons exist before starting the app
    ensure_favicons()
    
    init_error_handlers(app)
    return app

app = create_app()

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        filename
    )

@app.errorhandler(404)
def not_found_error(error):
    if request.path == '/favicon.ico':
        return send_from_directory(
            os.path.join(app.root_path, 'static'),
            'favicon.ico',
            mimetype='image/vnd.microsoft.icon'
        )
    return jsonify({"error": "Not found"}), 404

@app.route('/')
@compress_response
def status_page():
    providers = {}
    api_keys = AuthService.get_api_keys()
    
    for provider, details in PROVIDER_DETAILS.items():
        if provider == 'googleai':
            token = AuthService.get_google_token()
            providers[provider] = {
                'active': bool(token),
                'base_url': app.config['API_BASE_URLS'][provider],
                'endpoints': details['endpoints']
            }
        else:
            providers[provider] = {
                'active': bool(api_keys.get(provider)),
                'base_url': app.config['API_BASE_URLS'][provider],
                'endpoints': details['endpoints']
            }
    
    return render_template('status.html', 
                         providers=providers,
                         config=app.config)

@app.route('/<api_provider>/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<api_provider>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@compress_response
def proxy(api_provider, path):
    if api_provider not in app.config['API_BASE_URLS']:
        raise APIError(f"Unsupported API provider: {api_provider}", status_code=400)

    base_url = app.config['API_BASE_URLS'][api_provider]
    url = f"{base_url}/{path}" if path else base_url

    # Get authentication token
    if api_provider == 'googleai':
        auth_token = AuthService.get_google_token()
        if not auth_token:
            raise APIError("Failed to get Google Cloud access token", status_code=500)
    else:
        api_keys = AuthService.get_api_keys()
        auth_token = api_keys.get(api_provider)
        if not auth_token:
            raise APIError(f"API key not configured for {api_provider}", status_code=500)

    # Prepare request
    headers = ProxyService.prepare_headers(request.headers, api_provider, auth_token)
    request_data = ProxyService.filter_request_data(api_provider, request.get_data())
    
    # Make request
    response = ProxyService.make_request(
        method=request.method,
        url=url,
        headers=headers,
        params=request.args,
        data=request_data,
        api_provider=api_provider,
        use_cache=request.method.upper() == 'GET'
    )

    # Prepare response
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    response_headers = [(name, value) for (name, value) in response.raw.headers.items()
                       if name.lower() not in excluded_headers]

    return Response(response.content, response.status_code, response_headers)

@app.route('/health')
def health_check():
    try:
        # Add any necessary health checks here
        return jsonify({"status": "healthy"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.cli.command('clear-cache')
def clear_cache():
    """Clear the application cache"""
    CacheService.clear()
    print("Cache cleared successfully")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', Config.DEFAULT_PORT))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
