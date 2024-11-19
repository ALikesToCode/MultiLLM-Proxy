from flask import Flask, request, Response, render_template, jsonify
from dotenv import load_dotenv
from services.proxy_service import ProxyService
from services.auth_service import AuthService
from error_handlers import init_error_handlers, APIError
import os
from config import DevelopmentConfig, ProductionConfig
from proxy import PROVIDER_DETAILS

def create_app():
    app = Flask(__name__)
    
    load_dotenv()
    
    if os.environ.get('FLASK_ENV') == 'development':
        app.config.from_object(DevelopmentConfig)
    else:
        app.config.from_object(ProductionConfig)
    
    init_error_handlers(app)
    return app

app = create_app()

@app.route('/')
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
        data=request_data
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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', Config.DEFAULT_PORT))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
