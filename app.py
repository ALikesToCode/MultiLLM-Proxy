import os
import json
import time
import logging
import psutil
from datetime import datetime
from typing import Any, Callable, Dict, Optional, Union

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    session,
    send_from_directory,
    Response
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import gzip
import io

# Import your own modules
from services.auth_service import AuthService
from services.metrics_service import MetricsService
from services.proxy_service import ProxyService
from services.cache_service import CacheService
from error_handlers import init_error_handlers, APIError
from config import DevelopmentConfig, ProductionConfig, Config
from proxy import PROVIDER_DETAILS

# Configure basic logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)


def login_required(func: Callable) -> Callable:
    """
    Decorator that checks if the user is authenticated.
    Redirects to the login page if not authenticated.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not AuthService.is_authenticated():
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper


def api_auth_required(func: Callable) -> Callable:
    """
    Decorator that checks if the request has a valid API key in
    the Authorization header (Bearer scheme).
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        logger.debug(f"Raw Authorization header: {auth_header}")

        if not auth_header:
            logger.error("No Authorization header found")
            return jsonify({
                'error': 'Authentication required',
                'message': (
                    'Please provide your API key in the Authorization header. '
                    'Example: Authorization: Bearer YOUR_API_KEY'
                )
            }), 401

        # Extract API key from header
        api_key = auth_header.replace('Bearer ', '').strip()
        logger.debug(f"Extracted API key: {api_key[:5]}...")

        admin_api_key = os.environ.get('ADMIN_API_KEY')
        if not admin_api_key:
            logger.error("ADMIN_API_KEY not configured in environment")
            return jsonify({
                'error': 'Server configuration error',
                'message': 'ADMIN_API_KEY not configured on server'
            }), 500

        logger.debug(f"Admin key first 5 chars: {admin_api_key[:5]}...")
        if api_key == admin_api_key:
            logger.info("Request authenticated with admin API key")
            return func(*args, **kwargs)

        # Otherwise, check user-defined API keys
        for username, user_data in AuthService._users.items():
            user_api_key = user_data.get('api_key')
            if user_api_key and user_api_key == api_key:
                logger.info(f"Request authenticated with user API key for {username}")
                return func(*args, **kwargs)

        logger.error(f"Invalid API key provided: {api_key[:5]}...")
        return jsonify({
            'error': 'Invalid API key',
            'message': 'The provided API key is not valid'
        }), 401
    return wrapper


def check_provider(provider: str, details: Dict[str, Any], app_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check the status of a provider by retrieving stats and verifying tokens.
    """
    metrics_service = MetricsService.get_instance()
    provider_stats = {}
    try:
        provider_stats = metrics_service.get_provider_stats(provider)
    except Exception as e:
        logger.error(f"Error fetching provider stats for {provider}: {str(e)}")

    try:
        if provider == 'googleai':
            # Check GoogleAI token
            token = AuthService.get_google_token()
            if not token:
                return {
                    'name': provider.upper(),
                    'description': details.get('description', ''),
                    'active': False,
                    'is_configured': False,
                    'endpoints': details.get('endpoints', []),
                    'status': 'error',
                    'error': 'Google AI token not configured',
                    'requests_24h': provider_stats.get('requests_24h', 0),
                    'success_rate': provider_stats.get('success_rate', 0),
                    'avg_latency': provider_stats.get('avg_latency', 0),
                    'example_curl': details.get('example_curl', '')
                }
            return {
                'name': provider.upper(),
                'description': details.get('description', ''),
                'active': True,
                'is_configured': True,
                'endpoints': details.get('endpoints', []),
                'status': 'ok',
                'requests_24h': provider_stats.get('requests_24h', 0),
                'success_rate': provider_stats.get('success_rate', 0),
                'avg_latency': provider_stats.get('avg_latency', 0),
                'example_curl': details.get('example_curl', '')
            }
        else:
            # Check other providers
            api_key = AuthService.get_api_key(provider)
            if not api_key:
                return {
                    'name': provider.upper(),
                    'description': details.get('description', ''),
                    'active': False,
                    'is_configured': False,
                    'endpoints': details.get('endpoints', []),
                    'status': 'error',
                    'error': f'{provider.upper()} API key not configured',
                    'requests_24h': provider_stats.get('requests_24h', 0),
                    'success_rate': provider_stats.get('success_rate', 0),
                    'avg_latency': provider_stats.get('avg_latency', 0),
                    'example_curl': details.get('example_curl', '')
                }
            return {
                'name': provider.upper(),
                'description': details.get('description', ''),
                'active': True,
                'is_configured': True,
                'endpoints': details.get('endpoints', []),
                'status': 'ok',
                'requests_24h': provider_stats.get('requests_24h', 0),
                'success_rate': provider_stats.get('success_rate', 0),
                'avg_latency': provider_stats.get('avg_latency', 0),
                'example_curl': details.get('example_curl', '')
            }
    except Exception as exc:
        logger.error(f"Error checking provider {provider}: {str(exc)}")
        return {
            'name': provider.upper(),
            'description': details.get('description', ''),
            'active': False,
            'is_configured': False,
            'endpoints': details.get('endpoints', []),
            'status': 'error',
            'error': str(exc),
            'requests_24h': provider_stats.get('requests_24h', 0),
            'success_rate': provider_stats.get('success_rate', 0),
            'avg_latency': provider_stats.get('avg_latency', 0),
            'example_curl': details.get('example_curl', '')
        }


def create_app() -> Flask:
    """
    Create and configure the Flask application.
    """
    load_dotenv()

    app = Flask(
        __name__,
        static_url_path='/static',
        template_folder='templates'
    )

    # Secure session handling
    app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')

    # Initialize CSRF protection
    csrf = CSRFProtect()
    csrf.init_app(app)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e: CSRFError):
        """
        Handle CSRF errors, returning JSON if it's an AJAX/JSON request.
        """
        error_msg = f"CSRF token missing or invalid: {str(e)}"
        if request.is_json or 'application/json' in request.headers.get('Accept', ''):
            return jsonify({'error': 'CSRF token missing or invalid', 'message': error_msg}), 400
        return render_template('error.html', error=error_msg), 400

    # Ensure needed directories exist
    for directory in ['static', 'templates']:
        dir_path = os.path.join(os.path.dirname(__file__), directory)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

    # Configure environment
    flask_env = os.environ.get('FLASK_ENV', 'production')
    if flask_env == 'development':
        app.config.from_object(DevelopmentConfig)
    else:
        app.config.from_object(ProductionConfig)

    # Copy static config values
    for key in dir(Config):
        if not key.startswith('_'):
            app.config[key] = getattr(Config, key)

    # Initialize error handlers
    init_error_handlers(app)

    # Initialize services
    AuthService.initialize()
    # If needed, also initialize CacheService here or in another place
    # CacheService.initialize()  # Example if needed

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
        Handle user login. On POST, authenticate with username+api_key.
        On GET, render the login template.
        """
        try:
            if request.method == 'POST':
                username = request.form.get('username')
                api_key = request.form.get('api_key')
                if AuthService.authenticate_user(username, api_key):
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('status_page'))
                return render_template('login.html', error="Invalid username or API key")

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
                # Attempt to render a basic form on GET
                try:
                    return render_template('login.html', error=error_msg)
                except Exception as inner_e:
                    logger.exception("Error rendering basic login template")
                    return f"Critical error: {str(inner_e)}", 500
            return jsonify({'error': error_msg}), 500

    @app.route('/logout')
    def logout():
        """
        Handle user logout.
        """
        AuthService.logout()
        return redirect(url_for('login'))

    @app.route('/users', methods=['GET', 'POST'])
    @login_required
    def manage_users():
        """
        User management page. GET returns list of users (JSON or HTML).
        POST creates a new user (admin only).
        """
        try:
            if request.method == 'POST':
                current_user = AuthService.get_current_user()
                if not current_user or not getattr(current_user, 'is_admin', False):
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
            if 'application/json' in request.headers.get('Accept', ''):
                return jsonify({'status': 'success', 'users': users})
            return render_template(
                'users.html',
                users=users,
                current_user=AuthService.get_current_user()
            )

        except APIError as e:
            status_code = e.status_code
            if 'application/json' in request.headers.get('Accept', ''):
                return jsonify({'status': 'error', 'message': str(e)}), status_code
            return render_template('error.html', error=str(e)), status_code

        except Exception as e:
            logger.error(f"Error in user management: {str(e)}")
            if 'application/json' in request.headers.get('Accept', ''):
                return jsonify({'status': 'error', 'message': str(e)}), 500
            return render_template('500.html', error=str(e)), 500

    @app.route('/users/<username>', methods=['DELETE'])
    @login_required
    def delete_user(username: str):
        """
        Delete a user by username.
        """
        try:
            AuthService.delete_user(username)
            return jsonify({'message': f'User {username} deleted successfully'})
        except APIError as e:
            return jsonify({'error': str(e)}), e.status_code

    @app.route('/users/<username>/rotate-key', methods=['POST'])
    @login_required
    def rotate_api_key(username: str):
        """
        Generate a new API key for a given user.
        """
        try:
            result = AuthService.rotate_api_key(username)
            return jsonify(result)
        except APIError as e:
            return jsonify({'error': str(e)}), e.status_code

    @app.route('/favicon.ico')
    def favicon():
        """
        Serve favicon
        """
        return send_from_directory(
            os.path.join(app.root_path, 'static'),
            'favicon.ico',
            mimetype='image/vnd.microsoft.icon'
        )

    @app.route('/static/<path:filename>')
    def static_files(filename: str):
        """
        Serve static files
        """
        return send_from_directory('static', filename)

    @app.before_request
    def handle_redirects():
        """
        For every request (except login, static, favicon), enforce authentication.
        Also handle direct requests to /<provider> endpoints.
        """
        # Skip auth for API routes with Authorization header
        if request.headers.get('Authorization'):
            return
            
        # Skip auth for static files and login
        if request.endpoint in ['login', 'static_files', 'favicon'] or request.path.startswith('/static/'):
            return

        if not AuthService.is_authenticated():
            if request.path == '/':
                return redirect(url_for('login'))
            if request.is_json:
                raise APIError("Authentication required", status_code=401)
            return redirect(url_for('login', next=request.url))

        # If user hits /provider directly, redirect to proxy
        sanitized_path = request.path.rstrip('/')
        if sanitized_path in [f'/{prov}' for prov in app.config['API_BASE_URLS']]:
            return proxy(sanitized_path.strip('/'))

    @app.route('/health')
    def health_check():
        """
        Health check endpoint.
        """
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
        """
        A status page showing available providers, system metrics, etc.
        """
        try:
            providers = {}
            errors = []

            metrics_service = MetricsService.get_instance()
            system = {
                'cpu_usage': round(psutil.cpu_percent(interval=1), 1),
                'memory_usage': round(psutil.virtual_memory().percent, 1),
                'start_time': metrics_service.start_time
            }

            stats = metrics_service.get_stats()
            users_info = {
                'total': len(AuthService.list_users()),
                'active_sessions': len(session.keys()) if session else 1,
                'recent_activity': len(metrics_service.get_recent_activity())
            }

            # Check each provider
            for provider, details in PROVIDER_DETAILS.items():
                try:
                    providers[provider] = check_provider(provider, details, app.config)
                except Exception as exc:
                    logger.error(f"Failed to check {provider}: {str(exc)}")
                    errors.append(f"Failed to check {provider}: {str(exc)}")
                    providers[provider] = {
                        'name': provider.upper(),
                        'active': False,
                        'status': 'error',
                        'error': str(exc)
                    }

            recent_activity = metrics_service.get_recent_activity()

            # Return JSON or HTML
            if 'application/json' in request.headers.get('Accept', ''):
                return jsonify({
                    'status': 'running',
                    'system': system,
                    'stats': stats,
                    'users': users_info,
                    'providers': providers,
                    'recent_activity': recent_activity,
                    'errors': errors if errors else None,
                    'user': AuthService.get_current_user()
                })
            return render_template(
                'status.html',
                system=system,
                stats=stats,
                users=users_info,
                providers=providers,
                recent_activity=recent_activity,
                errors=errors if errors else None,
                user=AuthService.get_current_user()
            )
        except Exception as e:
            logger.error(f"Status page error: {str(e)}")
            if 'application/json' in request.headers.get('Accept', ''):
                return jsonify({'status': 'error', 'message': str(e)}), 500
            return render_template('500.html', error=str(e)), 500

    @app.route('/<api_provider>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    @app.route('/<api_provider>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    @csrf.exempt
    @api_auth_required
    def proxy(api_provider: str, path: str = ''):
        """
        Proxy requests to the appropriate API provider.
        """
        start_time = time.time()
        try:
            if api_provider not in app.config['API_BASE_URLS']:
                raise APIError(f"Unsupported API provider: {api_provider}", status_code=400)

            base_url = app.config['API_BASE_URLS'][api_provider]
            # Special handling for 'groq'
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
                    project_id = app.config.get('PROJECT_ID', '')
                    base_url = (
                        f"https://us-central1-aiplatform.googleapis.com/v1beta1/projects/"
                        f"{project_id}/locations/us-central1/models"
                    )
                    path = ''

            url = f"{base_url}/{path}" if path else base_url
            logger.info(f"Proxying request to: {url}")

            # Acquire auth token
            auth_token = None
            if api_provider == 'googleai':
                auth_token = AuthService.get_google_token()
            else:
                auth_token = AuthService.get_api_key(api_provider)

            if not auth_token:
                raise APIError(f"API key not configured for {api_provider}", status_code=500)

            is_streaming = False
            if request.is_json:
                try:
                    body = request.get_json()
                    is_streaming = bool(body.get('stream', False))
                except Exception:
                    pass

            headers = ProxyService.prepare_headers(request.headers, api_provider, auth_token)
            request_data = ProxyService.filter_request_data(api_provider, request.get_data())

            response = ProxyService.make_request(
                method=request.method,
                url=url,
                headers=headers,
                params=request.args,
                data=request_data,
                api_provider=api_provider,
                use_cache=(request.method.upper() == 'GET' and not is_streaming)
            )

            # Track request metrics
            response_time = (time.time() - start_time) * 1000  # ms
            MetricsService.get_instance().track_request(
                provider=api_provider,
                status_code=response.status_code,
                response_time=response_time
            )

            # Handle streaming
            if is_streaming and response.headers.get('content-type', '').startswith('text/event-stream'):
                def generate_stream():
                    try:
                        for chunk in response.iter_lines(decode_unicode=True):
                            if chunk:
                                yield f"{chunk}\n"
                    except Exception as e:
                        logger.error(f"Error in streaming response: {str(e)}")
                        yield f"data: {json.dumps({'error': str(e)})}\n\n"

                return Response(
                    generate_stream(),
                    status=response.status_code,
                    content_type='text/event-stream',
                    headers={
                        'Cache-Control': 'no-cache',
                        'Connection': 'keep-alive',
                        'X-Accel-Buffering': 'no'
                    }
                )

            return Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('content-type', 'application/json'),
                headers={
                    k: v for k, v in response.headers.items()
                    if k.lower() not in ['content-encoding', 'content-length', 'transfer-encoding']
                }
            )

        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            status_code = 500
            if isinstance(e, APIError):
                status_code = e.status_code

            MetricsService.get_instance().track_request(
                provider=api_provider,
                status_code=status_code,
                response_time=response_time
            )
            logger.error(f"Proxy error for {api_provider}: {str(e)}")
            if isinstance(e, APIError):
                raise e
            raise APIError(f"Proxy error: {str(e)}", status_code=500)

    @app.errorhandler(404)
    def not_found_error(error):
        """
        Handle 404 errors.
        """
        if request.path == '/favicon.ico':
            return send_from_directory('static', 'favicon.ico')
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        """
        Handle 500 errors.
        """
        logger.error(f"Internal server error: {str(error)}")
        return render_template('500.html'), 500

    @app.route('/status/updates')
    @login_required
    def status_updates():
        """
        Server-Sent Events endpoint for real-time status updates.
        Streams system, stats, and providers info.
        """
        def generate_updates():
            metrics_service = MetricsService.get_instance()

            while True:
                current_time = int(time.time())
                try:
                    # System metrics: update every 5 seconds
                    if current_time % 5 == 0:
                        system_data = {
                            'cpu_usage': round(psutil.cpu_percent(interval=1), 1),
                            'memory_usage': round(psutil.virtual_memory().percent, 1),
                            'start_time': metrics_service.start_time
                        }
                        yield f"event: system\ndata: {json.dumps(system_data)}\n\n"

                    # Request statistics: update every 10 seconds
                    if current_time % 10 == 0:
                        stats_data = metrics_service.get_stats()
                        yield f"event: stats\ndata: {json.dumps(stats_data)}\n\n"

                    # Recent activity: update every 3 seconds
                    if current_time % 3 == 0:
                        recent_activity = metrics_service.get_recent_activity()
                        yield f"event: activity\ndata: {json.dumps(recent_activity)}\n\n"

                    # Provider status: update every 30 seconds
                    if current_time % 30 == 0:
                        providers_info = {}
                        for prov, det in PROVIDER_DETAILS.items():
                            try:
                                providers_info[prov] = check_provider(prov, det, app.config)
                            except Exception as e:
                                logger.error(f"Error checking provider {prov}: {str(e)}")
                                providers_info[prov] = {
                                    'active': False,
                                    'status': 'error',
                                    'error': str(e)
                                }
                        yield f"event: providers\ndata: {json.dumps(providers_info)}\n\n"

                    time.sleep(1)

                except GeneratorExit:
                    break
                except Exception as e:
                    logger.error(f"Error generating status updates: {str(e)}")
                    yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                    time.sleep(5)

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
        """
        Handle chat completion requests and proxy them to the selected backend.
        """
        try:
            data = request.get_json()
            if not data:
                raise APIError("No request data provided")

            provider = data.get('provider', '').lower()
            if not provider:
                raise APIError("No provider specified")
            if provider not in PROVIDER_DETAILS:
                raise APIError(f"Unsupported provider: {provider}")

            # Check provider's authentication
            if provider == 'googleai':
                token = AuthService.get_google_token()
                if not token:
                    raise APIError("Google AI authentication token not configured")
            else:
                api_key = AuthService.get_api_key(provider)
                if not api_key:
                    raise APIError(f"{provider.upper()} API key not configured")

            proxy_service = ProxyService.get_instance()
            response = proxy_service.forward_request(provider, data)

            MetricsService.get_instance().track_request(
                provider=provider,
                endpoint='chat_completions',
                status='success',
                latency=response.get('latency', 0)
            )
            return jsonify(response)

        except APIError as e:
            logger.error(f"API Error in chat completions: {str(e)}")
            if 'provider' in locals():
                MetricsService.get_instance().track_request(
                    provider=provider,
                    endpoint='chat_completions',
                    status='error',
                    error=str(e)
                )
            return jsonify({'status': 'error', 'message': str(e)}), (
                401 if 'authentication' in str(e).lower() else 400
            )

        except Exception as e:
            logger.error(f"Unexpected error in chat completions: {str(e)}")
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
    @csrf.exempt
    @api_auth_required
    def google_chat_completions():
        """
        Specific endpoint for Google AI chat completions.
        """
        start_time = time.time()
        try:
            # Get and validate request data
            data = request.get_json()
            if not data:
                raise APIError("No request data provided")

            # Get and validate messages array
            if 'messages' not in data:
                raise APIError("Messages array is required", status_code=400)
            
            messages = data['messages']  # Use direct access to preserve original array
            if not isinstance(messages, list):
                raise APIError("Messages must be an array", status_code=400)
            if not messages:
                raise APIError("Messages array cannot be empty", status_code=400)

            # Validate message format
            for msg in messages:
                if not isinstance(msg, dict):
                    raise APIError("Each message must be an object", status_code=400)
                if 'role' not in msg:
                    raise APIError("Each message must have a 'role' field", status_code=400)
                if 'content' not in msg:
                    raise APIError("Each message must have a 'content' field", status_code=400)

            # Get Google token with retry on auth error
            def get_fresh_token():
                token = AuthService.get_google_token()
                if not token:
                    raise APIError("Google AI authentication token not configured", status_code=401)
                return token

            try:
                google_token = get_fresh_token()
                
                # Create a new instance of ProxyService
                proxy_service = ProxyService()
                
                # Prepare the request
                project_id = "gen-lang-client-0290064683"
                location = "us-central1"
                url = f"https://{location}-aiplatform.googleapis.com/v1beta1/projects/{project_id}/locations/{location}/endpoints/openapi/chat/completions"
                headers = ProxyService.prepare_headers(request.headers, 'googleai', google_token)
                
                # Prepare request data while preserving original messages and data
                request_data = {
                    'model': data.get('model', 'meta/llama-3.1-405b-instruct-maas'),
                    'messages': messages,  # Use the original messages array
                    'max_tokens': data.get('max_tokens', 1024),
                    'stream': data.get('stream', False),
                    'extra_body': data.get('extra_body', {
                        'google': {
                            'model_safety_settings': {
                                'enabled': False,
                                'llama_guard_settings': {}
                            }
                        }
                    })
                }
                
                logger.debug(f"Prepared request data: {json.dumps(request_data)}")
                
                # Make the request with all required parameters
                response = proxy_service.make_request(
                    method='POST',
                    url=url,
                    headers=headers,
                    params=request.args,
                    data=json.dumps(request_data).encode('utf-8'),  # Encode as bytes
                    api_provider='googleai',
                    use_cache=False
                )

                # If we get a 401, try refreshing the token and retry once
                if response.status_code == 401:
                    logger.info("Received 401, refreshing Google token and retrying...")
                    # Force token refresh by clearing the cached token
                    AuthService._google_token = None
                    AuthService._google_token_expiry = None
                    
                    # Get fresh token and retry
                    google_token = get_fresh_token()
                    headers = ProxyService.prepare_headers(request.headers, 'googleai', google_token)
                    response = proxy_service.make_request(
                        method='POST',
                        url=url,
                        headers=headers,
                        params=request.args,
                        data=json.dumps(request_data).encode('utf-8'),
                        api_provider='googleai',
                        use_cache=False
                    )

                # Track request with correct parameters
                response_time = (time.time() - start_time) * 1000
                MetricsService.get_instance().track_request(
                    provider='googleai',
                    status_code=response.status_code,
                    response_time=response_time
                )
                
                # Handle streaming response
                if request_data.get('stream', False):
                    def generate():
                        try:
                            # Check if response is gzipped
                            is_gzipped = response.headers.get('content-encoding', '').lower() == 'gzip'
                            
                            # For requests.Response objects
                            if hasattr(response, 'raw'):
                                buffer = io.BytesIO()
                                
                                # Read raw response in chunks
                                while True:
                                    chunk = response.raw.read(1024)
                                    if not chunk:
                                        break
                                        
                                    # If gzipped, accumulate chunks in buffer
                                    if is_gzipped:
                                        buffer.write(chunk)
                                    else:
                                        # Process uncompressed chunk directly
                                        try:
                                            chunk_str = chunk.decode('utf-8').strip()
                                            if chunk_str:
                                                for line in chunk_str.split('\n'):
                                                    line = line.strip()
                                                    if line and line.startswith('data: '):
                                                        try:
                                                            json_str = line[6:].strip()
                                                            if json_str == '[DONE]':
                                                                yield 'data: [DONE]\n\n'
                                                                continue
                                                            json_data = json.loads(json_str)
                                                            yield f"data: {json.dumps(json_data)}\n\n"
                                                        except json.JSONDecodeError as e:
                                                            logger.error(f"Error parsing JSON in stream: {e}")
                                                            continue
                                        except Exception as e:
                                            logger.error(f"Error processing chunk: {e}")
                                            continue
                                
                                # If gzipped, decompress and process the accumulated data
                                if is_gzipped:
                                    try:
                                        buffer.seek(0)
                                        with gzip.GzipFile(fileobj=buffer, mode='rb') as gz:
                                            decompressed = gz.read().decode('utf-8')
                                            for line in decompressed.split('\n'):
                                                line = line.strip()
                                                if line and line.startswith('data: '):
                                                    try:
                                                        json_str = line[6:].strip()
                                                        if json_str == '[DONE]':
                                                            yield 'data: [DONE]\n\n'
                                                            continue
                                                        json_data = json.loads(json_str)
                                                        yield f"data: {json.dumps(json_data)}\n\n"
                                                    except json.JSONDecodeError as e:
                                                        logger.error(f"Error parsing JSON in decompressed stream: {e}")
                                                        continue
                                    except Exception as e:
                                        logger.error(f"Error decompressing gzipped response: {e}")
                        
                        except Exception as e:
                            logger.error(f"Error in streaming response: {e}")
                        finally:
                            yield "data: [DONE]\n\n"
                        
                    return Response(
                        generate(),
                        mimetype='text/event-stream',
                        headers={
                            'Cache-Control': 'no-cache',
                            'Connection': 'keep-alive',
                            'Content-Type': 'text/event-stream',
                            'X-Accel-Buffering': 'no'
                        }
                    )
                
                # Handle regular response
                try:
                    response_json = response.json()
                    return jsonify(response_json), response.status_code
                except (json.JSONDecodeError, AttributeError):
                    # If response is not JSON or has no json() method, return raw content
                    content = response.content if hasattr(response, 'content') else response.get_data()
                    
                    # Handle gzipped content
                    if response.headers.get('content-encoding', '').lower() == 'gzip':
                        content = gzip.decompress(content)
                    
                    return Response(
                        content,
                        status=response.status_code,
                        content_type=response.headers.get('content-type', 'application/json')
                    )

            except APIError as e:
                logger.error(f"API Error in Google chat completions: {str(e)}")
                response_time = (time.time() - start_time) * 1000
                MetricsService.get_instance().track_request(
                    provider='googleai',
                    status_code=e.status_code,
                    response_time=response_time
                )
                return jsonify({'status': 'error', 'message': str(e)}), (
                    401 if 'authentication' in str(e).lower() else 400
                )
            except Exception as e:
                logger.error(f"Unexpected error in Google chat completions: {str(e)}")
                response_time = (time.time() - start_time) * 1000
                MetricsService.get_instance().track_request(
                    provider='googleai',
                    status_code=500,
                    response_time=response_time
                )
                return jsonify({
                    'status': 'error',
                    'message': f"Internal server error: {str(e)}"
                }), 500

        except APIError as e:
            logger.error(f"API Error in Google chat completions: {str(e)}")
            response_time = (time.time() - start_time) * 1000
            MetricsService.get_instance().track_request(
                provider='googleai',
                status_code=e.status_code,
                response_time=response_time
            )
            return jsonify({'status': 'error', 'message': str(e)}), (
                401 if 'authentication' in str(e).lower() else 400
            )
        except Exception as e:
            logger.error(f"Unexpected error in Google chat completions: {str(e)}")
            response_time = (time.time() - start_time) * 1000
            MetricsService.get_instance().track_request(
                provider='googleai',
                status_code=500,
                response_time=response_time
            )
            return jsonify({
                'status': 'error',
                'message': f"Internal server error: {str(e)}"
            }), 500

    return app


# Create and run the app
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
