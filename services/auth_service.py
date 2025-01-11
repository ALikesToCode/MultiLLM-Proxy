import os
import subprocess
from datetime import datetime, timedelta
import logging
from config import Config
from services.rate_limit_service import RateLimitService
from error_handlers import APIError
from typing import Optional, Dict, Any, Tuple, List
import time
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
import secrets
import string

logger = logging.getLogger(__name__)

class AuthService:
    _google_token = None
    _token_expiry = None
    _api_keys = {}  # Cache for API keys
    _users = {}  # In-memory user store (replace with database in production)
    _jwt_secret = os.environ.get('JWT_SECRET', 'your-secret-key')  # Use environment variable in production
    
    @classmethod
    def initialize(cls):
        """Initialize the auth service with default admin user if none exists"""
        if not cls._users:
            default_username = os.environ.get('ADMIN_USERNAME', 'admin')
            default_api_key = os.environ.get('ADMIN_API_KEY')
            if default_api_key:
                cls._users[default_username] = {
                    'api_key_hash': generate_password_hash(default_api_key),
                    'is_admin': True,
                    'created_at': datetime.utcnow(),
                    'last_login': None,
                    'api_key': default_api_key  # Store the actual API key for the admin
                }
                logger.info("Initialized default admin user")
    
    @classmethod
    def generate_api_key(cls, length: int = 40) -> str:
        """Generate a secure API key"""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @classmethod
    def create_user(cls, username: str, is_admin: bool = False) -> Dict[str, Any]:
        """Create a new user with a generated API key"""
        if not cls.get_current_user() or not cls.get_current_user().get('is_admin'):
            raise APIError("Only admins can create users", status_code=403)
            
        if username in cls._users:
            raise APIError("Username already exists", status_code=400)
            
        api_key = cls.generate_api_key()
        user = {
            'api_key_hash': generate_password_hash(api_key),
            'is_admin': is_admin,
            'created_at': datetime.utcnow(),
            'last_login': None,
            'api_key': api_key  # Include the API key in the response
        }
        cls._users[username] = user
        
        # Return user info with the API key (only time it's visible)
        return {
            'username': username,
            'api_key': api_key,
            'is_admin': is_admin,
            'created_at': user['created_at'].isoformat()
        }
    
    @classmethod
    def list_users(cls) -> List[Dict[str, Any]]:
        """List all users (admin only)"""
        if not cls.get_current_user() or not cls.get_current_user().get('is_admin'):
            raise APIError("Only admins can list users", status_code=403)
            
        return [
            {
                'username': username,
                'is_admin': user['is_admin'],
                'created_at': user['created_at'].isoformat(),
                'last_login': user['last_login'].isoformat() if user['last_login'] else None
            }
            for username, user in cls._users.items()
        ]
    
    @classmethod
    def delete_user(cls, username: str) -> None:
        """Delete a user (admin only)"""
        if not cls.get_current_user() or not cls.get_current_user().get('is_admin'):
            raise APIError("Only admins can delete users", status_code=403)
            
        if username not in cls._users:
            raise APIError("User not found", status_code=404)
            
        if username == cls.get_current_user()['username']:
            raise APIError("Cannot delete your own account", status_code=400)
            
        del cls._users[username]
    
    @classmethod
    def rotate_api_key(cls, username: str) -> Dict[str, str]:
        """Generate a new API key for a user (admin or self only)"""
        current_user = cls.get_current_user()
        if not current_user:
            raise APIError("Authentication required", status_code=401)
            
        if not current_user['is_admin'] and current_user['username'] != username:
            raise APIError("Can only rotate your own API key unless admin", status_code=403)
            
        if username not in cls._users:
            raise APIError("User not found", status_code=404)
            
        new_api_key = cls.generate_api_key()
        cls._users[username]['api_key_hash'] = generate_password_hash(new_api_key)
        cls._users[username]['api_key'] = new_api_key
        
        return {
            'username': username,
            'api_key': new_api_key
        }
    
    @classmethod
    def authenticate_user(cls, username: str, api_key: str) -> bool:
        """Authenticate a user with username and API key"""
        if username not in cls._users:
            return False
        
        user = cls._users[username]
        if check_password_hash(user['api_key_hash'], api_key):
            # Update last login
            user['last_login'] = datetime.utcnow()
            # Create session
            session['user'] = {
                'username': username,
                'is_admin': user.get('is_admin', False),
                'token': cls.generate_jwt_token(username),
                'api_key': api_key  # Store the API key in the session for use with providers
            }
            session['authenticated'] = True
            return True
        return False
    
    @classmethod
    def generate_jwt_token(cls, username: str) -> str:
        """Generate a JWT token for the user"""
        payload = {
            'username': username,
            'exp': datetime.utcnow() + timedelta(days=1)
        }
        return jwt.encode(payload, cls._jwt_secret, algorithm='HS256')
    
    @classmethod
    def verify_jwt_token(cls, token: str) -> Optional[Dict[str, Any]]:
        """Verify a JWT token and return the payload"""
        try:
            return jwt.decode(token, cls._jwt_secret, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise APIError("Token has expired", status_code=401)
        except jwt.InvalidTokenError:
            raise APIError("Invalid token", status_code=401)
    
    @classmethod
    def is_authenticated(cls) -> bool:
        """Check if the current user is authenticated"""
        return 'user' in session and session.get('user') and session.get('user').get('token') and session.get('authenticated')
    
    @classmethod
    def get_current_user(cls) -> Optional[Dict[str, Any]]:
        """Get the current authenticated user"""
        if not cls.is_authenticated():
            return None
        return session['user']
    
    @classmethod
    def logout(cls):
        """Log out the current user"""
        session.pop('user', None)
        session.pop('authenticated', None)
    
    @classmethod
    def get_api_keys(cls) -> Dict[str, str]:
        """Get API keys for all providers using the universal API key"""
        user = cls.get_current_user()
        if not user:
            return {}
            
        # Use the user's API key for all providers
        api_key = user.get('api_key')
        if not api_key:
            return {}
            
        return {
            'openai': api_key,
            'cerebras': api_key,
            'xai': api_key,
            'groq': api_key,
            'together': api_key,
            'googleai': api_key
        }
    
    @classmethod
    def get_api_key(cls, provider: str) -> Optional[str]:
        """Get API key for the specified provider"""
        user = cls.get_current_user()
        if not user:
            return None
            
        # Use the user's API key for all providers
        return user.get('api_key')
    
    @staticmethod
    def _get_google_token():
        """Get a Google Cloud access token using gcloud command"""
        try:
            cmd = [
                'gcloud', 'auth', 'print-access-token',
                '--scopes=https://www.googleapis.com/auth/cloud-platform'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            token = result.stdout.strip()
            if not token:
                raise APIError("Failed to get Google Cloud token: Empty token received")
            return token
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to get Google Cloud token: {e.stderr}"
            logger.error(error_msg)
            raise APIError(error_msg, status_code=500)
        except Exception as e:
            error_msg = f"Error getting Google Cloud token: {str(e)}"
            logger.error(error_msg)
            raise APIError(error_msg, status_code=500)

    @classmethod
    def get_google_token(cls):
        """Get a cached Google Cloud access token, refreshing if needed"""
        # First check if there's a direct API key configured
        user = cls.get_current_user()
        if user and user.get('api_key'):
            return user.get('api_key')
            
        # Then check environment variable
        env_key = os.environ.get('GOOGLE_API_KEY')
        if env_key:
            return env_key
            
        # Finally, try gcloud auth as fallback
        current_time = time.time()
        
        # Check if we have a cached token that's not expired
        if cls._google_token and cls._token_expiry > current_time:
            return cls._google_token
            
        # Get a new token
        token = cls._get_google_token()
        
        # Cache the token with 45-minute expiry
        cls._google_token = token
        cls._token_expiry = current_time + (45 * 60)  # 45 minutes
        
        return token
    
    @classmethod
    def invalidate_google_token(cls):
        """Invalidate the cached Google token to force a refresh."""
        cls._google_token = None
        cls._token_expiry = None
        logger.info("Invalidated Google Cloud token cache")