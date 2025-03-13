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
import threading

logger = logging.getLogger(__name__)

class AuthService:
    """Service for handling user authentication and API key management."""
    
    _users = {}  # In-memory user storage
    _api_keys = {}  # In-memory API key storage
    _google_token = None
    _google_token_expiry = None
    _google_token_lock = threading.Lock()
    _jwt_secret = os.environ.get('JWT_SECRET', 'your-secret-key')

    @classmethod
    def initialize(cls):
        """Initialize the auth service."""
        # Load admin API key from environment
        cls._api_keys['admin'] = os.environ.get('ADMIN_API_KEY')
        
        # Initialize default admin user if none exists
        if not cls._users:
            default_username = os.environ.get('ADMIN_USERNAME', 'admin')
            default_api_key = os.environ.get('ADMIN_API_KEY')
            if default_api_key:
                cls._users[default_username] = {
                    'api_key_hash': generate_password_hash(default_api_key),
                    'is_admin': True,
                    'created_at': datetime.utcnow(),
                    'last_login': None,
                    'api_key': default_api_key
                }
                logger.info("Initialized default admin user")
        
        # Load provider API keys from environment
        for provider in ['openai', 'cerebras', 'xai', 'groq', 'azure', 'scaleway', 
                        'hyperbolic', 'sambanova', 'openrouter', 'palm', 'together', 'nineteen']:
            env_key = f'{provider.upper()}_API_KEY'
            api_key = os.environ.get(env_key)
            if api_key:
                cls._api_keys[provider] = api_key
        
        # Load Chutes API token from environment
        chutes_token = os.environ.get('CHUTES_API_TOKEN')
        if chutes_token:
            cls._api_keys['chutes'] = chutes_token
            
        # Load Gemini API key from environment
        gemini_key = os.environ.get('GEMINI_API_KEY')
        if gemini_key:
            cls._api_keys['gemini'] = gemini_key
            cls._api_keys['gemma'] = gemini_key  # Gemma uses the same API key

    @classmethod
    def get_api_key(cls, provider: str) -> Optional[str]:
        """Get API key for a provider."""
        # First check environment variable
        env_key = f'{provider.upper()}_API_KEY'
        api_key = os.environ.get(env_key)
        if api_key:
            return api_key
            
        # Then check stored API keys
        return cls._api_keys.get(provider)

    @classmethod
    def get_google_token(cls) -> Optional[str]:
        """Get Google Cloud access token."""
        try:
            with cls._google_token_lock:
                current_time = datetime.now()
                # Check if token exists and is still valid (with 5-minute buffer)
                if (cls._google_token and cls._google_token_expiry and 
                    current_time < cls._google_token_expiry - timedelta(minutes=5)):
                    logger.debug("Using cached Google Cloud token")
                    return cls._google_token

                logger.info("Getting new Google Cloud token via gcloud CLI")
                # Get new token using gcloud command with --quiet flag to avoid interactive prompts
                result = subprocess.run(
                    ['gcloud', 'auth', 'print-access-token', '--quiet'],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30  # Add timeout to prevent hanging
                )

                token = result.stdout.strip()
                if token:
                    cls._google_token = token
                    # Set expiry to 40 minutes instead of 45 to ensure we refresh before Google's actual expiry
                    cls._google_token_expiry = current_time + timedelta(minutes=40)
                    logger.info("Successfully cached new Google Cloud token for 40 minutes")
                    return token
                else:
                    logger.error("Empty token received from gcloud command")
                    cls._google_token = None
                    cls._google_token_expiry = None
                    return None

        except subprocess.CalledProcessError as e:
            error_output = e.stderr.decode('utf-8') if isinstance(e.stderr, bytes) else str(e.stderr)
            logger.error(f"Error getting Google token: {error_output}")
            # Clear token cache on error
            cls._google_token = None
            cls._google_token_expiry = None
            return None
        except subprocess.TimeoutExpired:
            logger.error("Timeout while getting Google token")
            # Clear token cache on error
            cls._google_token = None
            cls._google_token_expiry = None
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting Google token: {str(e)}")
            # Clear token cache on error
            cls._google_token = None
            cls._google_token_expiry = None
            return None

    @classmethod
    def is_authenticated(cls) -> bool:
        """Check if the current user is authenticated"""
        return bool(session.get('authenticated') and session.get('user'))

    @classmethod
    def get_current_user(cls) -> Optional[Dict[str, Any]]:
        """Get the current authenticated user"""
        if not cls.is_authenticated():
            return None
        return session.get('user')

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
                'api_key': api_key
            }
            session['authenticated'] = True
            return True
        return False

    @classmethod
    def logout(cls):
        """Log out the current user"""
        session.pop('user', None)
        session.pop('authenticated', None)

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