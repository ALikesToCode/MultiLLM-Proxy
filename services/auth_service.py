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

    @classmethod
    def initialize(cls):
        """Initialize the auth service."""
        # Load admin API key from environment
        cls._api_keys['admin'] = os.environ.get('ADMIN_API_KEY')
        
        # Load provider API keys from environment
        for provider in ['openai', 'cerebras', 'xai', 'groq', 'azure', 'scaleway', 
                        'hyperbolic', 'sambanova', 'openrouter', 'palm', 'together']:
            env_key = f'{provider.upper()}_API_KEY'
            api_key = os.environ.get(env_key)
            if api_key:
                cls._api_keys[provider] = api_key

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
                if (cls._google_token and cls._google_token_expiry and 
                    current_time < cls._google_token_expiry):
                    return cls._google_token

                # Get new token using gcloud command
                result = subprocess.run(
                    ['gcloud', 'auth', 'print-access-token'],
                    capture_output=True,
                    text=True,
                    check=True
                )

                token = result.stdout.strip()
                if token:
                    cls._google_token = token
                    cls._google_token_expiry = current_time + timedelta(minutes=45)
                    logger.info("Successfully cached new Google Cloud token for 45 minutes")
                    return token
                else:
                    logger.error("Empty token received from gcloud command")
                    return None

        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting Google token: {e.stderr}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting Google token: {str(e)}")
            return None