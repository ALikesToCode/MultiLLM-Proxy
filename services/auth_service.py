import os
import subprocess
from datetime import datetime
import logging
from config import Config
from services.rate_limit_service import RateLimitService
from error_handlers import APIError
from typing import Optional
import time

logger = logging.getLogger(__name__)

class AuthService:
    _google_token = None
    _token_expiry = None
    _api_keys = {}  # Cache for API keys
    
    @classmethod
    def get_api_keys(cls):
        """Get API keys, loading them only when needed"""
        return {
            'openai': os.environ.get('OPENAI_API_KEY'),
            'cerebras': os.environ.get('CEREBRAS_API_KEY'),
            'xai': os.environ.get('XAI_API_KEY'),
            'groq': None  # Don't get Groq key here
        }
    
    @classmethod
    def get_api_key(cls, provider: str) -> Optional[str]:
        """Get API key for the specified provider"""
        if provider == 'openai':
            return os.environ.get('OPENAI_API_KEY')
        elif provider == 'cerebras':
            return os.environ.get('CEREBRAS_API_KEY')
        elif provider == 'xai':
            return os.environ.get('XAI_API_KEY')
        elif provider == 'groq':
            # Load Groq API keys if not already loaded
            if not Config.GROQ_API_KEYS:
                i = 1
                while True:
                    key = os.environ.get(f'GROQ_API_KEY_{i}')
                    if not key:
                        break
                    Config.GROQ_API_KEYS.append(key)
                    i += 1
            # Return first available key
            return Config.GROQ_API_KEYS[0] if Config.GROQ_API_KEYS else None
        elif provider == 'together':
            return os.environ.get('TOGETHER_API_KEY')
        return None
    
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