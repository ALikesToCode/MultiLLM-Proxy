import os
import subprocess
from datetime import datetime
import logging
from config import Config
from services.rate_limit_service import RateLimitService
from error_handlers import APIError
from typing import Optional

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
    
    @classmethod
    def get_google_token(cls):
        """Get Google Cloud authentication token with better error handling"""
        now = datetime.now()
        
        # Check if we have a valid cached token
        if cls._google_token and cls._token_expiry and cls._token_expiry > now + Config.TOKEN_REFRESH_BUFFER:
            return cls._google_token
            
        try:
            # Check if gcloud is installed
            import shutil
            if not shutil.which('gcloud'):
                raise APIError(
                    "gcloud CLI not found. Please install Google Cloud SDK.",
                    status_code=500
                )
            
            # Try to get token using gcloud
            try:
                result = subprocess.run(
                    ['gcloud', 'auth', 'print-access-token'],
                    capture_output=True,
                    text=True,
                    timeout=10  # Add timeout to prevent hanging
                )
            except subprocess.TimeoutExpired:
                raise APIError("Timeout while getting Google token", status_code=504)
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.decode().strip() if e.stderr else str(e)
                if "not logged in" in error_msg.lower():
                    raise APIError(
                        "Not logged in to gcloud. Please run 'gcloud auth login' first.",
                        status_code=401
                    )
                elif "project" in error_msg.lower():
                    raise APIError(
                        "No Google Cloud project selected. Please run 'gcloud config set project YOUR_PROJECT_ID'",
                        status_code=401
                    )
                raise APIError(f"Failed to get Google token: {error_msg}", status_code=401)
            except Exception as e:
                raise APIError(f"Error running gcloud command: {str(e)}", status_code=500)
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "Unknown gcloud error"
                raise APIError(f"Failed to get Google token: {error_msg}", status_code=401)
            
            token = result.stdout.strip()
            if not token:
                raise APIError("Received empty token from gcloud", status_code=401)
            
            # Cache the token
            cls._google_token = token
            cls._token_expiry = now + Config.TOKEN_LIFETIME
            logger.info("Successfully obtained new Google auth token")
            
            return cls._google_token
            
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Unexpected error getting Google token: {str(e)}", status_code=500)

    @classmethod
    def invalidate_google_token(cls):
        """Invalidate the cached Google token to force a refresh."""
        cls._google_token = None
        cls._token_expiry = None
        logger.info("Invalidated Google Cloud token cache")