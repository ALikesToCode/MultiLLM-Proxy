import os
import subprocess
from datetime import datetime
import logging
from config import Config
from services.rate_limit_service import RateLimitService
from error_handlers import APIError

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
    def get_api_key(cls, provider):
        """Get API key for a specific provider"""
        if provider not in cls._api_keys:
            if provider == 'groq':
                # Only load Groq keys when specifically requested
                if not Config.GROQ_API_KEYS:
                    # Load Groq API keys from environment variables
                    groq_keys = []
                    i = 1
                    while True:
                        key = os.environ.get(f'GROQ_API_KEY_{i}')
                        if not key:
                            break
                        groq_keys.append(key)
                        i += 1
                    Config.GROQ_API_KEYS = groq_keys
                
                cls._api_keys[provider] = RateLimitService.get_next_groq_key()
            else:
                # For other providers, get from environment
                cls._api_keys[provider] = os.environ.get(f'{provider.upper()}_API_KEY')
        
        return cls._api_keys[provider]
    
    @classmethod
    def get_google_token(cls):
        """Get Google Cloud authentication token with better error handling"""
        now = datetime.now()
        
        # Check if we have a valid cached token
        if cls._google_token and cls._token_expiry and cls._token_expiry > now + Config.TOKEN_REFRESH_BUFFER:
            return cls._google_token
            
        try:
            # First check if GOOGLE_APPLICATION_CREDENTIALS is set
            creds_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
            if not creds_path:
                raise APIError(
                    "GOOGLE_APPLICATION_CREDENTIALS environment variable not set. "
                    "Please set it to the path of your service account key file.",
                    status_code=401
                )
            
            if not os.path.exists(creds_path):
                raise APIError(
                    f"Google credentials file not found at {creds_path}. "
                    "Please check the path in GOOGLE_APPLICATION_CREDENTIALS.",
                    status_code=401
                )
            
            # Try to get token using gcloud
            result = subprocess.run(
                ['gcloud', 'auth', 'print-access-token'],
                capture_output=True,
                text=True,
                timeout=10  # Add timeout to prevent hanging
            )
            
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
            
        except subprocess.TimeoutExpired:
            raise APIError("Timeout while getting Google token", status_code=504)
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode().strip() if e.stderr else str(e)
            raise APIError(f"Failed to get Google token: {error_msg}", status_code=401)
        except Exception as e:
            raise APIError(f"Unexpected error getting Google token: {str(e)}", status_code=500)