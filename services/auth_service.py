import os
import subprocess
from datetime import datetime
import logging
from config import Config

logger = logging.getLogger(__name__)

class AuthService:
    _google_token = None
    _token_expiry = None
    
    @staticmethod
    def get_api_keys():
        return {
            'openai': os.environ.get('OPENAI_API_KEY'),
            'cerebras': os.environ.get('CEREBRAS_API_KEY'),
            'xai': os.environ.get('XAI_API_KEY'),
        }
    
    @classmethod
    def get_google_token(cls):
        now = datetime.now()
        if cls._google_token and cls._token_expiry and cls._token_expiry > now + Config.TOKEN_REFRESH_BUFFER:
            return cls._google_token
            
        try:
            result = subprocess.run(
                ['gcloud', 'auth', 'print-access-token'], 
                capture_output=True, 
                text=True, 
                check=True
            )
            cls._google_token = result.stdout.strip()
            cls._token_expiry = now + Config.TOKEN_LIFETIME
            return cls._google_token
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get Google token: {str(e)}")
            return None 