import os
from datetime import timedelta

class Config:
    PROJECT_ID = 'gen-lang-client-0290064683'
    DEFAULT_PORT = 1400
    DEFAULT_HOST = 'localhost'
    REQUEST_TIMEOUT = 30
    TOKEN_REFRESH_BUFFER = timedelta(minutes=5)
    TOKEN_LIFETIME = timedelta(hours=1)
    
    # Get host and port from environment or use defaults
    SERVER_HOST = os.environ.get('SERVER_HOST', DEFAULT_HOST)
    SERVER_PORT = int(os.environ.get('SERVER_PORT', DEFAULT_PORT))
    
    # Construct the base URL
    SERVER_BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"
    
    API_BASE_URLS = {
        'openai': 'https://api.openai.com',
        'cerebras': 'https://api.cerebras.ai',
        'googleai': f'https://us-central1-aiplatform.googleapis.com/v1beta1/projects/{PROJECT_ID}/locations/us-central1/endpoints/openapi',
        'xai': 'https://api.x.ai',
    }
    
    UNSUPPORTED_PARAMS = {
        'cerebras': ['frequency_penalty', 'presence_penalty', 'logit_bias']
    }

class DevelopmentConfig(Config):
    DEBUG = True
    
class ProductionConfig(Config):
    DEBUG = False 