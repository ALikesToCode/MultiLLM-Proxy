import os
from datetime import timedelta

class Config:
    PROJECT_ID = 'gen-lang-client-0290064683'
    DEFAULT_PORT = 1400
    DEFAULT_HOST = '0.0.0.0'  # Listen on all interfaces
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
        'groq': 'https://api.groq.com'
    }
    
    # Provider-specific timeouts (connect_timeout, read_timeout)
    API_TIMEOUTS = {
        'openai': (5, 60),
        'cerebras': (5, 60),
        'googleai': (10, 120),  # Google AI can be slow to respond
        'xai': (5, 60),
        'groq': (5, 120),
        'default': (5, 60)
    }
    
    # Provider-specific request retry settings
    API_RETRIES = {
        'openai': {'max_retries': 3, 'backoff_factor': 1},
        'cerebras': {'max_retries': 3, 'backoff_factor': 1},
        'googleai': {'max_retries': 5, 'backoff_factor': 2},  # More retries for Google AI
        'xai': {'max_retries': 3, 'backoff_factor': 1},
        'groq': {'max_retries': 3, 'backoff_factor': 1},
        'default': {'max_retries': 3, 'backoff_factor': 1}
    }
    
    UNSUPPORTED_PARAMS = {
        'cerebras': ['frequency_penalty', 'presence_penalty', 'logit_bias'],
        'groq': ['logit_bias', 'logprobs', 'top_logprobs']  # Parameters not supported by Groq
    }

    # Groq specific settings
    GROQ_TOKEN_LIMIT = 6000  # Tokens per minute per API key
    GROQ_API_KEYS = []  # Will be populated from environment variables
    
    # Available Groq models
    GROQ_MODELS = [
        'llama3-groq-70b-8192-tool-use-preview',
        'gemma2-9b-it',
        'llama3-8b-8192',
        'llama-3.2-90b-vision-preview',
        'llama3-70b-8192',
        'llama-3.2-11b-vision-preview',
        'llama-3.2-11b-text-preview',
        'whisper-large-v3-turbo',
        'llava-v1.5-7b-4096-preview',
        'llama-3.1-70b-versatile',
        'llama-3.2-3b-preview',
        'whisper-large-v3',
        'llama-guard-3-8b',
        'mixtral-8x7b-32768',
        'gemma-7b-it',
        'distil-whisper-large-v3-en',
        'llama-3.2-1b-preview',
        'llama-3.2-90b-text-preview',
        'llama3-groq-8b-8192-tool-use-preview',
        'llama-3.1-8b-instant'
    ]
    
    # Groq supported parameters and their defaults
    GROQ_PARAMS = {
        'frequency_penalty': {'type': 'number', 'default': 0, 'min': -2.0, 'max': 2.0},
        'presence_penalty': {'type': 'number', 'default': 0, 'min': -2.0, 'max': 2.0},
        'max_tokens': {'type': 'integer', 'default': None},
        'n': {'type': 'integer', 'default': 1, 'max': 1},  # Only n=1 is supported
        'temperature': {'type': 'number', 'default': 1, 'min': 0, 'max': 2},
        'top_p': {'type': 'number', 'default': 1, 'min': 0, 'max': 1},
        'stream': {'type': 'boolean', 'default': False},
        'stop': {'type': ['string', 'array'], 'default': None, 'max_sequences': 4}
    }

class DevelopmentConfig(Config):
    DEBUG = True
    
class ProductionConfig(Config):
    DEBUG = False 