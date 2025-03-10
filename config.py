import os
from datetime import timedelta

class Config:
    PROJECT_ID = os.environ.get('PROJECT_ID')
    GOOGLE_APPLICATION_CREDENTIALS = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
    LOCATION = os.environ.get('LOCATION')
    ENDPOINT = os.environ.get('GOOGLE_ENDPOINT')
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
        'googleai': f'https://{ENDPOINT}/v1/projects/{PROJECT_ID}/locations/{LOCATION}/endpoints/openapi',
        'xai': 'https://api.x.ai',
        'groq': 'https://api.groq.com',
        'together': 'https://api.together.xyz',
        'azure': 'https://models.inference.ai.azure.com',
        'scaleway': 'https://api.scaleway.ai/672113a8-636a-4c18-8096-b0e7d4a4f6be/v1',
        'hyperbolic': 'https://api.hyperbolic.xyz/v1',
        'sambanova': 'https://api.sambanova.ai/v1',
        'openrouter': 'https://openrouter.ai/api/v1',
        'palm': 'https://generativelanguage.googleapis.com/v1beta',
        'nineteen': 'https://api.nineteen.ai',
        'chutes': 'https://llm.chutes.ai'
    }
    
    # Provider-specific timeouts (connect_timeout, read_timeout)
    API_TIMEOUTS = {
        'openai': (5, 60),
        'cerebras': (5, 60),
        'googleai': (10, 120),  # Google AI can be slow to respond
        'xai': (5, 60),
        'groq': (5, 120),
        'together': (5, 120),  # Together AI can take longer for larger models
        'azure': (10, 120),
        'scaleway': (5, 60),
        'hyperbolic': (5, 60),
        'sambanova': (5, 120),  # SambaNova can take longer for larger models
        'openrouter': (5, 120),  # OpenRouter can take longer as it routes to various providers
        'palm': (10, 120),  # PaLM API can be slow to respond
        'nineteen': (5, 120),
        'chutes': (5, 120),  # Chutes API can take longer for larger models
        'default': (5, 60)
    }
    
    # Provider-specific request retry settings
    API_RETRIES = {
        'openai': {'max_retries': 3, 'backoff_factor': 1},
        'cerebras': {'max_retries': 3, 'backoff_factor': 1},
        'googleai': {'max_retries': 5, 'backoff_factor': 2},  # More retries for Google AI
        'xai': {'max_retries': 3, 'backoff_factor': 1},
        'groq': {'max_retries': 3, 'backoff_factor': 1},
        'together': {'max_retries': 3, 'backoff_factor': 1},
        'azure': {'max_retries': 3, 'backoff_factor': 1},
        'scaleway': {'max_retries': 3, 'backoff_factor': 1},
        'hyperbolic': {'max_retries': 3, 'backoff_factor': 1},
        'sambanova': {'max_retries': 3, 'backoff_factor': 1},
        'openrouter': {'max_retries': 3, 'backoff_factor': 1},
        'palm': {'max_retries': 5, 'backoff_factor': 2},  # More retries for PaLM API
        'nineteen': {'max_retries': 3, 'backoff_factor': 1},
        'chutes': {'max_retries': 3, 'backoff_factor': 1},
        'default': {'max_retries': 3, 'backoff_factor': 1}
    }
    
    UNSUPPORTED_PARAMS = {
        'cerebras': ['frequency_penalty', 'presence_penalty', 'logit_bias'],
        'groq': ['logit_bias', 'logprobs', 'top_logprobs'],  # Parameters not supported by Groq
        'together': ['logit_bias'],  # Parameters not supported by Together AI
        'azure': ['logit_bias'],  # Parameters not supported by Azure
        'scaleway': ['logit_bias', 'frequency_penalty', 'presence_penalty'],  # Parameters not supported by Scaleway
        'hyperbolic': ['logit_bias'],  # Parameters not supported by Hyperbolic
        'sambanova': ['logit_bias', 'frequency_penalty', 'presence_penalty'],  # Parameters not supported by SambaNova
        'openrouter': ['logit_bias'],  # Parameters not supported by OpenRouter
        'palm': ['logit_bias', 'frequency_penalty', 'presence_penalty'],  # Parameters not supported by PaLM API
        'chutes': ['logit_bias']  # Parameters not supported by Chutes
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
    
    # Together AI models
    TOGETHER_MODELS = [
        'meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo',
        'meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo',
        'mistralai/Mixtral-8x7B-Instruct-v0.1',
        'mistralai/Mistral-7B-Instruct-v0.2',
        'NousResearch/Nous-Hermes-2-Yi-34B',
        'openchat/openchat-3.5-1210'
    ]
    
    # Chutes AI models
    CHUTES_MODELS = [
        'deepseek-ai/DeepSeek-V3'
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