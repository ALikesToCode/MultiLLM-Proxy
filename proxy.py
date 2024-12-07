from config import Config

PROVIDER_DETAILS = {
    'openai': {
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': ''
            }
        ]
    },
    'cerebras': {
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': ''
            }
        ]
    },
    'googleai': {
        'endpoints': [
            {
                'url': '/predict',
                'curl': ''
            }
        ]
    },
    'xai': {
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': ''
            }
        ]
    },
    'groq': {
        'endpoints': [
            {
                'url': '/openai/v1/chat/completions',
                'curl': ''
            },
            {
                'url': '/openai/v1/models',
                'curl': ''
            },
            {
                'url': '/openai/v1/audio/transcriptions',
                'curl': ''
            },
            {
                'url': '/openai/v1/audio/translations',
                'curl': ''
            }
        ],
        'supported_audio_formats': [
            'flac', 'mp3', 'mp4', 'mpeg', 'mpga', 'm4a', 'ogg', 'wav', 'webm'
        ],
        'audio_models': [
            'whisper-large-v3',
            'whisper-large-v3-turbo',
            'distil-whisper-large-v3-en'
        ],
        'response_formats': ['json', 'text', 'verbose_json']
    }
} 