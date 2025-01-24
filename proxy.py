from config import Config

PROVIDER_DETAILS = {
    'openai': {
        'description': 'OpenAI API for GPT models and embeddings',
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/openai/v1/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"gpt-3.5-turbo\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            }
        ]
    },
    'cerebras': {
        'description': 'Cerebras AI models for text generation and chat',
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/cerebras/v1/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"cerebras/btlm-3b-8k\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            }
        ]
    },
    'googleai': {
        'description': 'Google AI with Gemini models for text and multimodal tasks',
        'endpoints': [
            {
                'url': '/predict',
                'curl': 'curl -X POST "http://localhost:1400/googleai/predict" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"google/gemini-pro\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            }
        ]
    },
    'xai': {
        'description': 'X.AI (formerly Twitter) language models',
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/xai/v1/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"x-1\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            }
        ]
    },
    'groq': {
        'description': 'Groq API for ultra-fast LLM inference',
        'endpoints': [
            {
                'url': '/openai/v1/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/groq/openai/v1/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"llama3-70b-8192\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            }
        ]
    },
    'azure': {
        'description': 'Azure AI models for text generation and chat',
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/azure/v1/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"gpt-4\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            }
        ]
    },
    'scaleway': {
        'description': 'Scaleway AI models for text generation',
        'endpoints': [
            {
                'url': '/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/scaleway/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"mistral\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            }
        ]
    },
    'hyperbolic': {
        'description': 'Hyperbolic AI models for text generation',
        'endpoints': [
            {
                'url': '/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/hyperbolic/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"mixtral-8x7b\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            }
        ]
    },
    'sambanova': {
        'description': 'SambaNova AI models for text generation and chat',
        'endpoints': [
            {
                'url': '/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/sambanova/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"sambanova-gpt\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            },
            {
                'url': '/completions',
                'curl': 'curl -X POST "http://localhost:1400/sambanova/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"sambanova-gpt\\", \\"prompt\\": \\"Hello!\\"}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'function_calling': False,
            'json_mode': False
        }
    },
    'openrouter': {
        'description': 'OpenRouter - Gateway to multiple AI models including Anthropic, Meta, Google, and more',
        'endpoints': [
            {
                'url': '/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/openrouter/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -H "HTTP-Referer: $YOUR_SITE_URL" -H "X-Title: $YOUR_APP_NAME" -d "{\\"model\\": \\"openai/gpt-3.5-turbo\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            },
            {
                'url': '/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/openrouter/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"anthropic/claude-2\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            },
            {
                'url': '/models',
                'curl': 'curl -X GET "http://localhost:1400/openrouter/models" -H "Authorization: Bearer $API_KEY"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'function_calling': True,
            'json_mode': True
        }
    },
    'nineteen': {
        'description': 'Nineteen AI - High-performance inference for open-source models',
        'endpoints': [
            {
                'url': '/v1/completions',
                'curl': 'curl -X POST "http://localhost:1400/nineteen/v1/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"TheBloke/Rogue-Rose-103b-v0.2-AWQ\\", \\"prompt\\": \\"Hello!\\", \\"temperature\\": 0.5, \\"max_tokens\\": 50, \\"top_p\\": 0.5, \\"stream\\": true}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'function_calling': False,
            'json_mode': False
        }
    },
    'palm': {
        'description': 'Google PaLM API for text generation and chat',
        'endpoints': [
            {
                'url': '/models/chat-bison-001/generateText',
                'curl': 'curl -X POST "http://localhost:1400/palm/models/chat-bison-001/generateText" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"prompt\\": {\\"messages\\": [{\\"content\\": \\"Hello!\\"}]}}"'
            },
            {
                'url': '/models/text-bison-001/generateText',
                'curl': 'curl -X POST "http://localhost:1400/palm/models/text-bison-001/generateText" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"prompt\\": \\"Hello!\\"}"'
            },
            {
                'url': '/models',
                'curl': 'curl -X GET "http://localhost:1400/palm/models" -H "Authorization: Bearer $API_KEY"'
            }
        ],
        'supported_features': {
            'streaming': False,
            'function_calling': False,
            'json_mode': False
        },
        'default_model': 'chat-bison-001'
    },
    'together': {
        'description': 'Together AI for high-performance open LLMs',
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/together/v1/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            },
            {
                'url': '/v1/models',
                'curl': 'curl -X GET "http://localhost:1400/together/v1/models" -H "Authorization: Bearer $API_KEY"'
            },
            {
                'url': '/v1/completions',
                'curl': 'curl -X POST "http://localhost:1400/together/v1/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo\\", \\"prompt\\": \\"Hello!\\"}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'function_calling': True,
            'json_mode': True
        },
        'default_model': 'meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo'
    }
} 