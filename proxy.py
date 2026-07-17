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
    'opencode': {
        'description': 'OpenCode Zen Go plan - OpenAI-compatible access to curated models like Kimi K2.6',
        'endpoints': [
            {
                'url': '/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/opencode/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"kimi-k2.6\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}], \\"max_tokens\\": 128}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'json_mode': True
        },
        'default_model': 'kimi-k2.6'
    },
    'mimo': {
        'description': 'Xiaomi MiMo Token Plan - OpenAI-compatible access to MiMo-V2.5-Pro',
        'endpoints': [
            {
                'url': '/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/mimo/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"mimo-v2.5-pro\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}], \\"max_tokens\\": 128}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'function_calling': True,
            'json_mode': True
        },
        'default_model': 'mimo-v2.5-pro'
    },
    'nanogpt': {
        'description': 'NanoGPT - OpenAI-compatible access to chat, models, embeddings, images, audio, memory, and search',
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': 'curl -X POST "http://localhost:1400/nanogpt/v1/chat/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"$NANOGPT_MODEL\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            },
            {
                'url': '/v1/models?detailed=true',
                'curl': 'curl -X GET "http://localhost:1400/nanogpt/v1/models?detailed=true" -H "Authorization: Bearer $API_KEY"'
            },
            {
                'url': '/v1/embeddings',
                'curl': 'curl -X POST "http://localhost:1400/nanogpt/v1/embeddings" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"$NANOGPT_EMBEDDING_MODEL\\", \\"input\\": \\"NanoGPT embeddings\\"}"'
            },
            {
                'url': '/v1/audio/speech',
                'curl': 'curl -X POST "http://localhost:1400/nanogpt/v1/audio/speech" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"$NANOGPT_TTS_MODEL\\", \\"voice\\": \\"alloy\\", \\"input\\": \\"Welcome to NanoGPT.\\"}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'function_calling': True,
            'json_mode': True,
            'vision': True,
            'embeddings': True,
            'audio': True,
            'images': True,
            'web_search': True,
            'memory': True
        }
    },
    'codex-easy': {
        'description': 'Codex Everywhere raw OpenAI-compatible gateway; model catalogs are specific to each API-key group',
        'endpoints': [
            {
                'url': '/v1/models',
                'curl': 'curl -X GET "$PROXY_BASE_URL/codex-easy/v1/models" -H "Authorization: Bearer $ADMIN_API_KEY"'
            },
            {
                'url': '/v1/responses',
                'curl': 'curl -X POST "$PROXY_BASE_URL/codex-easy/v1/responses" -H "Authorization: Bearer $ADMIN_API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"grok-4.5\\", \\"reasoning\\": {\\"effort\\": \\"high\\"}, \\"prompt_cache_key\\": \\"conversation-123\\", \\"input\\": \\"Hello!\\", \\"stream\\": true}"'
            },
            {
                'url': '/v1/chat/completions',
                'curl': 'curl -X POST "$PROXY_BASE_URL/codex-easy/v1/chat/completions" -H "Authorization: Bearer $ADMIN_API_KEY" -H "X-Grok-Conv-Id: conversation-123" -H "Content-Type: application/json" -d "{\\"model\\": \\"grok-4.5\\", \\"reasoning_effort\\": \\"high\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}], \\"stream\\": true}"'
            },
            {
                'url': '/v1/images/generations',
                'curl': 'curl -X POST "$PROXY_BASE_URL/codex-easy/v1/images/generations" -H "Authorization: Bearer $ADMIN_API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"$CODEX_EASY_IMAGE_MODEL\\", \\"prompt\\": \\"A small red fox in a forest\\"}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'raw_streaming': True
        }
    },
    'kimi-code': {
        'description': 'Kimi Code OpenAI-compatible coding endpoint at https://api.kimi.com/coding/v1; Chat Completions model k3',
        'endpoints': [
            {
                'url': '/v1/models',
                'curl': 'curl -X GET "$PROXY_BASE_URL/kimi-code/v1/models" -H "Authorization: Bearer $ADMIN_API_KEY"'
            },
            {
                'url': '/v1/chat/completions',
                'curl': 'curl -X POST "$PROXY_BASE_URL/kimi-code/v1/chat/completions" -H "Authorization: Bearer $ADMIN_API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"k3\\", \\"reasoning_effort\\": \\"max\\", \\"prompt_cache_key\\": \\"conversation-123\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}], \\"stream\\": true}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'raw_streaming': True,
            'function_calling': True
        },
        'default_model': 'k3'
    },
    'linkapi': {
        'description': 'LinkAPI multi-cloud gateway with native Claude, Gemini, OpenAI Responses, and OpenAI-compatible passthrough',
        'endpoints': [
            {
                'url': '/v1/messages',
                'curl': 'curl -X POST "$PROXY_BASE_URL/linkapi/v1/messages" -H "x-api-key: $ADMIN_API_KEY" -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" -d "{\\"model\\": \\"$LINKAPI_MODEL\\", \\"max_tokens\\": 1024, \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            },
            {
                'url': '/v1/responses',
                'curl': 'curl -X POST "$PROXY_BASE_URL/linkapi/v1/responses" -H "Authorization: Bearer $ADMIN_API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"$LINKAPI_MODEL\\", \\"input\\": \\"Hello!\\"}"'
            },
            {
                'url': '/v1/chat/completions',
                'curl': 'curl -X POST "$PROXY_BASE_URL/linkapi/v1/chat/completions" -H "Authorization: Bearer $ADMIN_API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"$LINKAPI_MODEL\\", \\"messages\\": [{\\"role\\": \\"user\\", \\"content\\": \\"Hello!\\"}]}"'
            },
            {
                'url': '/v1beta/models/{model}:generateContent',
                'curl': 'curl -X POST "$PROXY_BASE_URL/linkapi/v1beta/models/$LINKAPI_MODEL:generateContent" -H "x-goog-api-key: $ADMIN_API_KEY" -H "Content-Type: application/json" -d "{\\"contents\\": [{\\"parts\\": [{\\"text\\": \\"Hello!\\"}]}]}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'raw_streaming': True
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
    },
    'chutes': {
        'description': 'Chutes AI - Access to DeepSeek and other models',
        'endpoints': [
            {
                'url': '/v1/completions',
                'curl': 'curl -X POST "http://localhost:1400/chutes/v1/completions" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" -d "{\\"model\\": \\"deepseek-ai/DeepSeek-V3\\", \\"prompt\\": \\"Hello!\\", \\"temperature\\": 0.7, \\"max_tokens\\": 100, \\"stream\\": true}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'function_calling': False,
            'json_mode': False
        },
        'default_model': 'deepseek-ai/DeepSeek-V3'
    },
    'gemini': {
        'description': 'Google Gemini models via Generative Language API',
        'endpoints': [
            {
                'url': '/models/gemini-2.0-flash:generateContent',
                'curl': 'curl -X POST "http://localhost:1400/gemini/models/gemini-2.0-flash:generateContent" -H "Content-Type: application/json" -d "{\\"contents\\": [{\\"parts\\":[{\\"text\\": \\"Explain how AI works\\"}]}], \\"safetySettings\\": [{\\"category\\": \\"HARM_CATEGORY_HARASSMENT\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_HATE_SPEECH\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_SEXUALLY_EXPLICIT\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_DANGEROUS_CONTENT\\", \\"threshold\\": \\"BLOCK_NONE\\"}]}"'
            },
            {
                'url': '/models/gemini-2.0-pro:generateContent',
                'curl': 'curl -X POST "http://localhost:1400/gemini/models/gemini-2.0-pro:generateContent" -H "Content-Type: application/json" -d "{\\"contents\\": [{\\"parts\\":[{\\"text\\": \\"Explain how AI works\\"}]}], \\"safetySettings\\": [{\\"category\\": \\"HARM_CATEGORY_HARASSMENT\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_HATE_SPEECH\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_SEXUALLY_EXPLICIT\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_DANGEROUS_CONTENT\\", \\"threshold\\": \\"BLOCK_NONE\\"}]}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'function_calling': True,
            'json_mode': True,
            'web_search': True  # Gemini has web search capability
        },
        'default_model': 'gemini-2.0-flash'
    },
    'gemma': {
        'description': 'Google Gemma open-source models via Generative Language API',
        'endpoints': [
            {
                'url': '/models/gemma-2-9b:generateContent',
                'curl': 'curl -X POST "http://localhost:1400/gemma/models/gemma-2-9b:generateContent" -H "Content-Type: application/json" -d "{\\"contents\\": [{\\"parts\\":[{\\"text\\": \\"Explain how AI works\\"}]}], \\"safetySettings\\": [{\\"category\\": \\"HARM_CATEGORY_HARASSMENT\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_HATE_SPEECH\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_SEXUALLY_EXPLICIT\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_DANGEROUS_CONTENT\\", \\"threshold\\": \\"BLOCK_NONE\\"}]}"'
            },
            {
                'url': '/models/gemma-1.1-7b-it:generateContent',
                'curl': 'curl -X POST "http://localhost:1400/gemma/models/gemma-1.1-7b-it:generateContent" -H "Content-Type: application/json" -d "{\\"contents\\": [{\\"parts\\":[{\\"text\\": \\"Explain how AI works\\"}]}], \\"safetySettings\\": [{\\"category\\": \\"HARM_CATEGORY_HARASSMENT\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_HATE_SPEECH\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_SEXUALLY_EXPLICIT\\", \\"threshold\\": \\"BLOCK_NONE\\"}, {\\"category\\": \\"HARM_CATEGORY_DANGEROUS_CONTENT\\", \\"threshold\\": \\"BLOCK_NONE\\"}]}"'
            }
        ],
        'supported_features': {
            'streaming': True,
            'function_calling': True,
            'json_mode': True
        },
        'default_model': 'gemma-2-9b'
    }
} 
