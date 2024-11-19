from config import Config

def get_curl_command(provider, endpoint):
    base_url = f"{Config.SERVER_BASE_URL}/{provider}{endpoint['url']}"
    return endpoint['curl'].replace('http://localhost:1400', Config.SERVER_BASE_URL)

PROVIDER_DETAILS = {
    'openai': {
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': get_curl_command('openai', {
                    'url': '/v1/chat/completions',
                    'curl': 'curl -X POST "http://localhost:1400/openai/v1/chat/completions" \\\n'
                           '    -H "Content-Type: application/json" \\\n'
                           '    -d \'{"model": "gpt-3.5-turbo","messages": [{"role": "user","content": "Hello!"}]}\''
                })
            }
        ]
    },
    'cerebras': {
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': get_curl_command('cerebras', {
                    'url': '/v1/chat/completions',
                    'curl': 'curl -X POST "http://localhost:1400/cerebras/v1/chat/completions" \\\n'
                           '    -H "Content-Type: application/json" \\\n'
                           '    -d \'{"model": "llama3.1-70b","messages": [{"role": "user","content": "Hello!"}]}\''
                })
            }
        ]
    },
    'googleai': {
        'endpoints': [
            {
                'url': '/predict',
                'curl': get_curl_command('googleai', {
                    'url': '/predict',
                    'curl': 'curl -X POST "http://localhost:1400/googleai/predict" \\\n'
                           '    -H "Content-Type: application/json" \\\n'
                           '    -d \'{\n'
                           '      "instances": [{\n'
                           '        "prompt": "What is the capital of France?"\n'
                           '      }]\n'
                           '    }\''
                })
            }
        ]
    },
    'xai': {
        'endpoints': [
            {
                'url': '/v1/chat/completions',
                'curl': get_curl_command('xai', {
                    'url': '/v1/chat/completions',
                    'curl': 'curl -X POST "http://localhost:1400/xai/v1/chat/completions" \\\n'
                           '    -H "Content-Type: application/json" \\\n'
                           '    -d \'{"model": "xai-1.0","messages": [{"role": "user","content": "Hello!"}]}\''
                })
            }
        ]
    }
} 