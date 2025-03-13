import requests
import os
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get the Chutes API token from environment
chutes_api_token = os.environ.get('CHUTES_API_TOKEN')

if not chutes_api_token:
    print("Error: CHUTES_API_TOKEN not found in environment variables")
    exit(1)

# Test direct connection to Chutes API with streaming
print("Testing direct connection to Chutes API with streaming...")
response = requests.post(
    "https://llm.chutes.ai/v1/completions",
    headers={
        "Authorization": f"Bearer {chutes_api_token}",
        "Content-Type": "application/json"
    },
    json={
        "model": "deepseek-ai/DeepSeek-V3",
        "prompt": "My favourite type of cat",
        "stream": True,
        "max_tokens": 100,
        "temperature": 0.7
    },
    stream=True
)

print(f"Status code: {response.status_code}")
if response.status_code == 200:
    print("Direct connection successful!")
    print("Streaming response:")
    for line in response.iter_lines():
        if line:
            line = line.decode('utf-8')
            if line.startswith('data: '):
                data = line[6:]  # Remove 'data: ' prefix
                if data == '[DONE]':
                    print("[DONE]")
                else:
                    try:
                        json_data = json.loads(data)
                        if 'choices' in json_data and len(json_data['choices']) > 0:
                            text = json_data['choices'][0].get('text', '')
                            if text:
                                print(text, end='', flush=True)
                    except json.JSONDecodeError:
                        print(f"Error parsing JSON: {data}")
    print("\n")
else:
    print("Direct connection failed!")
    print("Response:")
    print(response.text)

# Test connection through the proxy with streaming
print("\nTesting connection through the proxy with streaming...")
proxy_url = "http://localhost:1400"  # Update with your proxy URL if different
response = requests.post(
    f"{proxy_url}/chutes/v1/completions",
    headers={
        "Authorization": f"Bearer {os.environ.get('ADMIN_API_KEY')}",
        "Content-Type": "application/json"
    },
    json={
        "model": "deepseek-ai/DeepSeek-V3",
        "prompt": "My favourite type of cat",
        "stream": True,
        "max_tokens": 100,
        "temperature": 0.7
    },
    stream=True
)

print(f"Status code: {response.status_code}")
if response.status_code == 200:
    print("Proxy connection successful!")
    print("Streaming response:")
    for line in response.iter_lines():
        if line:
            line = line.decode('utf-8')
            if line.startswith('data: '):
                data = line[6:]  # Remove 'data: ' prefix
                if data == '[DONE]':
                    print("[DONE]")
                else:
                    try:
                        json_data = json.loads(data)
                        if 'choices' in json_data and len(json_data['choices']) > 0:
                            text = json_data['choices'][0].get('text', '')
                            if text:
                                print(text, end='', flush=True)
                    except json.JSONDecodeError:
                        print(f"Error parsing JSON: {data}")
    print("\n")
else:
    print("Proxy connection failed!")
    print("Response:")
    print(response.text) 