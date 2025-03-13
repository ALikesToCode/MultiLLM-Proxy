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

# Test direct connection to Chutes API
print("Testing direct connection to Chutes API...")
response = requests.post(
    "https://llm.chutes.ai/v1/completions",
    headers={
        "Authorization": f"Bearer {chutes_api_token}",
        "Content-Type": "application/json"
    },
    json={
        "model": "deepseek-ai/DeepSeek-V3",
        "prompt": "My favourite type of cat",
        "stream": False,
        "max_tokens": 100,
        "temperature": 0.7
    }
)

print(f"Status code: {response.status_code}")
if response.status_code == 200:
    print("Direct connection successful!")
    print("Response:")
    print(json.dumps(response.json(), indent=2))
else:
    print("Direct connection failed!")
    print("Response:")
    print(response.text)

# Test connection through the proxy
print("\nTesting connection through the proxy...")
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
        "stream": False,
        "max_tokens": 100,
        "temperature": 0.7
    }
)

print(f"Status code: {response.status_code}")
if response.status_code == 200:
    print("Proxy connection successful!")
    print("Response:")
    print(json.dumps(response.json(), indent=2))
else:
    print("Proxy connection failed!")
    print("Response:")
    print(response.text) 