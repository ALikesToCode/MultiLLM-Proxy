#!/usr/bin/env python3

import os
import requests
import json
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get admin API key from environment
ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY')
if not ADMIN_API_KEY:
    print("ERROR: ADMIN_API_KEY not found in environment variables")
    sys.exit(1)

# Test connection to Gemini API through the proxy with streaming
print("\nTesting connection to Gemini API through proxy with streaming...")

# Define the proxy URL
proxy_url = "http://localhost:1400/gemini/chat/completions"

# Define the request parameters
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {ADMIN_API_KEY}"
}

data = {
    "model": "gemini-2.0-flash",
    "messages": [
        {"role": "user", "content": "Write a short poem about AI assistants"}
    ],
    "stream": True,
    "temperature": 0.7
}

try:
    # Make the request with streaming
    response = requests.post(
        proxy_url,
        headers=headers,
        json=data,
        stream=True,
    )

    if response.status_code == 200:
        print("Streaming response:")
        full_text = ""
        for line in response.iter_lines():
            if line:
                line_str = line.decode('utf-8')
                if line_str.startswith('data: '):
                    content = line_str[6:]  # Remove 'data: ' prefix
                    if content == '[DONE]':
                        print("\n[DONE]")
                        break
                    try:
                        response_json = json.loads(content)
                        if 'choices' in response_json and response_json['choices']:
                            delta = response_json['choices'][0].get('delta', {})
                            if 'content' in delta:
                                content_part = delta['content']
                                full_text += content_part
                                print(content_part, end="", flush=True)
                    except json.JSONDecodeError as e:
                        print(f"\nError parsing JSON: {e}")
                        print(f"Raw content: {content}")
                    except Exception as e:
                        print(f"\nError processing chunk: {e}")
        
        print("\n\nFull generated text:")
        print(full_text)
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
except Exception as e:
    print(f"Error: {e}")

# Now test direct model API streaming
print("\nTesting direct model API with streaming...")

direct_url = "http://localhost:1400/gemini/v1beta/models/gemini-2.0-flash:generateContent"

data = {
    "contents": [
        {"parts": [{"text": "Write a short poem about programming"}]}
    ],
    "stream": True,
    "generationConfig": {
        "temperature": 0.7
    },
    "safetySettings": [
        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
    ]
}

try:
    # Make the request with streaming
    response = requests.post(
        direct_url,
        headers=headers,
        json=data,
        stream=True,
    )

    if response.status_code == 200:
        print("Streaming response:")
        full_text = ""
        for line in response.iter_lines():
            if line:
                line_str = line.decode('utf-8')
                if line_str.startswith('data: '):
                    content = line_str[6:]  # Remove 'data: ' prefix
                    if content == '[DONE]':
                        print("\n[DONE]")
                        break
                    try:
                        response_json = json.loads(content)
                        if 'candidates' in response_json and response_json['candidates']:
                            candidate = response_json['candidates'][0]
                            if 'content' in candidate and 'parts' in candidate['content']:
                                for part in candidate['content']['parts']:
                                    if 'text' in part:
                                        text = part['text']
                                        full_text += text
                                        print(text, end="", flush=True)
                    except json.JSONDecodeError as e:
                        print(f"\nError parsing JSON: {e}")
                        print(f"Raw content: {content}")
                    except Exception as e:
                        print(f"\nError processing chunk: {e}")
        
        print("\n\nFull generated text:")
        print(full_text)
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
except Exception as e:
    print(f"Error: {e}")

print("\nTests completed.") 