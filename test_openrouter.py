#!/usr/bin/env python3
"""
Test script for OpenRouter integration with MultiLLM-Proxy
This script tests both streaming and non-streaming requests to OpenRouter
"""

import requests
import json
import os
import sys
import time
import argparse
from dotenv import load_dotenv
from sseclient import SSEClient

# Load environment variables
load_dotenv()

# Default values
DEFAULT_HOST = "http://localhost:1400"
DEFAULT_MODEL = "openai/gpt-3.5-turbo"
DEFAULT_PROMPT = "Write a short poem about artificial intelligence"
DEFAULT_ADMIN_KEY = "MjM0NTY3ODkwMTI"  # Default admin key for MultiLLM-Proxy

def test_openrouter_non_streaming(host, model, prompt, api_key):
    """Test OpenRouter with a non-streaming request"""
    print(f"\n🔍 Testing OpenRouter non-streaming with model: {model}")
    print(f"📝 Prompt: {prompt}")
    
    url = f"{host}/openrouter/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "stream": False
    }
    
    start_time = time.time()
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        
        # Extract and print the response
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})
        
        print("\n✅ Response received:")
        print("-" * 50)
        print(content)
        print("-" * 50)
        
        # Print token usage
        if usage:
            print(f"\n📊 Token usage:")
            print(f"  - Prompt tokens: {usage.get('prompt_tokens', 'N/A')}")
            print(f"  - Completion tokens: {usage.get('completion_tokens', 'N/A')}")
            print(f"  - Total tokens: {usage.get('total_tokens', 'N/A')}")
        
        print(f"\n⏱️ Request completed in {time.time() - start_time:.2f} seconds")
        return True
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        if hasattr(e, 'response') and e.response:
            try:
                error_data = e.response.json()
                print(f"Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"Status code: {e.response.status_code}")
                print(f"Response text: {e.response.text}")
        return False

def test_openrouter_streaming(host, model, prompt, api_key):
    """Test OpenRouter with a streaming request"""
    print(f"\n🔍 Testing OpenRouter streaming with model: {model}")
    print(f"📝 Prompt: {prompt}")
    
    url = f"{host}/openrouter/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "stream": True
    }
    
    start_time = time.time()
    try:
        # First make the POST request to initialize the stream
        response = requests.post(url, headers=headers, json=payload, stream=True)
        response.raise_for_status()
        
        # Then use SSEClient to process the stream
        client = SSEClient(response)
        
        print("\n✅ Streaming response:")
        print("-" * 50)
        
        full_response = ""
        for event in client:
            if event.data == "[DONE]":
                break
                
            try:
                data = json.loads(event.data)
                if data.get("choices") and data["choices"][0].get("delta") and data["choices"][0]["delta"].get("content"):
                    content = data["choices"][0]["delta"]["content"]
                    full_response += content
                    print(content, end="", flush=True)
            except json.JSONDecodeError:
                pass
        
        print("\n" + "-" * 50)
        print(f"\n⏱️ Streaming completed in {time.time() - start_time:.2f} seconds")
        return True
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        if hasattr(e, 'response') and e.response:
            try:
                error_data = e.response.json()
                print(f"Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"Status code: {e.response.status_code}")
                print(f"Response text: {e.response.text}")
        return False

def test_openrouter_credits(host, api_key):
    """Test OpenRouter credits endpoint"""
    print("\n💰 Checking OpenRouter credits")
    
    url = f"{host}/openrouter/credits"
    headers = {
        "Authorization": f"Bearer {api_key}"
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data.get("data"):
            credits = data["data"].get("credits", 0)
            used = data["data"].get("used", 0)
            print(f"✅ Credits available: ${credits:.2f}")
            print(f"✅ Credits used: ${used:.2f}")
            print(f"✅ Total allocation: ${credits + used:.2f}")
        else:
            print(f"✅ Response: {json.dumps(data, indent=2)}")
        
        return True
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        if hasattr(e, 'response') and e.response:
            try:
                error_data = e.response.json()
                print(f"Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"Status code: {e.response.status_code}")
                print(f"Response text: {e.response.text}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Test OpenRouter integration with MultiLLM-Proxy")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host URL (default: {DEFAULT_HOST})")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Model to test (default: {DEFAULT_MODEL})")
    parser.add_argument("--prompt", default=DEFAULT_PROMPT, help=f"Prompt to use (default: {DEFAULT_PROMPT})")
    parser.add_argument("--key", default=DEFAULT_ADMIN_KEY, help=f"API key (default: {DEFAULT_ADMIN_KEY})")
    parser.add_argument("--no-stream", action="store_true", help="Skip streaming test")
    parser.add_argument("--no-regular", action="store_true", help="Skip regular (non-streaming) test")
    parser.add_argument("--no-credits", action="store_true", help="Skip credits check")
    
    args = parser.parse_args()
    
    print("🚀 OpenRouter Integration Test")
    print(f"🔗 Host: {args.host}")
    print(f"🤖 Model: {args.model}")
    
    success = True
    
    # Test credits endpoint
    if not args.no_credits:
        if not test_openrouter_credits(args.host, args.key):
            success = False
    
    # Test non-streaming request
    if not args.no_regular:
        if not test_openrouter_non_streaming(args.host, args.model, args.prompt, args.key):
            success = False
    
    # Test streaming request
    if not args.no_stream:
        if not test_openrouter_streaming(args.host, args.model, args.prompt, args.key):
            success = False
    
    if success:
        print("\n✅ All tests completed successfully!")
        return 0
    else:
        print("\n❌ Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 