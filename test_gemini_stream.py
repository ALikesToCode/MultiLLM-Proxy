#!/usr/bin/env python3

import json
import os

import requests
from dotenv import load_dotenv


def print_openai_stream(response: requests.Response) -> str:
    full_text = ""
    for line in response.iter_lines():
        if not line:
            continue

        line_text = line.decode("utf-8")
        if not line_text.startswith("data: "):
            continue

        content = line_text[6:]
        if content == "[DONE]":
            print("\n[DONE]")
            break

        try:
            response_json = json.loads(content)
        except json.JSONDecodeError as error:
            print(f"\nError parsing JSON: {error}")
            print(f"Raw content: {content}")
            continue

        if "choices" in response_json and response_json["choices"]:
            delta = response_json["choices"][0].get("delta", {})
            if "content" in delta:
                content_part = delta["content"]
                full_text += content_part
                print(content_part, end="", flush=True)

    return full_text


def print_gemini_stream(response: requests.Response) -> str:
    full_text = ""
    for line in response.iter_lines():
        if not line:
            continue

        line_text = line.decode("utf-8")
        if not line_text.startswith("data: "):
            continue

        content = line_text[6:]
        if content == "[DONE]":
            print("\n[DONE]")
            break

        try:
            response_json = json.loads(content)
        except json.JSONDecodeError as error:
            print(f"\nError parsing JSON: {error}")
            print(f"Raw content: {content}")
            continue

        if "candidates" in response_json and response_json["candidates"]:
            candidate = response_json["candidates"][0]
            for part in candidate.get("content", {}).get("parts", []):
                if "text" in part:
                    full_text += part["text"]
                    print(part["text"], end="", flush=True)

    return full_text


def main() -> int:
    load_dotenv()

    admin_api_key = os.environ.get("ADMIN_API_KEY")
    if not admin_api_key:
        print("ERROR: ADMIN_API_KEY not found in environment variables")
        return 1

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {admin_api_key}",
    }

    print("\nTesting Gemini proxy chat completions streaming...")
    response = requests.post(
        "http://localhost:1400/gemini/chat/completions",
        headers=headers,
        json={
            "model": "gemini-2.0-flash",
            "messages": [
                {"role": "user", "content": "Write a short poem about AI assistants"},
            ],
            "stream": True,
            "temperature": 0.7,
        },
        stream=True,
    )

    if response.status_code == 200:
        print("Streaming response:")
        full_text = print_openai_stream(response)
        print("\n\nFull generated text:")
        print(full_text)
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return 1

    print("\nTesting Gemini direct model proxy streaming...")
    response = requests.post(
        "http://localhost:1400/gemini/v1beta/models/gemini-2.0-flash:generateContent",
        headers=headers,
        json={
            "contents": [
                {"parts": [{"text": "Write a short poem about programming"}]},
            ],
            "stream": True,
            "generationConfig": {
                "temperature": 0.7,
            },
            "safetySettings": [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ],
        },
        stream=True,
    )

    if response.status_code == 200:
        print("Streaming response:")
        full_text = print_gemini_stream(response)
        print("\n\nFull generated text:")
        print(full_text)
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return 1

    print("\nTests completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
