import json
import os

import requests
from dotenv import load_dotenv


def main() -> int:
    load_dotenv()

    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    if not gemini_api_key:
        print("Error: GEMINI_API_KEY not found in environment variables")
        return 1

    print("Testing direct connection to Gemini API...")
    response = requests.post(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
        headers={
            "x-goog-api-key": gemini_api_key,
            "Content-Type": "application/json",
        },
        json={
            "contents": [
                {
                    "parts": [{"text": "Explain how AI works"}],
                }
            ],
            "safetySettings": [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ],
        },
    )

    print(f"Status code: {response.status_code}")
    if response.status_code == 200:
        print("Direct connection successful!")
        print("Response:")
        print(json.dumps(response.json(), indent=2))
        return 0

    print("Direct connection failed!")
    print("Response:")
    print(response.text)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
