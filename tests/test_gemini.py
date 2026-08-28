import argparse
import io
import json
import os
from contextlib import redirect_stdout

import requests
from dotenv import load_dotenv


def print_response_body(response: requests.Response, *, show_content: bool) -> None:
    """Print response content only after an explicit operator opt-in."""
    if show_content:
        try:
            print(json.dumps(response.json(), indent=2))
        except ValueError:
            print(response.text)
        return

    print(f"Response body: [hidden, {len(response.content or b'')} bytes]")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Test a direct Gemini API request")
    parser.add_argument(
        "--show-content",
        action="store_true",
        help="Print model output or error bodies (hidden by default)",
    )
    args = parser.parse_args(argv)

    load_dotenv()

    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    if not gemini_api_key:
        print("Error: GEMINI_API_KEY not found in environment variables")
        return 1

    print("Testing direct connection to Gemini API...")
    try:
        response = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-2.0-flash:generateContent",
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
            },
            timeout=(5, 120),
        )
    except requests.RequestException as error:
        print(f"Direct connection failed: {type(error).__name__}")
        return 1

    print(f"Status code: {response.status_code}")
    if response.status_code == 200:
        print("Direct connection successful!")
        print("Response:")
        print_response_body(response, show_content=args.show_content)
        return 0

    print("Direct connection failed!")
    print("Response:")
    print_response_body(response, show_content=args.show_content)
    return 1


def test_response_body_is_hidden_by_default() -> None:
    response = requests.Response()
    response._content = b'{"output":"sensitive model content"}'
    output = io.StringIO()

    with redirect_stdout(output):
        print_response_body(response, show_content=False)

    diagnostics = output.getvalue()
    assert "sensitive model content" not in diagnostics
    assert "[hidden" in diagnostics


def test_response_body_can_be_shown_explicitly() -> None:
    response = requests.Response()
    response._content = b'{"output":"visible model content"}'
    response.headers["Content-Type"] = "application/json"
    output = io.StringIO()

    with redirect_stdout(output):
        print_response_body(response, show_content=True)

    assert "visible model content" in output.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
