import argparse
import io
import json
import os
from contextlib import redirect_stdout

import requests
from dotenv import load_dotenv


def print_response_body(response: requests.Response, *, show_content: bool) -> None:
    if show_content:
        try:
            print(json.dumps(response.json(), indent=2))
        except ValueError:
            print(response.text)
        return

    print(f"Response body: [hidden, {len(response.content or b'')} bytes]")


def run_completion_check(
    label: str,
    url: str,
    headers: dict[str, str],
    *,
    show_content: bool,
) -> bool:
    print(f"Testing {label}...")
    try:
        response = requests.post(
            url,
            headers=headers,
            json={
                "model": "deepseek-ai/DeepSeek-V3",
                "prompt": "My favourite type of cat",
                "stream": False,
                "max_tokens": 100,
                "temperature": 0.7,
            },
            timeout=(5, 120),
        )
    except requests.RequestException as error:
        print(f"Connection failed: {type(error).__name__}")
        return False

    try:
        print(f"Status code: {response.status_code}")
        print_response_body(response, show_content=show_content)
        return response.status_code == 200
    finally:
        response.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Test Chutes completions")
    parser.add_argument(
        "--show-content",
        action="store_true",
        help="Print model output or error bodies (hidden by default)",
    )
    args = parser.parse_args(argv)

    load_dotenv()

    chutes_api_token = os.environ.get("CHUTES_API_TOKEN")
    if not chutes_api_token:
        print("Error: CHUTES_API_TOKEN not found in environment variables")
        return 1
    admin_api_key = os.environ.get("ADMIN_API_KEY")
    if not admin_api_key:
        print("Error: ADMIN_API_KEY not found in environment variables")
        return 1

    direct_ok = run_completion_check(
        "direct connection to Chutes API",
        "https://llm.chutes.ai/v1/completions",
        {
            "Authorization": f"Bearer {chutes_api_token}",
            "Content-Type": "application/json",
        },
        show_content=args.show_content,
    )

    print()
    proxy_ok = run_completion_check(
        "connection through the proxy",
        "http://localhost:1400/chutes/v1/completions",
        {
            "Authorization": f"Bearer {admin_api_key}",
            "Content-Type": "application/json",
        },
        show_content=args.show_content,
    )

    return 0 if direct_ok and proxy_ok else 1


def test_response_body_is_hidden_by_default() -> None:
    response = requests.Response()
    response._content = b'{"output":"sensitive Chutes content"}'
    output = io.StringIO()

    with redirect_stdout(output):
        print_response_body(response, show_content=False)

    assert "sensitive Chutes content" not in output.getvalue()
    assert "[hidden" in output.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
