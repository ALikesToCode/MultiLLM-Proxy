import argparse
import io
import json
import os
from contextlib import redirect_stdout

import requests
from dotenv import load_dotenv


def print_streaming_response(
    response: requests.Response,
    *,
    show_content: bool = False,
) -> str:
    full_text = ""
    for line in response.iter_lines():
        if not line:
            continue

        line_text = line.decode("utf-8")
        if not line_text.startswith("data: "):
            continue

        data = line_text[6:]
        if data == "[DONE]":
            print("[DONE]")
            continue

        try:
            json_data = json.loads(data)
        except json.JSONDecodeError:
            print(f"Skipped malformed stream event ({len(data)} characters)")
            continue

        if "choices" in json_data and json_data["choices"]:
            text = json_data["choices"][0].get("text", "")
            if text:
                full_text += text
                if show_content:
                    print(text, end="", flush=True)

    return full_text


def run_stream_check(
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
                "stream": True,
                "max_tokens": 100,
                "temperature": 0.7,
            },
            stream=True,
            timeout=(5, 300),
        )
    except requests.RequestException as error:
        print(f"Connection failed: {type(error).__name__}")
        return False

    try:
        print(f"Status code: {response.status_code}")
        if response.status_code != 200:
            print(f"Response body: [hidden, {len(response.content or b'')} bytes]")
            return False

        full_text = print_streaming_response(
            response,
            show_content=show_content,
        )
        if not show_content:
            print(f"Response content: [hidden, {len(full_text)} characters]")
        return True
    finally:
        response.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Test Chutes streaming completions")
    parser.add_argument(
        "--show-content",
        action="store_true",
        help="Print model output (hidden by default)",
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

    direct_ok = run_stream_check(
        "direct connection to Chutes API with streaming",
        "https://llm.chutes.ai/v1/completions",
        {
            "Authorization": f"Bearer {chutes_api_token}",
            "Content-Type": "application/json",
        },
        show_content=args.show_content,
    )

    print()
    proxy_ok = run_stream_check(
        "connection through the proxy with streaming",
        "http://localhost:1400/chutes/v1/completions",
        {
            "Authorization": f"Bearer {admin_api_key}",
            "Content-Type": "application/json",
        },
        show_content=args.show_content,
    )

    return 0 if direct_ok and proxy_ok else 1


class StaticStreamResponse:
    def __init__(self, lines: list[bytes]) -> None:
        self.lines = lines

    def iter_lines(self):
        return iter(self.lines)


def test_stream_content_is_hidden_by_default() -> None:
    response = StaticStreamResponse(
        [b'data: {"choices":[{"text":"sensitive Chutes content"}]}'],
    )
    output = io.StringIO()

    with redirect_stdout(output):
        full_text = print_streaming_response(response)

    assert full_text == "sensitive Chutes content"
    assert "sensitive Chutes content" not in output.getvalue()


def test_malformed_stream_event_is_not_reflected() -> None:
    response = StaticStreamResponse([b"data: {sensitive malformed event"])
    output = io.StringIO()

    with redirect_stdout(output):
        print_streaming_response(response)

    diagnostics = output.getvalue()
    assert "sensitive malformed event" not in diagnostics
    assert "Skipped malformed stream event" in diagnostics


if __name__ == "__main__":
    raise SystemExit(main())
