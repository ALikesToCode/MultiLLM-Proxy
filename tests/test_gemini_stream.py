#!/usr/bin/env python3

import argparse
import io
import json
import os
from contextlib import redirect_stdout

import requests
from dotenv import load_dotenv


def print_openai_stream(
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

        content = line_text[6:]
        if content == "[DONE]":
            print("\n[DONE]")
            break

        try:
            response_json = json.loads(content)
        except json.JSONDecodeError:
            print(f"\nSkipped malformed stream event ({len(content)} characters)")
            continue

        if "choices" in response_json and response_json["choices"]:
            delta = response_json["choices"][0].get("delta", {})
            if "content" in delta:
                content_part = delta["content"]
                full_text += content_part
                if show_content:
                    print(content_part, end="", flush=True)

    return full_text


def print_gemini_stream(
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

        content = line_text[6:]
        if content == "[DONE]":
            print("\n[DONE]")
            break

        try:
            response_json = json.loads(content)
        except json.JSONDecodeError:
            print(f"\nSkipped malformed stream event ({len(content)} characters)")
            continue

        if "candidates" in response_json and response_json["candidates"]:
            candidate = response_json["candidates"][0]
            for part in candidate.get("content", {}).get("parts", []):
                if "text" in part:
                    full_text += part["text"]
                    if show_content:
                        print(part["text"], end="", flush=True)

    return full_text


def print_stream_summary(full_text: str, *, show_content: bool) -> None:
    if show_content:
        print("\n\nFull generated text:")
        print(full_text)
    else:
        print(f"\nGenerated text: [hidden, {len(full_text)} characters]")


def print_response_failure(response: requests.Response) -> None:
    print(f"Error: {response.status_code}")
    print(f"Response body: [hidden, {len(response.content or b'')} bytes]")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Test Gemini proxy streaming")
    parser.add_argument(
        "--show-content",
        action="store_true",
        help="Print prompts and model output (hidden by default)",
    )
    args = parser.parse_args(argv)

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
    try:
        response = requests.post(
            "http://localhost:1400/gemini/chat/completions",
            headers=headers,
            json={
                "model": "gemini-2.0-flash",
                "messages": [
                    {
                        "role": "user",
                        "content": "Write a short poem about AI assistants",
                    },
                ],
                "stream": True,
                "temperature": 0.7,
            },
            stream=True,
            timeout=(5, 300),
        )
    except requests.RequestException as error:
        print(f"Streaming request failed: {type(error).__name__}")
        return 1

    try:
        if response.status_code != 200:
            print_response_failure(response)
            return 1

        print("Streaming response received")
        full_text = print_openai_stream(response, show_content=args.show_content)
        print_stream_summary(full_text, show_content=args.show_content)
    finally:
        response.close()

    print("\nTesting Gemini direct model proxy streaming...")
    try:
        response = requests.post(
            "http://localhost:1400/gemini/v1beta/models/"
            "gemini-2.0-flash:generateContent",
            headers=headers,
            json={
                "contents": [
                    {"parts": [{"text": "Write a short poem about programming"}]},
                ],
                "stream": True,
                "generationConfig": {
                    "temperature": 0.7,
                },
            },
            stream=True,
            timeout=(5, 300),
        )
    except requests.RequestException as error:
        print(f"Direct streaming request failed: {type(error).__name__}")
        return 1

    try:
        if response.status_code != 200:
            print_response_failure(response)
            return 1

        print("Streaming response received")
        full_text = print_gemini_stream(response, show_content=args.show_content)
        print_stream_summary(full_text, show_content=args.show_content)
    finally:
        response.close()

    print("\nTests completed.")
    return 0


class StaticStreamResponse:
    def __init__(self, lines: list[bytes]) -> None:
        self.lines = lines

    def iter_lines(self):
        return iter(self.lines)


def test_stream_readers_hide_content_by_default() -> None:
    cases = (
        (
            print_openai_stream,
            b'data: {"choices":[{"delta":{"content":"sensitive openai"}}]}',
            "sensitive openai",
        ),
        (
            print_gemini_stream,
            b'data: {"candidates":[{"content":{"parts":[{"text":"sensitive gemini"}]}}]}',
            "sensitive gemini",
        ),
    )

    for reader, line, expected_text in cases:
        output = io.StringIO()
        with redirect_stdout(output):
            full_text = reader(StaticStreamResponse([line]))

        assert full_text == expected_text
        assert expected_text not in output.getvalue()


def test_stream_reader_does_not_reflect_malformed_events() -> None:
    output = io.StringIO()
    with redirect_stdout(output):
        print_openai_stream(StaticStreamResponse([b"data: {sensitive malformed event"]))

    diagnostics = output.getvalue()
    assert "sensitive malformed event" not in diagnostics
    assert "Skipped malformed stream event" in diagnostics


if __name__ == "__main__":
    raise SystemExit(main())
