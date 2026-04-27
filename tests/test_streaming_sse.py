import importlib
import json
import sys
import unittest

from streaming.openai import sanitize_openai_stream_payload
from streaming.sse import iter_sse_data, iter_sse_events


class SSEParserTest(unittest.TestCase):
    def test_parser_handles_split_chunks_crlf_comments_events_and_done(self):
        events = list(
            iter_sse_events(
                [
                    b": OPENROUTER PROCESSING\r\n",
                    b"event: completion\r\nid: evt_1\r\n",
                    b'data: {"choices":[{"delta":{"content":"Hel',
                    b'lo"}}]}\r\n\r\n',
                    b"data: [DO",
                    b"NE]\n\n",
                ]
            )
        )

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].comments, ["OPENROUTER PROCESSING"])
        self.assertEqual(events[0].event, "completion")
        self.assertEqual(events[0].event_id, "evt_1")
        self.assertEqual(
            json.loads(events[0].data)["choices"][0]["delta"]["content"],
            "Hello",
        )
        self.assertTrue(events[1].is_done)

    def test_data_iterator_ignores_comments_and_empty_frames(self):
        payloads = list(
            iter_sse_data(
                [
                    ": keep-alive\n\n",
                    "event: usage\n",
                    'data: {"usage":{"total_tokens":3}}\n\n',
                    "data:\n\n",
                    'data: {"choices":[{"delta":{"tool_calls":[{"id":"call_1"}]}}]}\n\n',
                ]
            )
        )

        self.assertEqual(len(payloads), 2)
        self.assertEqual(json.loads(payloads[0])["usage"]["total_tokens"], 3)
        self.assertEqual(
            json.loads(payloads[1])["choices"][0]["delta"]["tool_calls"][0]["id"],
            "call_1",
        )

    def test_openai_payload_sanitizer_removes_hidden_reasoning_metadata(self):
        payload = {
            "choices": [
                {
                    "delta": {
                        "content": "visible",
                        "tool_calls": [{"id": "call_1"}],
                        "reasoning_content": "deepseek state",
                        "reasoning": "hidden",
                        "reasoning_details": [{"text": "hidden"}],
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"total_tokens": 9},
        }

        sanitized = sanitize_openai_stream_payload(payload)

        delta = sanitized["choices"][0]["delta"]
        self.assertEqual(delta["content"], "visible")
        self.assertEqual(delta["tool_calls"], [{"id": "call_1"}])
        self.assertEqual(delta["reasoning_content"], "deepseek state")
        self.assertNotIn("reasoning", delta)
        self.assertNotIn("reasoning_details", delta)
        self.assertEqual(sanitized["choices"][0]["finish_reason"], "stop")
        self.assertEqual(sanitized["usage"]["total_tokens"], 9)

    def test_proxy_streaming_response_uses_sse_parser_and_closes_on_done(self):
        sys.modules.pop("services.proxy_service", None)
        proxy_module = importlib.import_module("services.proxy_service")

        class SplitStreamingResponse:
            headers = {"content-type": "text/event-stream"}
            closed = False

            def iter_content(self, chunk_size=1024):
                yield b": PROCESSING\r\n\r\n"
                yield b'data: {"choices":[{"delta":{"content":"Hel'
                yield b'lo","reasoning":"hidden"}}]}\r\n\r\n'
                yield b"data: [DONE]\r\n\r\n"
                yield b'data: {"choices":[{"delta":{"content":"late"}}]}\r\n\r\n'

            def iter_lines(self, decode_unicode=True):
                raise AssertionError("split SSE streams should use iter_content")

            def close(self):
                self.closed = True

        upstream = SplitStreamingResponse()
        chunks = list(
            proxy_module.ProxyService._create_streaming_response(
                upstream,
                "openrouter",
            )
        )

        self.assertEqual(len(chunks), 2)
        first_payload = json.loads(chunks[0][6:].strip())
        self.assertEqual(first_payload["choices"][0]["delta"]["content"], "Hello")
        self.assertNotIn("reasoning", first_payload["choices"][0]["delta"])
        self.assertEqual(chunks[1], "data: [DONE]\n\n")
        self.assertTrue(upstream.closed)


if __name__ == "__main__":
    unittest.main()
