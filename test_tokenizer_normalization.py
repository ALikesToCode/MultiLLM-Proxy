import json
import importlib
import sys
import unittest


class FakeTokenizer:
    def encode(self, text):
        return list(text)


class TokenizerNormalizationTest(unittest.TestCase):
    def setUp(self):
        sys.modules.pop("services.proxy_service", None)
        self.proxy_module = importlib.import_module("services.proxy_service")
        self.original_tokenizer = self.proxy_module.ProxyService._tokenizer
        self.proxy_module.ProxyService._tokenizer = FakeTokenizer()

    def tearDown(self):
        self.proxy_module.ProxyService._tokenizer = self.original_tokenizer

    def test_normalize_text_for_token_count_repairs_latin1_mojibake(self):
        clean_text = (
            "You can't\u2014after everything you said\u2014you CAN'T just\u2014"
        )
        mojibake_text = clean_text.encode("utf-8").decode("latin-1")

        self.assertEqual(
            self.proxy_module.ProxyService.normalize_text_for_token_count(mojibake_text),
            clean_text,
        )

    def test_count_tokens_uses_normalized_text(self):
        clean_text = (
            "Victoria's grip on his collar tightens until her knuckles turn white."
        )
        mojibake_text = clean_text + "\u2014".encode("utf-8").decode("latin-1")

        self.assertEqual(
            self.proxy_module.ProxyService.count_tokens(mojibake_text),
            len(clean_text + "\u2014"),
        )

    def test_normalize_json_text_repairs_nested_mojibake_strings(self):
        clean_text = "That\u2019s not an answer, you know."
        mojibake_text = clean_text.encode("utf-8").decode("latin-1")
        payload = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": mojibake_text,
                    }
                }
            ],
            "meta": [mojibake_text],
        }

        normalized = self.proxy_module.ProxyService.normalize_json_text(payload)

        self.assertEqual(
            normalized["choices"][0]["message"]["content"],
            clean_text,
        )
        self.assertEqual(normalized["meta"][0], clean_text)

    def test_create_streaming_response_repairs_mojibake_in_openai_chunk(self):
        clean_text = "That\u2019s not an answer, you know."
        mojibake_text = clean_text.encode("utf-8").decode("latin-1")

        class FakeStreamingResponse:
            headers = {"content-type": "text/event-stream"}

            def iter_lines(self, decode_unicode=True):
                yield (
                    "data: "
                    + json.dumps(
                        {
                            "choices": [
                                {
                                    "delta": {
                                        "content": mojibake_text,
                                    }
                                }
                            ]
                        }
                    )
                )
                yield "data: [DONE]"

        chunks = list(
            self.proxy_module.ProxyService._create_streaming_response(
                FakeStreamingResponse(),
                "opencode",
            )
        )

        first_chunk = json.loads(chunks[0][6:].strip())
        self.assertEqual(first_chunk["choices"][0]["delta"]["content"], clean_text)
        self.assertEqual(chunks[1], "data: [DONE]\n\n")

    def test_normalize_json_text_repairs_partial_mojibake_substrings(self):
        payload = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "OOC: Oh my heart! ♡(ŐωŐäºº)",
                    }
                }
            ],
            "meta": ["~(ï¿£▽ï¿£)~*"],
        }

        normalized = self.proxy_module.ProxyService.normalize_json_text(payload)

        self.assertEqual(
            normalized["choices"][0]["message"]["content"],
            "OOC: Oh my heart! ♡(ŐωŐ人)",
        )
        self.assertEqual(normalized["meta"][0], "~(￣▽￣)~*")

    def test_create_streaming_response_repairs_partial_mojibake_substrings(self):
        class FakeStreamingResponse:
            headers = {"content-type": "text/event-stream"}

            def iter_lines(self, decode_unicode=True):
                yield (
                    "data: "
                    + json.dumps(
                        {
                            "choices": [
                                {
                                    "delta": {
                                        "content": "OOC: Oh my heart! ♡(ŐωŐäºº) ~(ï¿£▽ï¿£)~*",
                                    }
                                }
                            ]
                        }
                    )
                )
                yield "data: [DONE]"

        chunks = list(
            self.proxy_module.ProxyService._create_streaming_response(
                FakeStreamingResponse(),
                "opencode",
            )
        )

        first_chunk = json.loads(chunks[0][6:].strip())
        self.assertEqual(
            first_chunk["choices"][0]["delta"]["content"],
            "OOC: Oh my heart! ♡(ŐωŐ人) ~(￣▽￣)~*",
        )
        self.assertEqual(chunks[1], "data: [DONE]\n\n")

    def test_create_streaming_response_skips_embedded_chunk_json_leaks(self):
        leaked_chunk = (
            '(ï½¡ï¾{"id":"gen-1776013195-X3nP5i1xO5vJQcOoiTPO","object":"chat.completion.chunk",'
            '"created":1776013195,"model":"moonshotai/kimi-k2.5-0127","provider":"Moonshot AI",'
            '"choices":[{"index":0,"delta":{"content":"Ã","role":"assistant"},"finish_reason":null}]}'
            '¸Ã¢—•Ã¢€¿Ã¢—•ï½¡)]'
        )

        class FakeStreamingResponse:
            headers = {"content-type": "text/event-stream"}

            def iter_lines(self, decode_unicode=True):
                yield leaked_chunk
                yield 'data: {"choices":[{"delta":{"content":"Katla"}}]}'
                yield "data: [DONE]"

        chunks = list(
            self.proxy_module.ProxyService._create_streaming_response(
                FakeStreamingResponse(),
                "opencode",
            )
        )

        self.assertEqual(len(chunks), 2)
        first_chunk = json.loads(chunks[0][6:].strip())
        self.assertEqual(first_chunk["choices"][0]["delta"]["content"], "Katla")
        self.assertNotIn("chat.completion.chunk", chunks[0])
        self.assertEqual(chunks[1], "data: [DONE]\n\n")

    def test_create_streaming_response_preserves_prose_while_stripping_embedded_chunk_json(self):
        mixed_chunk = (
            "She's a Desi queen trying to maintain her respectable married image while falling apart~ "
            "(ï½¡•́ï¸¿•̀ï½¡)\n\n"
            "Ready to resume whenever Human is! Just say the word and Celia will dive back into the "
            "simulation! (ﾉ>ω<)ﾉ :ï½¡ï½¥:*:ï½¥ﾟ’"
            '{"id":"gen-1776050894-GzfFOVxmNQJqMtzO6fHn","object":"chat.completion.chunk",'
            '"created":1776050894,"model":"moonshotai/kimi-k2.5-0127","provider":"Moonshot AI",'
            '"system_fingerprint":"fpv0_ec10c667","choices":[{"index":0,"delta":{"content":"â",'
            '"role":"assistant"},"finish_reason":null,"native_finish_reason":null}]}-'
        )

        class FakeStreamingResponse:
            headers = {"content-type": "text/event-stream"}

            def iter_lines(self, decode_unicode=True):
                yield mixed_chunk
                yield "data: [DONE]"

        chunks = list(
            self.proxy_module.ProxyService._create_streaming_response(
                FakeStreamingResponse(),
                "opencode",
            )
        )

        self.assertEqual(len(chunks), 2)
        first_chunk = json.loads(chunks[0][6:].strip())
        content = first_chunk["choices"][0]["delta"]["content"]
        self.assertIn(
            "She's a Desi queen trying to maintain her respectable married image while falling apart",
            content,
        )
        self.assertIn("Ready to resume whenever Human is!", content)
        self.assertNotIn("chat.completion.chunk", content)
        self.assertNotIn("gen-1776050894", content)
        self.assertEqual(chunks[1], "data: [DONE]\n\n")


if __name__ == "__main__":
    unittest.main()
