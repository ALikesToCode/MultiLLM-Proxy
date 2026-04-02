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


if __name__ == "__main__":
    unittest.main()
