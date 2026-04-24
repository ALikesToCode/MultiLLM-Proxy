import importlib
import json
import sys
import types
import unittest


class _FakeTokenizer:
    def encode(self, text):
        return list(text)


_STUBBED_MODULES = (
    "tiktoken",
    "flask",
    "error_handlers",
    "config",
    "services.cache_service",
    "services.rate_limit_service",
    "services.auth_service",
    "services.proxy_service",
)


def _install_proxy_service_stubs():
    tiktoken_module = types.ModuleType("tiktoken")
    tiktoken_module.get_encoding = lambda _name: _FakeTokenizer()
    tiktoken_module.encoding_for_model = lambda _name: _FakeTokenizer()
    sys.modules["tiktoken"] = tiktoken_module

    flask_module = types.ModuleType("flask")

    class _Response:
        def __init__(self, response=None, status=200, mimetype=None, headers=None):
            self.response = response
            self.status_code = status
            self.mimetype = mimetype
            self.headers = headers or {}

    flask_module.Response = _Response
    sys.modules["flask"] = flask_module

    error_handlers_module = types.ModuleType("error_handlers")

    class _APIError(Exception):
        def __init__(self, message="", status_code=500):
            super().__init__(message)
            self.status_code = status_code

    error_handlers_module.APIError = _APIError
    sys.modules["error_handlers"] = error_handlers_module

    config_module = types.ModuleType("config")

    class _Config:
        API_TIMEOUTS = {"default": (5, 60), "opencode": (5, 120)}
        API_RETRIES = {"default": {"max_retries": 3, "backoff_factor": 1}}
        UNSUPPORTED_PARAMS = {}

    config_module.Config = _Config
    sys.modules["config"] = config_module

    for module_name, class_name in (
        ("services.cache_service", "CacheService"),
        ("services.rate_limit_service", "RateLimitService"),
        ("services.auth_service", "AuthService"),
    ):
        module = types.ModuleType(module_name)
        setattr(module, class_name, type(class_name, (), {}))
        sys.modules[module_name] = module


class StreamingArtifactCleanupTest(unittest.TestCase):
    def setUp(self):
        self.original_modules = {
            module_name: sys.modules.get(module_name)
            for module_name in _STUBBED_MODULES
        }
        _install_proxy_service_stubs()
        sys.modules.pop("services.proxy_service", None)
        self.proxy_module = importlib.import_module("services.proxy_service")
        self.original_tokenizer = self.proxy_module.ProxyService._tokenizer
        self.proxy_module.ProxyService._tokenizer = _FakeTokenizer()

    def tearDown(self):
        self.proxy_module.ProxyService._tokenizer = self.original_tokenizer
        for module_name, module in self.original_modules.items():
            if module is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = module

    def test_streaming_response_skips_think_blocks_and_concatenated_chunk_json_artifacts(self):
        leaked_payload = (
            '{"id":"gen-1776744934-wGCBfaErSvYUDQG06WoQ","object":"chat.completion.chunk",'
            '"created":1776744934,"model":"moonshotai/kimi-k2.5-0127","provider":"Moonshot AI",'
            '"choices":[{"index":0,"delta":{"content":"","role":"assistant","reasoning":"挑è¡",'
            '"reasoning_details":[{"type":"reasoning.text","text":"挑è¡","format":"unknown","index":0}]},'
            '"finish_reason":null,"native_finish_reason":null}]}'
            '{"id":"gen-1776744934-wGCBfaErSvYUDQG06WoQ","object":"chat.completion.chunk",'
            '"created":1776744934,"model":"moonshotai/kimi-k2.5-0127","provider":"Moonshot AI",'
            '"choices":[{"index":0,"delta":{"content":"","role":"assistant","reasoning":"è¾助",'
            '"reasoning_details":[{"type":"reasoning.text","text":"è¾助","format":"unknown","index":0}]},'
            '"finish_reason":null,"native_finish_reason":null}]}'
            '*The ascent was a brutal ballet of desperation and calculated intent.*'
        )

        class FakeStreamingResponse:
            headers = {"content-type": "text/event-stream"}

            def iter_lines(self, decode_unicode=True):
                yield "<think>"
                yield "The user wants a montage showing Mysterious scaling the building."
                yield "</think>"
                yield leaked_payload
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
        self.assertEqual(
            content,
            "*The ascent was a brutal ballet of desperation and calculated intent.*",
        )
        self.assertNotIn("<think>", content)
        self.assertNotIn("Mysterious scaling the building", content)
        self.assertNotIn("chat.completion.chunk", content)
        self.assertNotIn("reasoning_details", content)
        self.assertNotIn("gen-1776744934", content)
        self.assertEqual(chunks[1], "data: [DONE]\n\n")


if __name__ == "__main__":
    unittest.main()
