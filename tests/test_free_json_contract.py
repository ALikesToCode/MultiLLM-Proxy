import copy
import json
import unittest
from unittest.mock import patch

from services.free_json_contract import (
    JsonOutputError,
    check_json_output,
    validate_response_format,
)
from tests.test_free_json_responses import FORMAT
from tests.unified_api_test_case import UnifiedApiTestCase


def contract(schema):
    return {
        "type": "json_schema",
        "json_schema": {"name": "test", "strict": True, "schema": schema},
    }


class JsonContractTest(unittest.TestCase):
    def test_enforces_nested_batch_contract(self):
        schema = {
            "type": "object",
            "properties": {
                "results": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 2,
                    "items": {"$ref": "#/$defs/result"},
                }
            },
            "required": ["results"],
            "additionalProperties": False,
            "$defs": {
                "result": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "color": {"enum": ["red", "blue"]},
                    },
                    "required": ["id", "color"],
                    "additionalProperties": False,
                }
            },
        }
        response_format = contract(schema)
        validate_response_format(response_format)
        good = {"results": [{"id": 1, "color": "red"}]}
        check_json_output(json.dumps(good), response_format)
        invalid = [
            {},
            {"results": []},
            {"results": [good["results"][0]] * 3},
            {"results": [{"id": "1", "color": "red"}]},
            {"results": [{"id": True, "color": "red"}]},
            {"results": [{"id": 1, "color": "green"}]},
            {"results": [{"id": 1}]},
            {"results": [{"id": 1, "color": "red", "extra": 0}]},
            {**good, "extra": 0},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(JsonOutputError) as error:
                check_json_output(json.dumps(value), response_format)
            self.assertEqual(error.exception.reason, "schema_mismatch")

    def test_composition_constraints_and_nullable_values(self):
        response_format = contract(
            {
                "anyOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 1, "maximum": 3},
                ]
            }
        )
        for text in ("null", "1", "3"):
            check_json_output(text, response_format)
        for text in ('"1"', "0", "4"):
            with self.assertRaises(JsonOutputError):
                check_json_output(text, response_format)

    def test_duplicate_properties_and_nonfinite_numbers_are_invalid(self):
        for text in (
            '{"color":"red","color":"blue"}',
            "NaN",
            "Infinity",
            "-Infinity",
            "1e999",
        ):
            with self.subTest(text=text), self.assertRaises(JsonOutputError) as error:
                check_json_output(text, FORMAT)
            self.assertEqual(error.exception.reason, "invalid_json")

    def test_external_references_never_retrieve_network_resources(self):
        for reference in (
            "https://example.test/schema",
            "file:///etc/passwd",
            "//example.test/schema",
        ):
            with (
                self.subTest(reference=reference),
                patch("urllib.request.urlopen") as fetch,
            ):
                with self.assertRaises(ValueError):
                    validate_response_format(contract({"$ref": reference}))
                fetch.assert_not_called()

    def test_literal_ref_property_does_not_count_as_reference(self):
        response_format = contract(
            {"type": "object", "properties": {"$ref": {"type": "string"}}}
        )
        validate_response_format(response_format)
        check_json_output('{"$ref":"literal"}', response_format)

    def test_draft_7_is_supported_but_unknown_dialect_is_not(self):
        response_format = contract(
            {"$schema": "http://json-schema.org/draft-07/schema#", "const": "red"}
        )
        validate_response_format(response_format)
        check_json_output('"red"', response_format)
        with self.assertRaises(ValueError):
            validate_response_format(
                contract({"$schema": "https://example.test/custom"})
            )


class JsonSchemaRequestTest(UnifiedApiTestCase):
    def test_invalid_schemas_fail_before_provider_dispatch(self):
        deep = {}
        for _ in range(40):
            deep = {"properties": {"child": deep}}
        invalid = [
            "json",
            {"type": "unknown"},
            {"type": "json_schema"},
            contract({"type": "bogus"}),
            contract({"required": "color"}),
            contract({"$ref": "https://example.test/private"}),
            contract({"description": "x" * (64 * 1024)}),
            contract(deep),
            contract({"enum": list(range(5000))}),
        ]
        bad_strict = copy.deepcopy(FORMAT)
        bad_strict["json_schema"]["strict"] = "true"
        invalid.append(bad_strict)
        with patch("app.ProxyService.make_request") as send:
            for response_format in invalid:
                with self.subTest(response_format=str(response_format)[:80]):
                    response = self.client.post(
                        "/v1/chat/completions",
                        headers={"Authorization": "Bearer admin-test-key"},
                        json={
                            "model": "free:text",
                            "messages": [{"role": "user", "content": "Hello"}],
                            "response_format": response_format,
                        },
                    )
                    self.assertEqual(response.status_code, 400)
            send.assert_not_called()
