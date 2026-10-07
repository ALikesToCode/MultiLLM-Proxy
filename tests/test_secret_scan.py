"""Synthetic vectors shared with the Worker; no live credential fixtures."""
import json
from pathlib import Path
import subprocess
import time

import pytest
from services.secret_scan import scan_text, redact_text, scan_payload, redact_payload

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests/fixtures/secret_scan_vectors.json").read_text())

@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_vectors(vector):
    text = "".join(vector["parts"])
    findings = scan_text(text)
    assert [f["type"] for f in findings] == vector["types"]
    if "field" in vector:
        assert scan_payload({vector["field"]: text})["types"] == vector["payload_types"]
    updated = redact_text(text, findings)
    assert scan_text(updated) == [f for f in findings if f["confidence"] == "heuristic"]
    assert redact_text(text, findings) == updated


def test_runtime_parity():
    source = """import {readFileSync} from 'node:fs';
import {scanText,redactText,scanPayload} from './worker/secret-scan.mjs';
const vectors=JSON.parse(readFileSync('./tests/fixtures/secret_scan_vectors.json'));
console.log(JSON.stringify(vectors.map(v=>{const text=v.parts.join('');const findings=scanText(text);
return [findings,redactText(text,findings),scanPayload(v.field ? {[v.field]:text} : {messages:[text]})]})));"""
    output = subprocess.run(["node", "--input-type=module", "-e", source], cwd=ROOT, check=True, capture_output=True, text=True)
    expected = []
    for v in VECTORS:
        text = "".join(v["parts"]); findings = scan_text(text)
        expected.append([findings, redact_text(text, findings), scan_payload({v["field"]: text} if "field" in v else {"messages": [text]})])
    assert json.loads(output.stdout) == expected


def test_payload_limits_skips_and_modes():
    token = "".join(VECTORS[2]["parts"])
    payload = {"messages": [token, token], "password": "AbCdEf0123456789", "image": "ABcd0123" * 100,
               "data": "data:image/png;base64," + token + "+/="}
    updated, report = redact_payload(payload, mode="redact")
    assert report["high"] == 2 and report["heuristic"] == 1
    assert updated["messages"][0] == updated["messages"][1]
    assert updated["password"] == payload["password"]
    assert payload["messages"][0] == token
    assert report["paths"] == ['$["messages"][0]', '$["messages"][1]', '$["password"]']
    for mode in ("observe", "block"):
        assert redact_payload(payload, mode=mode)[0] is payload
    assert redact_payload(payload, mode="off")[1]["high"] == 0
    assert scan_payload(payload, max_bytes=3)["truncated"]
    assert scan_payload({"a": "🙂", "b": token}, max_bytes=1)["high"] == 0
    assert len(scan_payload([token] * 25)["paths"]) == 20
    nested = token
    for _ in range(70): nested = [nested]
    assert scan_payload(nested)["truncated"]


def test_performance():
    text = ("ordinary log text API_TOKEN=AbCdEf0123456789; " * 24000)[:1000000]
    start = time.perf_counter()
    scan_text(text)
    assert time.perf_counter() - start < 0.5
    start = time.perf_counter()
    assert not scan_text("A" * 1000000)
    assert time.perf_counter() - start < 0.5


def test_incomplete_example_delimiters_remain_bounded():
    start = time.perf_counter()
    assert not scan_text("<" * 1000000)
    assert time.perf_counter() - start < 0.5


def test_many_incomplete_private_key_markers_remain_bounded():
    text = ("-----" + "BEGIN RSA PRIVATE KEY" + "-----\n") * 30000
    start = time.perf_counter()
    assert not scan_text(text)
    assert time.perf_counter() - start < 0.5
