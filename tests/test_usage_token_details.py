"""Provider-reported token details remain separate from optional price buckets."""

import json

from services import usage_store
from services.usage_types import StreamUsageObserver, UsageObservation


def test_usage_details_survive_partial_streams_and_sql_rollups(tmp_path, monkeypatch):
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.sqlite3"))
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    observer = StreamUsageObserver(65536)
    for body in ({"usage": {"prompt_tokens": 100, "prompt_tokens_details": {"cached_tokens": 60}}},
                 {"usage": {"completion_tokens": 20, "completion_tokens_details": {"reasoning_tokens": 8}}}):
        observer.feed(("data: " + json.dumps(body) + "\n\n").encode())
    observation = observer.finish()
    assert (observation.input_tokens, observation.cached_input_tokens, observation.reasoning_tokens) == (100, 60, 8)
    from tests.test_usage_ledger import row
    store = usage_store.SqlUsageStore()
    store.record("a" * 32, [{**row(tokens=(100, 20)), "cached_input_tokens": 60, "reasoning_tokens": 8}])
    for group in ("model", "principal"):
        [summary] = store.summary(group, "2000-01-01", "2100-01-01", None, 10)
        assert (summary["cached_input_tokens"], summary["reasoning_tokens"]) == (60, 8)
        assert usage_store.summarize(summary)["cache_hit_rate"] == 60
    native = UsageObservation.from_body({"usage": {"input_tokens": 10, "output_tokens": 3,
                                                  "cache_read_input_tokens": 60, "cache_creation_input_tokens": 30}})
    assert (native.input_tokens, native.cached_input_tokens) == (100, 60)
    responses = UsageObservation.from_body({"response": {"usage": {"input_tokens": 100,
        "input_tokens_details": {"cached_tokens": 60}, "output_tokens_details": {"reasoning_tokens": 8}}}})
    assert (responses.cached_input_tokens, responses.reasoning_tokens) == (60, 8)
    assert UsageObservation.from_body({"usage": {"prompt_tokens_details": {"cached_tokens": -1},
                                                "completion_tokens_details": {"reasoning_tokens": True}}}).cached_input_tokens is None
