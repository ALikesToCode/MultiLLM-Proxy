import json
import sqlite3
from pathlib import Path

import pytest
from flask import Flask, Response, g

from services import prompt_cache_cost as cache, request_accounting as accounting, usage_store
from services.cost_service import CostService
from services.protocol_translation.anthropic import _anthropic_usage_to_chat, _chat_usage_to_anthropic
from tests.test_usage_ledger import row


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.setenv('PROMPT_CACHE_USAGE_BUCKETS_ENABLED', 'true')
    monkeypatch.setenv('CONTROL_PLANE_DATABASE_URL', '')
    monkeypatch.setenv('MODEL_PRICING_USD_PER_MILLION', json.dumps({'openai:m': {
        'input': 2, 'output': 8, 'cache_read': 0.5, 'cache_write': 3}}))
    monkeypatch.setenv('PROMPT_CACHE_PRICE_METADATA_JSON', '{}')


def observe(usage):
    return accounting._usage_from({'usage': usage})


def context(model='openai:m'):
    return accounting.UsageContext(kind='chat', models=[model], provider=None,
        user={'username': 'reader'}, started=accounting.time.perf_counter(), start_ns=1,
        input_tokens=50, output_tokens=60, path='/v1/chat/completions', trace=(None, None))


@pytest.mark.parametrize('flag', ['', 'false', 'garbage'])
def test_disabled_preserves_rows_prices_translation_and_schema(monkeypatch, flag):
    monkeypatch.setenv('PROMPT_CACHE_USAGE_BUCKETS_ENABLED', flag)
    usage = observe({'prompt_tokens': 100, 'completion_tokens': 10,
                     'prompt_tokens_details': {'cached_tokens': 60}})
    result = accounting._row(context(), 200, usage, None)
    assert set(result) == set(usage_store.ROW_FIELDS)
    assert result['cost_usd'] == 0.00028
    assert _anthropic_usage_to_chat({})['prompt_tokens'] == 0
    connection = sqlite3.connect(':memory:')
    usage_store.SqlUsageStore.ensure(connection)
    assert 'ordinary_input_tokens' not in {item[1] for item in connection.execute('PRAGMA table_info(usage_events)')}


@pytest.mark.parametrize('usage,expected', [
    ({'prompt_tokens': 100, 'completion_tokens': 10, 'prompt_tokens_details': {'cached_tokens': 60}}, (40, 60, 0, 10)),
    ({'input_tokens': 40, 'output_tokens': 10, 'cache_read_input_tokens': 60, 'cache_creation_input_tokens': 20}, (40, 60, 20, 10)),
    ({'prompt_tokens': 100, 'completion_tokens': 0, 'prompt_tokens_details': {'cached_tokens': 0}}, (100, 0, 0, 0)),
    ({'prompt_tokens': 100, 'completion_tokens': 10}, (None, None, 0, 10)),
    ({'prompt_tokens': 4, 'prompt_tokens_details': {'cached_tokens': 8}}, (None, 8, 0, None)),
    ({'input_tokens': True, 'cache_creation_input_tokens': -1}, (None, None, None, None)),
])
def test_inclusive_exclusive_and_unknown_counts(usage, expected):
    buckets = cache.buckets_from(observe(usage))
    assert tuple(buckets[name] for name in cache.TOKEN_FIELDS) == expected


def test_costs_and_metadata_supplement_only(monkeypatch):
    usage = observe({'prompt_tokens': 100, 'completion_tokens': 10,
                     'prompt_tokens_details': {'cached_tokens': 60}})
    result = accounting._row(context(), 200, usage, None)
    assert result['cost_usd'] == 0.00019
    assert result['ordinary_input_cost_microusd'] == 80
    assert result['cache_read_input_cost_microusd'] == 30
    assert result['bucket_basis'] == 'measured'
    monkeypatch.setenv('PROMPT_CACHE_PRICE_METADATA_JSON', json.dumps({'openai:m': {'cache_read': 0.01}}))
    assert CostService.price_buckets('openai:m', usage)['cost_usd'] == 0.00019
    monkeypatch.setenv('MODEL_PRICING_USD_PER_MILLION', json.dumps({'openai:m': {'input': 2, 'output': 8}}))
    assert CostService.price_buckets('openai:m', usage)['cost_usd'] == 0.0001606
    assert CostService.price_buckets('missing', usage)['cost_usd'] is None
    monkeypatch.setenv('PROMPT_CACHE_PRICE_METADATA_JSON', '{}')
    missing = CostService.price_buckets('openai:m', usage)
    assert missing['cost_usd'] is None and missing['ordinary_input_cost_microusd'] == 80
    assert missing['cache_read_input_cost_microusd'] is None


def test_missing_counts_zero_prices_and_bounds(monkeypatch):
    monkeypatch.setenv('MODEL_PRICING_USD_PER_MILLION', json.dumps({'free': {
        'input': 0, 'output': 0, 'cache_read': 0, 'cache_write': 0}}))
    assert CostService.price_buckets('free', observe({}))['cost_usd'] == 0
    monkeypatch.setenv('MODEL_PRICING_USD_PER_MILLION', json.dumps({'huge': {
        'input': '1e100', 'output': 0, 'cache_read': 0, 'cache_write': 0}}))
    assert CostService.price_buckets('huge', observe({'prompt_tokens': 2, 'prompt_tokens_details': {'cached_tokens': 0}}))['cost_usd'] is None
    assert cache.buckets_from(observe({'prompt_tokens': 2**53}))['ordinary_input_tokens'] is None


def test_split_sse_and_translations_preserve_unknown_and_cache_counts():
    observer = cache.CacheStreamObserver(256)
    data = (b'data: {"message":{"usage":{"input_tokens":40,"cache_read_input_tokens":60,"cache_creation_input_tokens":20}}}\n\n'
            b'data: {"usage":{"output_tokens":10}}\n\n')
    for start in range(0, len(data), 7):
        observer.feed(data[start:start+7])
    usage = observer.finish()
    assert tuple(cache.buckets_from(usage)[name] for name in cache.TOKEN_FIELDS) == (40, 60, 20, 10)
    chat = _anthropic_usage_to_chat({'input_tokens': 40, 'cache_read_input_tokens': 60, 'cache_creation_input_tokens': 20})
    assert chat['prompt_tokens'] == 120 and chat['completion_tokens'] is None
    reverse = _chat_usage_to_anthropic(chat)
    assert reverse == {'input_tokens': 40, 'output_tokens': None, 'cache_creation_input_tokens': 20, 'cache_read_input_tokens': 60}
    assert _anthropic_usage_to_chat({})['prompt_tokens'] is None


def test_registered_accounting_stream_keeps_body_and_records_once(monkeypatch):
    app = Flask(__name__)
    rows = []
    monkeypatch.setattr(accounting.usage_ledger.LEDGER, 'record', lambda row: rows.append(row))
    monkeypatch.setattr(accounting.BudgetService, 'record_cost', lambda row: None)
    monkeypatch.setattr(accounting.BudgetService, 'settle', lambda reservation: None)
    monkeypatch.setattr(accounting.telemetry_export.EXPORTER, 'submit', lambda row: None)
    data = b'data: {"usage":{"prompt_tokens":100,"completion_tokens":10,"prompt_tokens_details":{"cached_tokens":60}}}\n\n'
    @app.post('/v1/chat/completions')
    def completion():
        g.usage_context = context()
        return accounting.finish(Response((data[i:i+9] for i in range(0, len(data), 9)), mimetype='text/event-stream'))
    response = app.test_client().post('/v1/chat/completions')
    assert response.get_data() == data
    response.close()
    assert len(rows) == 1 and rows[0]['cache_read_input_tokens'] == 60


def test_sqlite_additive_migration_old_rows_and_bucket_serialization(tmp_path, monkeypatch):
    monkeypatch.setenv('USAGE_DB_PATH', str(tmp_path/'usage.sqlite3'))
    store = usage_store.SqlUsageStore()
    monkeypatch.setenv('PROMPT_CACHE_USAGE_BUCKETS_ENABLED', 'false')
    store.record('a'*32, [row()])
    monkeypatch.setenv('PROMPT_CACHE_USAGE_BUCKETS_ENABLED', 'true')
    result = accounting._row(context(), 200, observe({'prompt_tokens': 100, 'completion_tokens': 10,
        'prompt_tokens_details': {'cached_tokens': 60}}), None)
    store.record('b'*32, [result])
    recent = store.recent('2000', None, None, 10)
    assert recent[0]['cache_read_input_tokens'] == 60
    assert recent[1]['cache_read_input_tokens'] is None
    db = sqlite3.connect(':memory:')
    monkeypatch.setenv('PROMPT_CACHE_USAGE_BUCKETS_ENABLED', 'false')
    store.ensure(db)
    db.executescript(Path('intelligence-migrations/0016_usage_buckets.sql').read_text())
    assert set(cache.ROW_FIELDS) <= {item[1] for item in db.execute('PRAGMA table_info(usage_events)')}


def test_d1_enabled_sends_nullable_buckets_without_changing_disabled_payload(monkeypatch):
    calls = []
    monkeypatch.setattr(usage_store.intelligence_d1_store, 'request_private_intelligence',
        lambda body, **kwargs: calls.append(body) or {'version': 1, 'recorded': 1, 'duplicate': False})
    result = accounting._row(context(), 200, observe({}), None)
    usage_store.D1UsageStore().record('a'*32, [result])
    assert calls[0]['rows'][0]['cache_read_input_tokens'] is None
    monkeypatch.setenv('PROMPT_CACHE_USAGE_BUCKETS_ENABLED', 'false')
    usage_store.D1UsageStore().record('b'*32, [result])
    assert set(calls[1]['rows'][0]) == set(usage_store.ROW_FIELDS)


@pytest.mark.parametrize('metadata', ['bad json', '[]', '{"openai:m":{"cache_read":-1}}'])
def test_bad_metadata_disables_feature_without_logging_value(monkeypatch, caplog, metadata):
    monkeypatch.setenv('PROMPT_CACHE_PRICE_METADATA_JSON', metadata)
    assert not cache.enabled()
    assert metadata not in caplog.text
    assert set(accounting._row(context(), 200, observe({'prompt_tokens': 1}), None)) == set(usage_store.ROW_FIELDS)


def test_stream_keeps_prior_counts_after_nulls_and_drops_oversized_lines():
    observer = cache.CacheStreamObserver(200)
    observer.feed(b'data: {"usage":{"prompt_tokens":100,"prompt_tokens_details":{"cached_tokens":60},"completion_tokens":0}}\n')
    observer.feed(b'data: ' + b'x'*201 + b'\n')
    observer.feed(b'data: {"usage":{"prompt_tokens":null,"completion_tokens":null}}\n')
    buckets = cache.buckets_from(observer.finish())
    assert tuple(buckets[name] for name in cache.TOKEN_FIELDS) == (40, 60, 0, 0)


def test_sqlite_schema_upgrade_and_writes_are_safe_under_concurrency(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setenv('USAGE_DB_PATH', str(tmp_path/'parallel.sqlite3'))
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda i: usage_store.SqlUsageStore().record(format(i, '032x'), [row()]), range(8))) == [1]*8
    assert len(usage_store.SqlUsageStore().recent('2000', None, None, 20)) == 8


def test_real_authenticated_route_keeps_native_body_and_bucket_ledger(tmp_path, monkeypatch):
    from unittest.mock import patch
    from services import usage_ledger
    from tests.unified_api_test_case import UnifiedApiTestCase

    monkeypatch.setenv('USAGE_LEDGER_ENABLED', 'true')
    monkeypatch.setenv('USAGE_DB_PATH', str(tmp_path/'routes.sqlite3'))
    monkeypatch.setenv('USAGE_LEDGER_BACKEND', 'sql')
    monkeypatch.setenv('USAGE_LEDGER_FLUSH_SECONDS', '300')
    fixture = UnifiedApiTestCase()
    usage_ledger.LEDGER.reset()
    with patch('config.load_runtime_env'):
        fixture.setUp()
    try:
        upstream = fixture._chat_response()
        body = {'id': 'chatcmpl-cache', 'object': 'chat.completion',
                'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'ok'}, 'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 100, 'completion_tokens': 10, 'prompt_tokens_details': {'cached_tokens': 60}}}
        upstream._content = json.dumps(body).encode()
        monkeypatch.setenv('MODEL_PRICING_USD_PER_MILLION', json.dumps({'opencode:m': {'input': 2, 'output': 8, 'cache_read': 0.5}}))
        with patch('app.ProxyService.make_request', return_value=upstream):
            response = fixture.client.post('/v1/chat/completions', headers={'Authorization': 'Bearer admin-test-key'},
                json={'model': 'opencode:m', 'messages': [{'role': 'user', 'content': 'hi'}]})
            assert response.status_code == 200
            assert response.get_json()['usage'] == body['usage']
        assert usage_ledger.LEDGER.flush(timeout=5)
        stored = usage_ledger.LEDGER.store().recent('2000', None, None, 10)
        assert stored[0]['cache_read_input_tokens'] == 60 and stored[0]['cost_usd'] == 0.00019
    finally:
        usage_ledger.LEDGER.reset()
        fixture.tearDown()


def test_enabled_accounting_does_not_run_unbounded_legacy_costs(monkeypatch):
    monkeypatch.setenv('MODEL_PRICING_USD_PER_MILLION', json.dumps({'openai:m': {
        'input': '1e100', 'output': 0, 'cache_read': 0, 'cache_write': 0}}))
    result = accounting._row(context(), 200, observe({'prompt_tokens': 2, 'completion_tokens': 0,
        'prompt_tokens_details': {'cached_tokens': 0}}), None)
    assert result['cost_usd'] is None and result['ordinary_input_tokens'] == 2


def test_python_worker_serialization_parity():
    import subprocess

    result = accounting._row(context(), 200, observe({'prompt_tokens': 100, 'completion_tokens': 10,
        'prompt_tokens_details': {'cached_tokens': 60}}), None)
    process = subprocess.run(['node', '--input-type=module', '-e',
        "import {serializeUsageBuckets} from './worker/usage-buckets-d1.mjs';"
        "let s='';for await(const b of process.stdin)s+=b;"
        "console.log(JSON.stringify(serializeUsageBuckets(JSON.parse(s),{PROMPT_CACHE_USAGE_BUCKETS_ENABLED:'true'})));"],
        input=json.dumps(result), text=True, capture_output=True, check=True)
    assert json.loads(process.stdout) == result


def test_partial_cache_budget_estimates_and_failure_recording_are_bounded(monkeypatch):
    from services.usage_types import UsageObservation

    estimated = UsageObservation().with_estimates(100, 10)
    assert cache.buckets_from(estimated)['bucket_basis'] == 'estimated'
    assert cache.budget_price(['openai:m'], estimated, 1) == 0.00028
    monkeypatch.setenv('MODEL_PRICING_USD_PER_MILLION', json.dumps({'openai:m': {'input': '1e100', 'output': 0}}))
    rows = []
    monkeypatch.setattr(accounting.usage_ledger.LEDGER, 'record', lambda row: rows.append(row))
    monkeypatch.setattr(accounting.BudgetService, 'record_cost', lambda row: None)
    monkeypatch.setattr(accounting.BudgetService, 'settle', lambda reservation: None)
    monkeypatch.setattr(accounting.telemetry_export.EXPORTER, 'submit', lambda row: None)
    accounting._record(context(), 200, observe({'prompt_tokens': 2, 'completion_tokens': 0}), None)
    assert len(rows) == 1 and rows[0]['cost_usd'] is None


def test_embeddings_keep_cache_observations_with_known_zero_output():
    c = context()
    c.kind, c.path = 'embeddings', '/v1/embeddings'
    result = accounting._row(c, 200, observe({'prompt_tokens': 100,
        'prompt_tokens_details': {'cached_tokens': 60}}), None)
    assert result['cache_read_input_tokens'] == 60
    assert result['ordinary_input_tokens'] == 40
    assert result['output_tokens'] == 0 and result['cost_usd'] == 0.00011


def test_migration_adds_nullable_bucket_columns_and_keeps_existing_rows():
    db = sqlite3.connect(':memory:')
    for path in sorted(Path('intelligence-migrations').glob('*.sql')):
        if path.name.startswith('0016_'):
            db.execute("INSERT INTO usage_events (at, day, principal, kind, endpoint, status, latency_ms) "
                       "VALUES ('2026-10-09T00:00:00Z', '2026-10-09', 'old', 'chat', '/v1/chat/completions', 200, 5)")
        db.executescript(path.read_text())
    columns = {item[1] for item in db.execute('PRAGMA table_info(usage_events)')}
    assert set(usage_store.EVENT_COLUMNS) <= columns
    assert set(cache.ROW_FIELDS) <= columns
    assert db.execute('SELECT principal, ordinary_input_tokens, bucket_basis FROM usage_events').fetchall() == [
        ('old', None, None)]
