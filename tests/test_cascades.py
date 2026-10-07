"""Synthetic cascade acceptance tests; no provider or deployed gateway calls."""

import copy
import json
from unittest.mock import patch

import pytest
from flask import Flask, Response, g, jsonify

from error_handlers import APIError
from services import cascade_d1, intelligence_d1_store, request_accounting, usage_ledger
from services.budget_service import BudgetDecision, BudgetService
from services.cascade_checks import agrees, judge_passes, local_check
from services.cascade_config import normalize_config
from services.cascade_service import CascadeService
from services.rate_limit_service import LimitDecision, RateLimitService

CONFIG = {"name": "cascade:test", "tiers": [{"model": "opencode:cheap"}, {"model": "opencode:strong"}], "checks": ["complete"]}
PAYLOAD = {"model": "cascade:test", "messages": [{"role": "user", "content": "What is two plus two?"}]}
TOOLS = [{"type": "function", "function": {"name": "lookup", "parameters": {"type": "object", "required": ["count"], "properties": {"count": {"type": "integer"}}, "additionalProperties": False}}}]


def answer(text="4", finish="stop", calls=None):
    message = {"role": "assistant", "content": text}
    if calls is not None:
        message["tool_calls"] = calls
    return {"id": "chatcmpl-synthetic", "object": "chat.completion", "model": "opencode:cheap", "created": 1,
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}}


@pytest.fixture
def context(monkeypatch):
    app = Flask(__name__)
    rows = []
    monkeypatch.setattr(usage_ledger.LEDGER, "record", lambda row: rows.append(row))
    monkeypatch.setattr(BudgetService, "record_cost", lambda row: None)
    monkeypatch.setattr(BudgetService, "settle", lambda value: None)
    monkeypatch.setattr(RateLimitService, "enforce_request", lambda **kwargs: LimitDecision(True, metadata={}))
    from services import telemetry_export
    monkeypatch.setattr(telemetry_export.EXPORTER, "submit", lambda row: None)
    with app.test_request_context('/v1/chat/completions', method='POST', json=PAYLOAD):
        g.authenticated_user = {"username": "synthetic", "is_admin": True}
        yield app, rows


def run(config, bodies, payload=None, **kwargs):
    from routes.cascades import dispatch_cascade
    calls = []
    def dispatch(body, remaining):
        calls.append(copy.deepcopy(body))
        value = bodies[len(calls) - 1]
        if isinstance(value, BaseException):
            raise value
        if isinstance(value, Response):
            return value
        if callable(value):
            return value(body, remaining)
        return jsonify(value)
    with patch.object(CascadeService, 'get_route', return_value=normalize_config(config)):
        response = dispatch_cascade(copy.deepcopy(payload or PAYLOAD), dispatch, **kwargs)
    return response, calls


@pytest.mark.parametrize('change', [
    {'name': 'bad'}, {'name': 'cascade:'}, {'name': 'cascade:a b'}, {'tiers': []},
    {'tiers': [{'model': 'opencode:x'}] * 5}, {'tiers': [{'model': 'cascade:x'}, {'model': 'opencode:y'}]},
    {'tiers': [{'model': 'opencode:x', 'max_output_tokens': True}, {'model': 'opencode:y'}]},
    {'tiers': [{'model': 'opencode:x', 'max_output_tokens': 0}, {'model': 'opencode:y'}]},
    {'checks': ['judge']}, {'checks': ['complete'] * 2}, {'checks': ['unknown']},
    {'checks': 'complete'}, {'checks': [[]]}, {'judge': {'model': 'opencode:j', 'min_score': True}},
    {'judge': {'model': 'opencode:j', 'min_score': float('nan')}},
    {'judge': {'model': 'opencode:j', 'min_score': 11}}, {'agreement': {'extra': 1}}, {'extra': 1}
])
def test_config_validation(change):
    with pytest.raises(ValueError):
        normalize_config({**CONFIG, **change})


def test_config_order_defaults_and_bounds():
    config = normalize_config({**CONFIG, 'checks': ['judge', 'complete', 'agreement'], 'judge': {'model': 'free:text'}, 'agreement': {}})
    assert config['checks'] == ['complete', 'agreement', 'judge']
    assert config['judge']['min_score'] == 7
    assert config['agreement'] == {}


def test_first_tier_pass_and_output_cap(context):
    payload = {**PAYLOAD, 'max_tokens': 50, 'stream': True}
    config = {**CONFIG, 'tiers': [{'model': 'opencode:cheap', 'max_output_tokens': 20}, CONFIG['tiers'][1]]}
    response, calls = run(config, [answer()], payload)
    assert len(calls) == len(context[1]) == 1
    assert calls[0]['stream'] is False and calls[0]['max_completion_tokens'] == 20
    assert 'max_tokens' not in calls[0]
    assert response.headers['X-MultiLLM-Cascade'] == 'tier=1/2; model=opencode:cheap; skipped='
    data = b''.join(response.iter_encoded())
    response.close()
    assert b'chat.completion.chunk' in data and b'data: [DONE]' in data
    assert b'"content": "4"' in data or b'"content":"4"' in data
    assert len(context[1]) == 1, 'SSE replay never charges an extra call'


@pytest.mark.parametrize('check,bad,extra', [
    ('complete', answer(''), {}), ('complete', answer('partial', 'length'), {}),
    ('json', answer('not JSON'), {'response_format': {'type': 'json_object'}}),
    ('json', answer('{"n":"wrong"}'), {'response_format': {'type': 'json_schema', 'json_schema': {'schema': {'type': 'object', 'required': ['n'], 'properties': {'n': {'type': 'integer'}}}}}}),
    ('tools', answer(None, 'tool_calls', [{'id': 'synthetic-call', 'type': 'function', 'function': {'name': 'lookup', 'arguments': '{}'}}]), {'tools': TOOLS}),
    ('no_refusal', answer("I'm sorry, I cannot help with that request."), {}),
])
def test_escalation_for_every_local_check_and_final_unchecked(context, check, bad, extra):
    response, calls = run({**CONFIG, 'checks': [check]}, [bad, answer('', 'length')], {**PAYLOAD, **extra})
    assert len(calls) == len(context[1]) == 2
    assert response.get_json()['choices'][0]['message']['content'] == ''
    assert f'skipped=1:{check}' in response.headers['X-MultiLLM-Cascade']
    assert 'tier=2/2' in response.headers['X-MultiLLM-Cascade']


def test_all_fail_returns_final_and_upstream_error_escalates(context):
    config = {**CONFIG, 'tiers': [CONFIG['tiers'][0], {'model': 'opencode:middle'}, CONFIG['tiers'][1]]}
    response, calls = run(config, [answer(''), {'error': {'message': 'synthetic failure'}}, answer('final', 'length')])
    assert len(calls) == 3
    assert response.get_json()['choices'][0]['message']['content'] == 'final'
    assert 'skipped=1:complete,2:complete' in response.headers['X-MultiLLM-Cascade']


def test_tools_repair_is_returned_and_replayed(context):
    call = {'id': 'synthetic-call', 'type': 'function', 'function': {'name': 'LOOKUP', 'arguments': "{'count': '2',}"}}
    response, calls = run({**CONFIG, 'checks': ['tools']}, [answer(None, 'tool_calls', [call])], {**PAYLOAD, 'tools': TOOLS, 'stream': True})
    raw = b''.join(response.iter_encoded()).decode()
    response.close()
    chunks = [json.loads(line.removeprefix('data: ')) for line in raw.splitlines() if line.startswith('data: {')]
    fragments = [call for chunk in chunks for choice in chunk.get('choices', []) for call in choice.get('delta', {}).get('tool_calls', [])]
    assert any(call.get('function', {}).get('name') == 'lookup' for call in fragments)
    arguments = ''.join(call.get('function', {}).get('arguments', '') for call in fragments)
    assert json.loads(arguments) == {'count': 2}
    assert len(calls) == 1


def test_json_success_and_strict_failure():
    fmt = {'response_format': {'type': 'json_schema', 'json_schema': {'schema': {'type': 'object', 'required': ['n'], 'properties': {'n': {'type': 'integer'}}, 'additionalProperties': False}}}}
    assert local_check('json', answer('{"n":2}'), fmt, 200)
    for text in ('{"n": NaN}', '{"n":2,"n":3}', '{"extra":2}', '{}'):
        assert not local_check('json', answer(text), fmt, 200)
    assert local_check('json', answer('prose'), {}, 200)


@pytest.mark.parametrize('left,right,expected', [('4', '4.00', True), ('1e3', '1000', True), ('-0', '0', True), ('４  Hello', '4 hello', True), ('Yes', '  YES ', True), ('4', '5', False)])
def test_numeric_and_normalized_agreement(left, right, expected):
    assert agrees(left, right) == expected


@pytest.mark.parametrize('repeat,escalates', [('4.0', False), ('5', True)])
def test_agreement_calls_are_accounted(context, repeat, escalates):
    response, calls = run({**CONFIG, 'checks': ['agreement']}, [answer('4'), answer(repeat), answer('final')])
    assert len(calls) == len(context[1]) == (3 if escalates else 2)
    assert ('1:agreement' in response.headers['X-MultiLLM-Cascade']) == escalates


def test_long_answers_skip_agreement(context):
    response, calls = run({**CONFIG, 'checks': ['agreement']}, [answer('x' * 301)])
    assert len(calls) == 1 and response.status_code == 200


@pytest.mark.parametrize('judge,escalates', [('{"score":8}', False), ('{"score":6}', True), ('bad', False), ('{"score":true}', False), ('{"score":99}', False), (APIError('synthetic judge error', 503), False)])
def test_judge_pass_fail_error_and_every_call_accounted(context, judge, escalates):
    judged = judge if isinstance(judge, Exception) else answer(judge)
    response, calls = run({**CONFIG, 'checks': ['judge'], 'judge': {'model': 'opencode:judge'}}, [answer('4'), judged, answer('final')])
    assert len(calls) == len(context[1]) == (3 if escalates else 2)
    assert ('1:judge' in response.headers['X-MultiLLM-Cascade']) == escalates
    assert calls[1]['response_format'] == {'type': 'json_object'}
    assert calls[1]['messages'][0]['role'] == 'system'


def test_outer_aggregate_released_and_four_calls_have_four_rows(context):
    g.usage_context = request_accounting.UsageContext(kind='chat', models=['cascade:test'], provider=None, user=g.authenticated_user, started=0, start_ns=0)
    config = {**CONFIG, 'checks': ['agreement', 'judge'], 'judge': {'model': 'opencode:judge'}}
    response, calls = run(config, [answer('4'), answer('4.0'), answer('{"score":3}'), answer('final')])
    assert len(calls) == len(context[1]) == 4
    assert [row['requested_model'] for row in context[1]] == ['opencode:cheap', 'opencode:cheap', 'opencode:judge', 'opencode:strong']
    assert all(row['input_tokens'] == 3 and row['output_tokens'] == 2 for row in context[1])
    assert g.usage_context is None
    response.close()


def test_final_stream_passes_through_and_records_usage_on_close(context):
    events = ['data: ' + json.dumps({'id': 'synthetic', 'model': 'opencode:strong', 'choices': [{'index': 0, 'delta': {'content': 'final'}, 'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 11, 'completion_tokens': 7, 'total_tokens': 18}}) + '\n\n', 'data: [DONE]\n\n']
    response, calls = run(CONFIG, [answer(''), Response(iter(events), content_type='text/event-stream')], {**PAYLOAD, 'stream': True})
    assert calls[-1]['stream'] is True
    assert len(context[1]) == 1
    assert b''.join(response.iter_encoded()).decode() == ''.join(events)
    response.close()
    response.close()
    assert len(context[1]) == 2 and context[1][-1]['input_tokens'] == 11 and context[1][-1]['output_tokens'] == 7


def test_deadline_returns_best_without_another_tier(context):
    response, calls = run(CONFIG, [answer('partial', 'length')], timeout=0.5)
    assert len(calls) == 1
    assert response.get_json()['choices'][0]['message']['content'] == 'partial'
    assert '2:deadline' in response.headers['X-MultiLLM-Cascade']


def test_cascade_and_tier_allowlists(context):
    g.authenticated_user = {'username': 'synthetic', 'allowed_models': ['opencode:*']}
    with pytest.raises(APIError) as caught:
        run(CONFIG, [answer()])
    assert caught.value.status_code == 403 and context[1] == []
    g.authenticated_user['allowed_models'] = ['cascade:test', 'opencode:strong']
    response, calls = run(CONFIG, [answer('final')])
    assert [call['model'] for call in calls] == ['opencode:strong']
    assert '1:admission' in response.headers['X-MultiLLM-Cascade']


def test_judge_and_agreement_gemini_exclusion_scoped(context):
    def check_flag(body, remaining):
        assert g.judge_exclude_gemini == body['model'].startswith(('auto:', 'free:'))
        return jsonify(answer('{"score":9}' if body['model'].endswith('judge') else '4'))
    config = {**CONFIG, 'checks': ['agreement', 'judge'], 'agreement': {'model': 'auto:repeat'}, 'judge': {'model': 'free:judge'}}
    response, calls = run(config, [answer(), check_flag, check_flag])
    assert response.status_code == 200 and not g.judge_exclude_gemini
    run({**CONFIG, 'checks': ['judge'], 'judge': {'model': 'gemini:judge'}}, [answer(), check_flag])


def test_secret_firewall_failure_is_not_swallowed(context):
    error = APIError('Synthetic blocked content', 422, {'error': 'secret_detected'})
    with pytest.raises(APIError) as caught:
        run(CONFIG, [error])
    assert caught.value.status_code == 422


def test_budget_denial_keeps_best(context, monkeypatch):
    g.authenticated_user = {'username': 'synthetic', 'daily_budget_usd': 1}
    from services import accounted_dispatch as dispatch_module
    monkeypatch.setattr(dispatch_module, 'budgeted', lambda user: True)
    decisions = iter([BudgetDecision(True, reservation='synthetic-reservation'), BudgetDecision(False, status_code=402, error='budget_exceeded', message='Synthetic budget denial')])
    monkeypatch.setattr(BudgetService, 'check_and_reserve', lambda *args: next(decisions))
    response, calls = run(CONFIG, [answer('partial', 'length')])
    assert len(calls) == 1 and response.get_json()['choices'][0]['message']['content'] == 'partial'


def test_sqlite_storage_roundtrip_and_seed_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv('INTELLIGENCE_STORAGE_BACKEND', '')
    monkeypatch.setenv('MODEL_REGISTRY_DB_PATH', str(tmp_path / 'models.sqlite3'))
    saved = CascadeService.save_route(CONFIG, {'opencode': 'https://synthetic.invalid'})
    assert saved['updated_at']
    assert CascadeService.get_route(CONFIG['name']) == saved
    assert len(CascadeService.list_routes()) == 1


def test_d1_storage_cached_outage_and_save_failure(monkeypatch):
    monkeypatch.setenv('INTELLIGENCE_STORAGE_BACKEND', 'd1')
    stored, calls = {}, []
    def transport(body, *, endpoint):
        assert endpoint == 'cascades'
        calls.append(body['operation'])
        if body['operation'] == 'put':
            stored[body['cascade']['name']] = body['cascade']
            return {'version': 1, 'stored': True}
        return {'version': 1, 'cascades': list(stored.values())}
    monkeypatch.setattr(intelligence_d1_store, 'request_private_intelligence', transport)
    cascade_d1.reset_cache()
    saved = CascadeService.save_route(CONFIG, {'opencode': 'https://synthetic.invalid'})
    cascade_d1.reset_cache()
    assert CascadeService.get_route(CONFIG['name']) == saved
    assert CascadeService.get_route(CONFIG['name']) == saved
    assert calls.count('list') == 1
    def fail(*args, **kwargs):
        raise RuntimeError('synthetic outage')
    monkeypatch.setattr(intelligence_d1_store, 'request_private_intelligence', fail)
    cascade_d1._cache['expires'] = 0
    assert CascadeService.get_route(CONFIG['name']) == saved
    with pytest.raises(APIError) as caught:
        CascadeService.save_route(CONFIG, {'opencode': 'https://synthetic.invalid'})
    assert caught.value.status_code == 503
    cascade_d1.reset_cache()


def test_deadline_fallback_prefers_answer_passing_more_checks(context):
    config = {**CONFIG, 'tiers': [CONFIG['tiers'][0], {'model': 'opencode:middle'}, CONFIG['tiers'][1]],
              'checks': ['complete', 'json']}
    payload = {**PAYLOAD, 'response_format': {'type': 'json_object'}}
    from routes import cascades
    # Calls consume a deterministic clock; the second tier uses the remaining window.
    now = [0.0]
    def clock():
        return now[0]
    def second(body, remaining):
        now[0] = 2.5
        return jsonify(answer('worse partial', 'length'))
    with patch.object(cascades.time, 'monotonic', clock):
        response, calls = run(config, [answer('useful prose'), second], payload, timeout=3)
    assert len(calls) == 2
    assert response.get_json()['choices'][0]['message']['content'] == 'useful prose'
    assert 'tier=1/3' in response.headers['X-MultiLLM-Cascade']
    assert '3:deadline' in response.headers['X-MultiLLM-Cascade']


def test_candidate_deadline_and_allowlist_apply_before_nested_wire_call(context):
    from routes.cascade_deadline import bounded_timeout, check_candidate
    import time
    g.cascade_deadline = time.monotonic() + 0.5
    connect, read = bounded_timeout((5, 120))
    assert 0 < connect + read <= 0.5
    g.authenticated_user = {'allowed_models': ['cascade:test', 'auto:repeat']}
    with pytest.raises(APIError) as caught:
        check_candidate('opencode:disallowed')
    assert caught.value.status_code == 403
    g.cascade_deadline = time.monotonic() - 1
    with pytest.raises(APIError) as caught:
        bounded_timeout((5, 120))
    assert caught.value.status_code == 504


def test_oversized_answer_read_is_bounded_and_preserves_stream(context):
    from routes.cascades import _body, MAX_ANSWER_BYTES
    chunks = [b'x' * MAX_ANSWER_BYTES, b'y', b'z']
    seen = []
    def generate():
        for chunk in chunks:
            seen.append(chunk[-1:])
            yield chunk
    response = Response(generate(), content_type='application/json')
    assert _body(response) is None and seen == [b'x', b'y']
    assert b''.join(response.iter_encoded()) == b''.join(chunks)
    response.close()


def test_explicit_empty_refusal_and_unchecked_tool_shape():
    refused = answer('')
    refused['choices'][0]['message']['refusal'] = 'synthetic refusal'
    assert not local_check('no_refusal', refused, {}, 200)
    assert not local_check('tools', answer(None, calls=[{'function': {'name': 'x', 'arguments': '{}'}}]), {'tools': [{'type': 'bad'}]}, 200)


def test_subrequest_repair_cannot_reask_outside_accounting(context):
    from routes.tool_repair import with_chat_tool_repair
    class App:
        config = {}
    calls = []
    def dispatch(*args, **kwargs):
        calls.append(True)
        return jsonify(answer(None, 'tool_calls', [{'id': 'synthetic', 'type': 'function', 'function': {'name': 'lookup', 'arguments': '{}'}}]))
    g.cascade_deadline = 1
    wrapped = with_chat_tool_repair(dispatch)
    response = wrapped(App(), None, None, None, {**PAYLOAD, 'model': 'opencode:cheap', 'tools': TOOLS}, request_headers={'X-MultiLLM-Tool-Repair': 'reask'})
    assert len(calls) == 1
    assert 'reasked=0' in response.headers['X-MultiLLM-Tool-Repair']


def test_nonfinal_streamed_json_usage_settles_before_next_call(context):
    def streamed(body, remaining):
        assert len(context[1]) == 0
        return Response(iter([json.dumps(answer('partial', 'length'))]), content_type='application/json')
    def final(body, remaining):
        assert len(context[1]) == 1
        assert context[1][0]['input_tokens'] == 3 and context[1][0]['output_tokens'] == 2
        return jsonify(answer('final'))
    response, calls = run(CONFIG, [streamed, final])
    response.close()
    assert len(calls) == len(context[1]) == 2


def test_intelligence_tiers_accept_config_and_preserve_concrete_usage(context, tmp_path, monkeypatch):
    monkeypatch.setenv('INTELLIGENCE_STORAGE_BACKEND', '')
    monkeypatch.setenv('MODEL_REGISTRY_DB_PATH', str(tmp_path / 'models.sqlite3'))
    config = {**CONFIG, 'tiers': [{'model': 'auto:intelligence'}, CONFIG['tiers'][1]]}
    CascadeService.save_route(config, {'opencode': 'https://synthetic.invalid'})
    body = {**answer(), 'multillm': {'selected_model': 'opencode:cheap'}}
    response, calls = run(config, [body])
    assert 'model=opencode:cheap' in response.headers['X-MultiLLM-Cascade']
    assert context[1][0]['selected_model'] == 'opencode:cheap'


def test_intelligence_policy_honors_cascade_deadline_allowlist_and_repair(context):
    from routes import intelligence
    from types import SimpleNamespace
    g.cascade_deadline = 42
    g.authenticated_user = {'username': 'synthetic', 'allowed_models': ['auto:intelligence', 'opencode:cheap']}
    policy = {'enabled': True, 'candidates': [{'model': 'opencode:cheap'}, {'model': 'opencode:forbidden'}], 'max_request_bytes': 4096}
    gateway = SimpleNamespace(deadline=99, tool_repair=SimpleNamespace(mode='reask'), events=lambda: iter([answer()]))
    parsed = SimpleNamespace(payload={'stream': False})
    with patch.object(intelligence, 'load_policy', return_value=policy), patch.object(intelligence.ChatRequest, 'parse', return_value=parsed) as parse, patch.object(intelligence, 'ChatGateway', return_value=gateway), patch.object(intelligence, 'IntelligenceTransport'):
        response = intelligence.dispatch_intelligence_chat(context[0], None, None, None, {**PAYLOAD, 'model': 'auto:intelligence'})
    assert response.status_code == 200
    assert parse.call_args.args[1]['candidates'] == [{'model': 'opencode:cheap'}]
    assert gateway.deadline == 42 and gateway.tool_repair.mode == 'repair'


def test_intelligence_final_stream_receipt_concrete_and_bytes_unchanged(context):
    from routes import intelligence
    from types import SimpleNamespace
    import time
    gateway = SimpleNamespace(emitted=False, selected={'model': 'opencode:cheap'})
    events = [': keep-alive\n\n', 'data: {"model":"opencode:cheap","choices":[]}\n\n', 'data: [DONE]\n\n']
    closed = []
    def generate():
        try:
            yield events[0]
            gateway.emitted = True
            yield events[1]
            yield events[2]
        finally:
            closed.append(True)
    with patch.object(intelligence, 'stream_response', return_value=Response(generate(), content_type='text/event-stream')):
        response = intelligence._cascade_stream(gateway, time.monotonic() + 5)
    assert response.headers['X-MultiLLM-Model'] == 'opencode:cheap'
    assert b''.join(response.iter_encoded()).decode() == ''.join(events)
    response.close()
    assert closed == [True]


def test_final_routed_stream_records_known_model_on_early_close(context):
    events = ['data: {"choices":[{"delta":{"content":"partial"}}]}\n\n']
    config = {**CONFIG, 'tiers': [CONFIG['tiers'][0], {'model': 'auto:intelligence'}]}
    final = Response(iter(events), content_type='text/event-stream', headers={'X-MultiLLM-Model': 'opencode:concrete'})
    response, calls = run(config, [answer(''), final], {**PAYLOAD, 'stream': True})
    next(response.iter_encoded())
    response.close()
    assert len(context[1]) == 2
    assert context[1][-1]['selected_model'] == 'opencode:concrete'
    assert 'model=opencode:concrete' in response.headers['X-MultiLLM-Cascade']


def test_interrupted_nonfinal_body_escalates_and_closes_source(context):
    closed = []
    def interrupted():
        try:
            yield b'{"choices":'
            raise RuntimeError('synthetic private upstream failure')
        finally:
            closed.append(True)
    response, calls = run(CONFIG, [Response(interrupted(), content_type='application/json'), answer('final')])
    assert response.get_json()['choices'][0]['message']['content'] == 'final'
    assert '1:complete' in response.headers['X-MultiLLM-Cascade']
    assert len(calls) == len(context[1]) == 2 and closed == [True]


def test_empty_chunks_cannot_make_verification_loop_unbounded(context):
    from routes.cascades import _body
    seen = []
    def chunks():
        for index in range(10000):
            seen.append(index)
            yield b''
    response = Response(chunks(), content_type='application/json')
    assert _body(response) is None
    assert len(seen) == 4096
    response.close()


@pytest.mark.parametrize('pool', ['free:text', 'free:vision'])
def test_free_tier_storage_roundtrip(pool, tmp_path, monkeypatch):
    monkeypatch.setenv('INTELLIGENCE_STORAGE_BACKEND', '')
    monkeypatch.setenv('MODEL_REGISTRY_DB_PATH', str(tmp_path / 'models.sqlite3'))
    config = {**CONFIG, 'tiers': [{'model': pool}, CONFIG['tiers'][1]]}
    saved = CascadeService.save_route(config, {'opencode': 'https://synthetic.invalid'})
    assert CascadeService.get_route(CONFIG['name']) == saved


@pytest.mark.parametrize('text,expected_calls', [('4', 1), ('', 2)])
def test_free_tier_accounting_receipt_and_health_owner(context, text, expected_calls):
    from services.route_health import RouteHealth
    config = {**CONFIG, 'tiers': [{'model': 'free:text'}, CONFIG['tiers'][1]]}
    free_answer = jsonify(answer(text))
    free_answer.headers['X-MultiLLM-Auto-Selected-Model'] = 'opencode:synthetic-free'
    with patch.object(RouteHealth, 'record') as health:
        response, calls = run(config, [free_answer, answer('final')])
    assert len(calls) == len(context[1]) == expected_calls
    assert context[1][0]['requested_model'] == 'free:text'
    assert context[1][0]['selected_model'] == 'opencode:synthetic-free'
    assert health.call_count == expected_calls - 1
    if expected_calls == 1:
        assert 'model=opencode:synthetic-free' in response.headers['X-MultiLLM-Cascade']
    else:
        assert 'skipped=1:complete' in response.headers['X-MultiLLM-Cascade']
