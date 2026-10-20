"""Offline cost breaker fixtures."""
import json
import sqlite3
from pathlib import Path
import pytest
from flask import Flask, Response, g
from error_handlers import APIError
from services import stream_cost_breaker as breaker, request_accounting as accounting, key_controls
from services.upstream_transport import iter_stream_content

@pytest.fixture(autouse=True)
def settings(monkeypatch):
    for name, value in {"STREAM_COST_BREAKER_ENABLED":"true",
        "MODEL_PRICING_USD_PER_MILLION":json.dumps({"openai:m":{"input":1,"cache_read":0.25,"cache_write":2,"output":1}}),
        "PROMPT_CACHE_PRICE_METADATA_JSON":"{}", "PROMPT_CACHE_USAGE_BUCKETS_ENABLED":"false",
        "USAGE_RESERVATIONS_ENABLED":"false","AUTH_STORAGE_BACKEND":"sql",
        "CONTROL_PLANE_DATABASE_URL":"","CONFIG_REVISION_SYNC_ENABLED":"false"}.items():
        monkeypatch.setenv(name,value)

def frame(value):
    return ("data: "+json.dumps(value,ensure_ascii=False)+"\n\n").encode()
def delta(text):
    return frame({"choices":[{"delta":{"content":text}}]})
class Source:
    def __init__(self,chunks):
        self.chunks=iter(chunks)
        self.closes=self.reads=0
    def __iter__(self): return self
    def __next__(self):
        self.reads+=1
        return next(self.chunks)
    def close(self): self.closes+=1

@pytest.mark.parametrize("flag",["","false","private-invalid-value"])
def test_defaults(monkeypatch,caplog,flag):
    monkeypatch.setenv("STREAM_COST_BREAKER_ENABLED",flag)
    breaker._warned.clear()
    source=Source([b"\xff",b"data: malformed\n",b"\n"])
    assert breaker.wrap_stream(source,None) is source
    assert "max_stream_cost_usd" not in key_controls.public({})
    assert not breaker.enabled() and not breaker.enabled()
    assert "private-invalid-value" not in caplog.text
    assert len(caplog.records)==(1 if flag.startswith("private") else 0)

@pytest.mark.parametrize("protocol,marker",[("chat",b'data: {"error"'),("anthropic",b"event: error"),("responses",b"event: response.failed")])
def test_crossing(protocol,marker):
    state=breaker.prepare({"max_stream_cost_microusd":4},["openai:m"],0,protocol)
    source=Source([delta("four"),delta("secret"),b"data: [DONE]\n\n"])
    wrapped=breaker.wrap_stream(source,state)
    chunks=list(wrapped)
    wrapped.close()
    assert chunks[0]==delta("four")
    assert marker in chunks[1] and b"stream_cost_cap_exceeded" in chunks[1]
    assert b"[DONE]" not in b"".join(chunks) and b"finish_reason" not in chunks[1]
    assert source.closes==1 and source.reads==2 and state.exceeded

def test_unicode_and_crlf():
    data=delta("ह").replace(b"\n",b"\r\n")+b"data: [DONE]\r\n\r\n"
    state=breaker.prepare({"max_stream_cost_microusd":3},["openai:m"],0,"chat")
    assert b"".join(breaker.wrap_stream(Source([data[i:i+1] for i in range(len(data))]),state))==data
    assert state.running_microusd==3

def test_cache_and_unknown_final():
    state=breaker.prepare({"max_stream_cost_microusd":100},["openai:m"],0,"anthropic")
    data=frame({"type":"message","usage":{"input_tokens":4,"cache_read_input_tokens":8,"cache_creation_input_tokens":2,"output_tokens":1}})
    list(breaker.wrap_stream(Source([data,frame({"type":"message_stop"})]),state))
    assert state.basis=="measured" and state.running_microusd==11 and state.final_usage is not None
    unknown=breaker.prepare({"max_stream_cost_microusd":100},["openai:m"],3,"chat")
    list(breaker.wrap_stream(Source([delta("x"),b"data: [DONE]\n\n"]),unknown))
    assert unknown.final_usage is None and unknown.basis=="conservative_estimate"

def test_preflight():
    with pytest.raises(APIError) as error:
        breaker.prepare({"max_stream_cost_microusd":20},["openai:m","missing"],0,"chat")
    assert error.value.status_code==503 and error.value.payload["error"]=="stream_cost_unpriced"
    with pytest.raises(APIError) as error:
        breaker.prepare({"max_stream_cost_microusd":1},["openai:m"],2,"chat")
    assert error.value.payload["error"]=="stream_cost_cap_exceeded"

@pytest.mark.parametrize("value",[True,-1,"nan","inf",0.0000001,{},1000000001])
def test_invalid_cap(value):
    with pytest.raises(APIError): key_controls.validate({"max_stream_cost_usd":value})

def test_cap_and_old_key_migration():
    assert key_controls.validate({"max_stream_cost_usd":"0.000012"})["max_stream_cost_microusd"]==12
    assert key_controls.public({"max_stream_cost_microusd":12})["max_stream_cost_usd"]==0.000012
    assert "max_stream_cost_usd" not in key_controls.public({"max_stream_cost_microusd":None})
    db=sqlite3.connect(":memory:")
    db.execute("CREATE TABLE control_users (username TEXT PRIMARY KEY)")
    db.execute("INSERT INTO control_users VALUES (?)",("old",))
    db.executescript(Path("intelligence-migrations/0030_stream_cost_caps.sql").read_text())
    assert db.execute("SELECT max_stream_cost_microusd FROM control_users").fetchone()==(None,)

def test_accounting_path(monkeypatch):
    app=Flask(__name__)
    rows=[]
    monkeypatch.setattr(accounting.usage_ledger.LEDGER,"record",rows.append)
    monkeypatch.setattr(accounting.telemetry_export.EXPORTER,"submit",lambda row:None)
    monkeypatch.setattr(accounting.BudgetService,"record_cost",lambda row:None)
    monkeypatch.setattr(accounting.BudgetService,"settle",lambda *a,**k:None)
    class Upstream(Source):
        headers={"content-type":"text/event-stream"}
        status_code=200
        def iter_content(self,chunk_size): yield from self
    upstream=Upstream([delta("ok"),delta("secret-response"),b"data: [DONE]\n\n"])
    @app.post("/v1/chat/completions")
    def chat():
        g.authenticated_user={"username":"reader","max_stream_cost_usd":0.000003}
        g.rate_limit={"input_tokens":0,"output_tokens":50}
        denied=accounting.begin()
        if denied is not None: return denied
        return accounting.finish(Response(iter_stream_content(upstream),mimetype="text/event-stream"))
    with app.test_client() as client:
        response=client.post("/v1/chat/completions",json={"model":"openai:m","stream":True})
        data=response.get_data()
        response.close()
    assert b"stream_cost_cap_exceeded" in data and b"secret-response" not in data and b"[DONE]" not in data
    assert upstream.closes==1 and len(rows)==1 and rows[0]["status"]==499 and rows[0]["cost_usd"] is None
    with app.test_request_context("/v1/chat/completions",method="POST",json={"model":"missing","stream":True}):
        g.authenticated_user={"username":"reader","max_stream_cost_usd":0.000003}
        denied=accounting.begin()
        assert denied.status_code==503 and denied.get_json()["error"]=="stream_cost_unpriced"

def test_trailing_measured_overrun_never_emits_success_finish():
    state=breaker.prepare({"max_stream_cost_microusd":4},["openai:m"],0,"chat")
    stop=frame({"choices":[{"delta":{},"finish_reason":"stop"}]})
    usage=frame({"usage":{"prompt_tokens":0,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens":5}})
    data=b"".join(breaker.wrap_stream(Source([delta("four"),stop,usage,b"data: [DONE]\n\n"]),state))
    assert b"stream_cost_cap_exceeded" in data and b"finish_reason" not in data and b"[DONE]" not in data
    assert state.final_usage is not None and state.final_usage.output_tokens==5

def test_multiline_and_oversized_frames():
    value=b'data: {"choices":\n' + b'data: [{"delta":{"content":"ok"}}]}\n\n'
    state=breaker.prepare({"max_stream_cost_microusd":2},["openai:m"],0,"chat")
    assert b"".join(breaker.wrap_stream(Source([value]),state))==value
    state=breaker.prepare({"max_stream_cost_microusd":100000},["openai:m"],0,"chat")
    source=Source([b"data: "+b"x"*breaker.FRAME_LIMIT])
    result=b"".join(breaker.wrap_stream(source,state))
    assert b"stream_cost_cap_exceeded" in result and source.closes==1

def test_cancel_before_read_and_concurrent_state_isolation():
    state=breaker.prepare({"max_stream_cost_microusd":2},["openai:m"],0,"chat")
    source=Source([delta("x")])
    body=breaker.wrap_stream(source,state)
    body.close(); body.close()
    assert source.closes==1 and source.reads==0
    other=breaker.prepare({"max_stream_cost_microusd":2},["openai:m"],0,"chat")
    assert b"".join(breaker.wrap_stream(Source([delta("ok")]),other))==delta("ok")
    assert state.output_bound==0 and other.output_bound==2

def test_sql_accounts_keep_cap_through_updates_rotation_and_disabled_writes(tmp_path,monkeypatch):
    from unittest.mock import patch
    from services.auth_service import AuthService
    monkeypatch.setenv("AUTH_DB_PATH",str(tmp_path/"auth.sqlite3"))
    monkeypatch.setenv("ADMIN_API_KEY","synthetic-stream-cost-admin")
    monkeypatch.setenv("ADMIN_USERNAME","admin")
    for name,value in (("_storage_path",None),("_users",{}),("_api_key_prefix_index",{}),("_verified_keys",{})):
        monkeypatch.setattr(AuthService,name,value)
    AuthService.initialize()
    with patch.object(AuthService,"get_current_user",return_value={"username":"admin","is_admin":True}):
        AuthService.create_user("reader",scopes=["chat"])
        AuthService.set_key_controls("reader",{"max_stream_cost_usd":"0.000004"})
        AuthService.set_key_controls("reader",{"allowed_models":["openai:*"]})
        key=AuthService.rotate_api_key("reader")["api_key"]
        verified=AuthService.verify_api_key(key)
        assert verified["max_stream_cost_usd"]==0.000004
        with Flask(__name__).test_request_context("/v1/chat/completions",method="POST",
                json={"model":"openai:missing","stream":True}):
            g.authenticated_user=verified
            denied=accounting.begin()
            assert denied.status_code==503 and denied.get_json()["error"]=="stream_cost_unpriced"
        monkeypatch.setenv("STREAM_COST_BREAKER_ENABLED","false")
        AuthService.rotate_api_key("reader")
        monkeypatch.setenv("STREAM_COST_BREAKER_ENABLED","true")
        assert AuthService._load_user_by_username("reader")["max_stream_cost_microusd"]==4
        AuthService.set_key_controls("reader",{"max_stream_cost_usd":None})
        assert "max_stream_cost_usd" not in AuthService._public_user("reader",AuthService._users["reader"])

def test_strict_d1_rows_missing_schema_and_off_wire(monkeypatch):
    from services import user_store
    row={name:None for name in user_store.USER_FIELDS}
    row.update(username="reader",api_key_hash="synthetic-hash",api_key_prefix="synthetic-prefix",
        scopes="chat",is_admin=0,created_at="2026-10-09T00:00:00Z")
    monkeypatch.setattr(user_store,"_call",lambda *a,**k:{"user":row})
    with pytest.raises(APIError) as error: breaker.get_user("reader")
    assert error.value.status_code==503 and error.value.payload["error"]=="stream_cost_storage_unavailable"
    row["max_stream_cost_microusd"]=4
    assert breaker.get_user("reader")["max_stream_cost_microusd"]==4
    row["unknown"]=None
    with pytest.raises(APIError): breaker.get_user("reader")
    row.pop("unknown"); row.pop("max_stream_cost_microusd")
    monkeypatch.setenv("STREAM_COST_BREAKER_ENABLED","false")
    captured=[]
    monkeypatch.setattr(user_store,"upsert_user",captured.append)
    breaker.upsert_user(row)
    assert captured==[row]

def test_real_durable_unknown_hold(monkeypatch,tmp_path):
    from services import reservation_store
    from services.budget_service import BudgetService
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED","true")
    monkeypatch.setenv("USAGE_HOLD_REVIEW_AFTER_SECONDS","")
    store=reservation_store.SqlReservationStore(str(tmp_path/"holds.sqlite3"))
    monkeypatch.setattr(reservation_store,"get_store",lambda:store)
    identity="a"*32
    store.reserve(identity,"reader",0.001,1,None,0,0)
    BudgetService.mark_dispatched(identity)
    state=breaker.prepare({"max_stream_cost_microusd":4},["openai:m"],0,"chat")
    list(breaker.wrap_stream(Source([delta("four"),delta("over")]),state))
    context=accounting.UsageContext("chat",["openai:m"],None,{"username":"reader"},
        accounting.time.perf_counter(),1,reservation=identity,path="/v1/chat/completions",trace=(None,None),stream_cost=state)
    monkeypatch.setattr(accounting.usage_ledger.LEDGER,"record",lambda row:None)
    monkeypatch.setattr(accounting.telemetry_export.EXPORTER,"submit",lambda row:None)
    accounting._record(context,499,None,None)
    assert store.get(identity)["state"]=="unknown"
    assert store.summary("reader")["held_usd"]==0.001

def test_cached_stream_keeps_zero_charge_and_releases_hold(monkeypatch):
    app=Flask(__name__)
    rows,settled=[],[]
    monkeypatch.setattr(accounting.usage_ledger.LEDGER,"record",rows.append)
    monkeypatch.setattr(accounting.telemetry_export.EXPORTER,"submit",lambda row:None)
    monkeypatch.setattr(accounting.BudgetService,"record_cost",lambda row:None)
    monkeypatch.setattr(accounting.BudgetService,"settle",lambda identity,**kwargs:settled.append(identity))
    with app.test_request_context("/v1/chat/completions",method="POST"):
        g.usage_context=accounting.UsageContext("chat",["openai:m"],None,{"username":"reader"},
            accounting.time.perf_counter(),1,reservation="cached",trace=(None,None),
            stream_cost=breaker.prepare({"max_stream_cost_microusd":0},["openai:m"],0,"chat"))
        original=delta("cached")+b"data: [DONE]\n\n"
        response=accounting.finish(Response(iter([original]),mimetype="text/event-stream",
            headers={"X-MultiLLM-Cache":"hit"}))
        assert b"".join(response.response)==original
        response.close()
    assert rows[0]["cost_usd"]==0 and rows[0]["status"]==200 and rows[0]["cost_basis"]=="cache"
    assert settled==["cached"]

def test_fractional_prices_do_not_create_a_rounding_fee(monkeypatch):
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION",json.dumps({"openai:m":{
        "input":0.1,"cache_read":0.1,"cache_write":0.1,"output":0.1}}))
    state=breaker.prepare({"max_stream_cost_microusd":0},["openai:m"],0,"chat")
    assert state.running_microusd==0
