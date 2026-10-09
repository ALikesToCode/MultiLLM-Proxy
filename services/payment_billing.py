"""Fixed Stripe checkout transport and verified, durable payment evidence."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import requests

from services.enterprise_contract import (PaymentCallback, PaymentEvent, TenantContext, deliver_payment,
                                          register_enterprise_adapters)

logger = logging.getLogger(__name__)
ENDPOINT = "https://api.stripe.com/v1/checkout/sessions"
MAX_BODY = 65536
LEASE_SECONDS = 60
LABEL = re.compile(r"[A-Za-z0-9_:.-]{1,128}\Z")
REF = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
SCHEMA_QUERIES = (
    "SELECT checkout_id,principal,context_json,idempotency_key,body_hash,amount_microusd,currency,status,checkout_url,session_id,payment_intent,merchant,livemode,credited,refunded,revision,claim_token,claim_until,active_event,created_at FROM payment_checkouts LIMIT 0",
    "SELECT event_id,evidence_hash,checkout_id,kind,status,amount,target_amount,operation_id,revision,claim_token,claim_until,created_at FROM payment_events LIMIT 0",
    "SELECT principal,utc_day,attempts FROM payment_velocity LIMIT 0",
    "SELECT id,checkout_id,event_id,outcome,created_at FROM payment_audit LIMIT 0")


class PaymentError(Exception):
    def __init__(self, code="payments_unavailable", status=503):
        super().__init__(code)
        self.code, self.status = code, status


@lru_cache(maxsize=2)
def _warn_once(kind):
    logger.warning("Invalid payment %s; payments disabled", kind)


@dataclass(frozen=True)
class ProcessorConfig:
    secret_key_ref: str
    webhook_key_ref: str
    return_origins: tuple[str, ...]
    product_name: str


def origin(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError("Invalid URL")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or "\\" in url:
        raise ValueError("Invalid URL")
    return f"https://{parsed.hostname.lower()}" + (f":{parsed.port}" if parsed.port not in (None, 443) else "")


def settings(env) -> ProcessorConfig | None:
    raw = env.get("PAYMENTS_ENABLED", "")
    flag = raw.strip().lower() if isinstance(raw, str) else "invalid" if raw is not None else ""
    if flag in {"", "0", "false", "off", "no"}:
        return None
    if flag not in {"1", "true", "on", "yes"}:
        _warn_once("flag")
        return None
    try:
        value = json.loads(env.get("PAYMENT_PROCESSOR_CONFIG_JSON") or "{}")
        webhook = env.get("PAYMENT_WEBHOOK_KEY_REF", "")
        if (type(value) is not dict or set(value) != {"processor", "secret_key_ref", "return_origins", "product_name"}
                or value["processor"] != "stripe" or not isinstance(webhook, str) or not REF.fullmatch(webhook)
                or not isinstance(value["secret_key_ref"], str) or not REF.fullmatch(value["secret_key_ref"])
                or not isinstance(value["product_name"], str) or not 1 <= len(value["product_name"]) <= 128
                or any(ord(c) < 32 for c in value["product_name"])
                or type(value["return_origins"]) is not list or not 1 <= len(value["return_origins"]) <= 16):
            raise ValueError()
        origins = tuple(origin(url) for url in value["return_origins"])
        if any(url != normalized for url, normalized in zip(value["return_origins"], origins)):
            raise ValueError()
        return ProcessorConfig(value["secret_key_ref"], webhook, origins, value["product_name"])
    except (ValueError, TypeError, KeyError):
        _warn_once("configuration")
        return None


def verify_signature(raw: bytes, header: str, secret: str, now: int) -> bool:
    try:
        if not isinstance(raw, bytes) or len(raw) > MAX_BODY or not secret or len(header) > 8192:
            return False
        pieces = [part.strip().split("=", 1) for part in header.split(",")]
        timestamps = [value for key, value in pieces if key == "t"]
        signatures = [value for key, value in pieces if key == "v1"]
        if len(timestamps) != 1 or not re.fullmatch(r"[0-9]{1,12}", timestamps[0]):
            return False
        timestamp = timestamps[0]
        if abs(now - int(timestamp)) > 300:
            return False
        expected = hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
        return any(hmac.compare_digest(expected, candidate) for candidate in signatures
                   if re.fullmatch(r"[0-9a-f]{64}", candidate))
    except (TypeError, ValueError, AttributeError, UnicodeError):
        return False


def owner_permission(context, owner):
    return context.principal_id == owner and context.org_id is None and context.team_id is None


def checked_checkout(body, config):
    if (type(body) is not dict or set(body) != {"amount_microusd", "currency", "idempotency_key", "return_url"}
            or type(body["amount_microusd"]) is not int or not 500000 <= body["amount_microusd"] <= 1000000000
            or body["amount_microusd"] % 10000 or body["currency"] != "USD"
            or not isinstance(body["idempotency_key"], str) or not LABEL.fullmatch(body["idempotency_key"])):
        raise PaymentError("invalid_payment_checkout", 400)
    try:
        if origin(body["return_url"]) not in config.return_origins:
            raise ValueError()
    except (ValueError, TypeError):
        raise PaymentError("invalid_payment_checkout", 400) from None
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def public_checkout(row):
    return {"checkout_id": row["checkout_id"], "url": row["checkout_url"],
            "amount_microusd": row["amount_microusd"], "currency": "USD", "status": "pending"}


def stripe_http(url, *, headers, body):
    """The only processor transport; redirects never receive merchant credentials."""
    if url != ENDPOINT:
        raise PaymentError()
    response = requests.post(ENDPOINT, headers=headers, data=body, timeout=(3, 10), allow_redirects=False)
    if response.status_code != 200:
        raise PaymentError("payment_processor_unavailable", 503)
    return response.json()


class SqlPaymentStore:
    """A migrated SQLite authority; no runtime schema creation or memory fallback."""
    def __init__(self, path):
        self.path = path

    @contextmanager
    def transaction(self):
        db = None
        try:
            db = sqlite3.connect(Path(self.path).resolve().as_uri() + "?mode=rw", uri=True, timeout=10)
            db.row_factory = sqlite3.Row
            for query in SCHEMA_QUERIES:
                db.execute(query)
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except sqlite3.Error:
            if db is not None:
                db.rollback()
            raise PaymentError() from None
        finally:
            if db is not None:
                db.close()

    def call(self, operation, **data):
        with self.transaction() as db:
            handler = getattr(self, "_" + operation, None)
            if operation not in {"reserve", "save", "find", "claim", "finish"} or handler is None:
                raise PaymentError("invalid_payment_operation", 400)
            return handler(db, **data)

    def _reserve(self, db, *, context, body_hash, idempotency_key, checkout_id, amount, now, token):
        scope = json.dumps(context, sort_keys=True, separators=(",", ":"))
        row = db.execute("SELECT * FROM payment_checkouts WHERE principal=? AND context_json=? AND idempotency_key=?",
                         (context["principal_id"], scope, idempotency_key)).fetchone()
        if row:
            if row["body_hash"] != body_hash:
                raise PaymentError("payment_idempotency_conflict", 409)
            if not row["checkout_url"] and row["claim_until"] <= now:
                db.execute("UPDATE payment_checkouts SET claim_token=?,claim_until=? WHERE checkout_id=?",
                           (token, now + LEASE_SECONDS, row["checkout_id"]))
        else:
            day = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
            db.execute("INSERT INTO payment_velocity VALUES (?,?,0) ON CONFLICT DO NOTHING", (context["principal_id"], day))
            changed = db.execute("UPDATE payment_velocity SET attempts=attempts+1 WHERE principal=? AND utc_day=? AND attempts<10",
                                 (context["principal_id"], day)).rowcount
            if not changed:
                raise PaymentError("payment_velocity_limited", 429)
            db.execute("INSERT INTO payment_checkouts (checkout_id,principal,context_json,idempotency_key,body_hash,amount_microusd,currency,claim_token,claim_until,created_at) VALUES (?,?,?,?,?,?,'USD',?,?,?)",
                       (checkout_id, context["principal_id"], scope, idempotency_key, body_hash, amount, token, now+LEASE_SECONDS, now))
            db.execute("INSERT INTO payment_audit (checkout_id,outcome,created_at) VALUES (?,'created',?)", (checkout_id, now))
        row = db.execute("SELECT * FROM payment_checkouts WHERE principal=? AND context_json=? AND idempotency_key=?",
                         (context["principal_id"], scope, idempotency_key)).fetchone()
        return dict(row)

    def _save(self, db, *, checkout_id, token, session_id=None, url=None, livemode=None, merchant=None):
        if session_id is None:
            db.execute("UPDATE payment_checkouts SET claim_until=0 WHERE checkout_id=? AND claim_token=?", (checkout_id, token))
        else:
            changed = db.execute("UPDATE payment_checkouts SET session_id=?,checkout_url=?,livemode=?,merchant=?,status='pending',claim_until=0,claim_token=NULL WHERE checkout_id=? AND claim_token=?",
                                 (session_id, url, int(livemode), merchant, checkout_id, token)).rowcount
            if not changed:
                raise PaymentError("payment_checkout_processing", 503)
        return None

    def _find(self, db, *, checkout_id=None, payment_intent=None):
        row = db.execute("SELECT * FROM payment_checkouts WHERE checkout_id=?" if checkout_id else
                         "SELECT * FROM payment_checkouts WHERE payment_intent=?", (checkout_id or payment_intent,)).fetchone()
        return dict(row) if row else None

    def _claim(self, db, *, event_id, evidence_hash, checkout_id, kind, status, amount, target_amount,
               operation_id, payment_intent, now, token):
        existing = db.execute("SELECT * FROM payment_events WHERE event_id=?", (event_id,)).fetchone()
        if existing:
            if existing["evidence_hash"] != evidence_hash:
                raise PaymentError("payment_event_conflict", 400)
            if existing["status"] not in {"processing", "pending_credit", "pending_match"}:
                return {**dict(existing), "claimed": False}
            if existing["status"] == "pending_match":
                if status == "pending_match":
                    return {**dict(existing), "claimed": False}
                existing = None
            if existing and existing["claim_until"] > now:
                raise PaymentError("payment_credit_unavailable", 503)
        row = db.execute("SELECT * FROM payment_checkouts WHERE checkout_id=?", (checkout_id,)).fetchone()
        if status == "processing" and row:
            if row["active_event"] and row["active_event"] != event_id:
                active = db.execute("SELECT claim_until FROM payment_events WHERE event_id=?", (row["active_event"],)).fetchone()
                # Retry the original event first, preserving its immutable callback.
                if active:
                    raise PaymentError("payment_credit_unavailable", 503)
            if not existing:
                prior = db.execute("SELECT status FROM payment_events WHERE operation_id=? AND status IN ('credited','refunded','disputed') LIMIT 1",
                                   (operation_id,)).fetchone()
                if prior or (kind == "credit" and row["credited"]):
                    status = "ignored"
                if kind != "credit" and not row["credited"]:
                    raise PaymentError("payment_credit_unavailable", 503)
                if kind == "refund":
                    amount = max(0, target_amount - row["refunded"])
                    if amount == 0:
                        status = "ignored"
        revision = existing["revision"] if existing else row["revision"] if row else 0
        if not existing:
            db.execute("INSERT INTO payment_events (event_id,evidence_hash,checkout_id,kind,status,amount,target_amount,operation_id,revision,claim_token,claim_until,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET checkout_id=excluded.checkout_id,kind=excluded.kind,status=excluded.status,amount=excluded.amount,target_amount=excluded.target_amount,operation_id=excluded.operation_id,revision=excluded.revision,claim_token=excluded.claim_token,claim_until=excluded.claim_until WHERE payment_events.status='pending_match' AND payment_events.evidence_hash=excluded.evidence_hash",
                       (event_id, evidence_hash, checkout_id, kind, status, amount, target_amount, operation_id, revision,
                        token, now+LEASE_SECONDS if status == "processing" else 0, now))
            db.execute("INSERT INTO payment_audit (checkout_id,event_id,outcome,created_at) VALUES (?,?,?,?)",
                       (checkout_id, event_id, status, now))
        else:
            db.execute("UPDATE payment_events SET status='processing',claim_token=?,claim_until=? WHERE event_id=?", (token, now+LEASE_SECONDS, event_id))
        if status == "processing":
            db.execute("UPDATE payment_checkouts SET active_event=?,payment_intent=COALESCE(payment_intent,?) WHERE checkout_id=?",
                       (event_id, payment_intent, checkout_id))
        elif status == "failed" and row and not row["credited"]:
            db.execute("UPDATE payment_checkouts SET status='failed' WHERE checkout_id=?", (checkout_id,))
        result = dict(db.execute("SELECT * FROM payment_events WHERE event_id=?", (event_id,)).fetchone())
        return {**result, "claimed": status == "processing"}

    def _finish(self, db, *, event_id, token, status, now):
        row = db.execute("SELECT * FROM payment_events WHERE event_id=? AND claim_token=? AND status='processing'", (event_id, token)).fetchone()
        if not row:
            raise PaymentError("payment_credit_unavailable", 503)
        if status != "pending_credit" and status != {"credit": "credited", "refund": "refunded", "dispute": "disputed"}[row["kind"]]:
            raise PaymentError("invalid_payment_operation", 400)
        db.execute("UPDATE payment_events SET status=?,claim_until=0 WHERE event_id=?", (status, event_id))
        if status != "pending_credit":
            db.execute("UPDATE payment_checkouts SET active_event=NULL,revision=revision+1,credited=CASE WHEN ?='credit' THEN 1 ELSE credited END,refunded=CASE WHEN ?='refund' THEN ? ELSE refunded END,status=? WHERE checkout_id=? AND active_event=?",
                       (row["kind"], row["kind"], row["target_amount"], status, row["checkout_id"], event_id))
        db.execute("INSERT INTO payment_audit (checkout_id,event_id,outcome,created_at) VALUES (?,?,?,?)", (row["checkout_id"], event_id, status, now))
        return None


class D1PaymentStore:
    """Injected private transport returns the same fixed domain operations as SQL."""
    def __init__(self, transport):
        self.transport = transport

    def call(self, operation, **data):
        try:
            reply = self.transport({"version": 1, "operation": operation, **data})
            if not isinstance(reply, dict) or set(reply) != {"version", "result"} or reply["version"] != 1:
                raise PaymentError()
            return reply["result"]
        except PaymentError:
            raise
        except Exception:
            raise PaymentError() from None


class PaymentBilling:
    def __init__(self, *, env=None, store=None, http=None, secret_resolver=None, callback: PaymentCallback | None = None,
                 permission=owner_permission, clock=time.time):
        # Configuration and secret access are supplied by the host, never file reads.
        import os
        self.env = os.environ if env is None else env
        self.store, self.http, self.callback = store, http or stripe_http, callback
        self.secret_resolver = secret_resolver or self.env.get
        self.permission, self.clock = permission, clock
        self.lock = threading.RLock()

    def config(self):
        config = settings(self.env)
        if config is None:
            raise PaymentError("not_found", 404)
        return config

    def state(self, operation, **values):
        if self.store is None:
            raise PaymentError()
        return self.store.call(operation, **values)

    def checkout(self, context, owner, body):
        config = self.config()
        try:
            allowed = type(context) is TenantContext and self.permission(context, owner) is True
        except Exception:
            raise PaymentError("payment_permission_unavailable", 503) from None
        if not allowed:
            raise PaymentError("payment_permission_denied", 403)
        body_hash = checked_checkout(body, config)
        with self.lock:
            token, now = uuid.uuid4().hex, int(self.clock())
            row = self.state("reserve", context=asdict(context), body_hash=body_hash,
                             idempotency_key=body["idempotency_key"], checkout_id="pay_"+uuid.uuid4().hex,
                             amount=body["amount_microusd"], now=now, token=token)
            if row["checkout_url"]:
                return public_checkout(row)
            if row["claim_token"] != token:
                raise PaymentError("payment_checkout_processing", 503)
            try:
                session = self.create_session(config, row, body)
                self.state("save", checkout_id=row["checkout_id"], token=token, session_id=session["id"],
                           url=session["url"], livemode=session["livemode"], merchant="direct")
            except Exception:
                self.state("save", checkout_id=row["checkout_id"], token=token)
                raise PaymentError("payment_processor_unavailable", 503) from None
            return public_checkout({**row, "checkout_url": session["url"]})

    def create_session(self, config, row, body):
        secret = self.secret_resolver(config.secret_key_ref)
        if not secret or self.http is None:
            raise PaymentError()
        form = {"mode": "payment", "line_items[0][price_data][currency]": "usd",
                "line_items[0][price_data][unit_amount]": str(row["amount_microusd"] // 10000),
                "line_items[0][price_data][product_data][name]": config.product_name,
                "line_items[0][quantity]": "1", "success_url": body["return_url"], "cancel_url": body["return_url"],
                "client_reference_id": row["checkout_id"], "metadata[checkout_id]": row["checkout_id"]}
        session = self.http(ENDPOINT, headers={"Authorization": "Bearer " + secret,
                           "Content-Type": "application/x-www-form-urlencoded", "Idempotency-Key": row["checkout_id"]}, body=urlencode(form))
        if (type(session) is not dict or session.get("object") != "checkout.session"
                or not isinstance(session.get("id"), str) or not LABEL.fullmatch(session["id"])
                or type(session.get("amount_total")) is not int or session["amount_total"]*10000 != row["amount_microusd"]
                or session.get("currency") != "usd" or type(session.get("livemode")) is not bool
                or origin(session.get("url")) != "https://checkout.stripe.com"):
            raise PaymentError()
        return session

    def webhook(self, raw, signature):
        config = self.config()
        try:
            secret = self.secret_resolver(config.webhook_key_ref)
        except Exception:
            raise PaymentError() from None
        if not secret:
            raise PaymentError()
        now = int(self.clock())
        if not verify_signature(raw, signature, secret, now):
            raise PaymentError("invalid_payment_signature", 400)
        try:
            value = json.loads(raw)
            if type(value) is not dict or value.get("object") != "event" or not LABEL.fullmatch(value.get("id", "")):
                raise ValueError()
            evidence_hash = hashlib.sha256(raw).hexdigest()
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise PaymentError("invalid_payment_event", 400) from None
        with self.lock:
            row, decision = self.classify(value)
            token = uuid.uuid4().hex
            claimed = self.state("claim", event_id=value["id"], evidence_hash=evidence_hash,
                                 checkout_id=row["checkout_id"] if row else None, now=now, token=token, **decision)
            if not claimed["claimed"]:
                if claimed["status"] == "pending_match":
                    raise PaymentError("payment_credit_unavailable", 503)
                return {"received": True, "status": claimed["status"]}
            event = PaymentEvent(TenantContext(**json.loads(row["context_json"])), row["checkout_id"], claimed["revision"],
                                 claimed["operation_id"], "stripe", value["id"], claimed["kind"], "USD", claimed["amount"], True)
            try:
                deliver_payment(register_enterprise_adapters(payment=self.callback), event)
            except Exception:
                self.state("finish", event_id=value["id"], token=token, status="pending_credit", now=now)
                raise PaymentError("payment_credit_unavailable", 503) from None
            status = {"credit": "credited", "refund": "refunded", "dispute": "disputed"}[event.kind]
            self.state("finish", event_id=value["id"], token=token, status=status, now=now)
            return {"received": True, "status": status}

    def classify(self, value):
        kind = value.get("type")
        decision = {"kind": "ignored", "status": "ignored", "amount": 0, "target_amount": 0,
                    "operation_id": None, "payment_intent": None}
        kinds = {"checkout.session.completed": "credit", "checkout.session.async_payment_succeeded": "credit",
                 "checkout.session.async_payment_failed": "failed", "charge.refunded": "refund", "charge.dispute.created": "dispute"}
        if not isinstance(kind, str) or kind not in kinds:
            return None, decision
        obj = value.get("data", {}).get("object", {}) if type(value.get("data")) is dict else {}
        if type(obj) is not dict:
            return None, {**decision, "status": "mismatch"}
        session = kind.startswith("checkout.session.")
        checkout_id = obj.get("client_reference_id") if session else None
        intent = obj.get("payment_intent")
        if not isinstance(intent, str) or not LABEL.fullmatch(intent):
            intent = None
        if (session and (not isinstance(checkout_id, str) or not LABEL.fullmatch(checkout_id))) or (not session and intent is None):
            return None, {**decision, "status": "mismatch"}
        row = self.state("find", checkout_id=checkout_id, payment_intent=intent)
        if row is None and not session:
            return None, {**decision, "status": "pending_match"}
        amount = obj.get("amount_total") if session else obj.get("amount")
        metadata = obj.get("metadata", {})
        mismatch = (row is None or obj.get("currency") != "usd" or type(amount) is not int
                    or type(value.get("livemode")) is not bool or value["livemode"] != bool(row["livemode"])
                    or type(obj.get("livemode")) is not bool or obj["livemode"] != bool(row["livemode"])
                    or (value.get("account") or "direct") != row["merchant"])
        if not mismatch and session:
            mismatch = (amount*10000 != row["amount_microusd"] or obj.get("id") != row["session_id"]
                        or type(metadata) is not dict or metadata.get("checkout_id") != checkout_id
                        or (row["payment_intent"] is not None and intent != row["payment_intent"]))
        if not mismatch and not session:
            mismatch = (amount <= 0 or amount*10000 > row["amount_microusd"]
                        or (kind == "charge.refunded" and amount*10000 != row["amount_microusd"]))
        if mismatch:
            return row, {**decision, "status": "mismatch"}
        mapped = kinds[kind]
        if kind == "checkout.session.completed" and obj.get("payment_status") != "paid":
            return row, decision
        if mapped == "failed":
            return row, {**decision, "status": "failed"}
        target = 0
        if mapped == "refund":
            target = obj.get("amount_refunded")
            if type(target) is not int or not 0 < target <= amount:
                return row, {**decision, "status": "mismatch"}
            target *= 10000
        object_id = obj.get("id")
        if mapped == "dispute" and (not isinstance(object_id, str) or not LABEL.fullmatch(object_id)):
            return row, {**decision, "status": "mismatch"}
        operation = f"credit:{row['checkout_id']}" if mapped == "credit" else f"refund:{row['checkout_id']}:{target}" if mapped == "refund" else "dispute:" + hashlib.sha256(object_id.encode()).hexdigest()
        return row, {"kind": mapped, "status": "processing", "amount": amount*10000,
                     "target_amount": target, "operation_id": operation, "payment_intent": intent}
