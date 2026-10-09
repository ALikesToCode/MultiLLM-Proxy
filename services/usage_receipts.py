"""Opt-in, immutable Ed25519 evidence for content-free usage metadata."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import re
from contextlib import closing
from decimal import Decimal
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from services import intelligence_d1_store, usage_store
from services.sqlite_store import connect

logger = logging.getLogger(__name__)
DOMAIN = b"MultiLLM usage receipt v1\\n"
MAX_BYTES = 65536
MAX_INTEGER = 2**53 - 1
_LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_REF = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_CONTENT_FIELDS = frozenset({"prompt", "messages", "content", "input", "output", "response", "api_key",
                             "authorization", "password", "secret", "private_key", "signing_key"})


class ReceiptError(Exception):
    def __init__(self, code="usage_receipts_unavailable", status=503):
        super().__init__(code)
        self.code, self.status = code, status


@lru_cache(maxsize=1)
def _warn_invalid_flag():
    logger.warning("Invalid USAGE_RECEIPTS_ENABLED; usage receipts disabled")


def enabled() -> bool:
    flag = os.environ.get("USAGE_RECEIPTS_ENABLED", "").strip().lower()
    if flag not in {"", "0", "false", "no", "off", "1", "true", "yes", "on"}:
        _warn_invalid_flag()
        return False
    return flag in {"1", "true", "yes", "on"}


def canonical_bytes(value) -> bytes:
    """Exact finite IEEE-754 decimals, scalar Unicode keys in codepoint order.

    Unlike runtime-specific shortest-number printers, exact decimal expansion is
    identical in Python and WebCrypto callers. Integer values must be JS-safe.
    """
    nodes, scalar_bytes = 0, 0
    def scalar(text):
        nonlocal scalar_bytes
        scalar_bytes += len(text.encode("utf-8"))
        if scalar_bytes > MAX_BYTES:
            raise ValueError()
        return text
    def encode(item, depth=0):
        nonlocal nodes
        nodes += 1
        if depth > 32 or nodes > 4096:
            raise ValueError()
        if item is None or type(item) is bool:
            return scalar(json.dumps(item))
        if type(item) in (int, float):
            if not math.isfinite(item) or (item == int(item) and abs(item) > MAX_INTEGER):
                raise ValueError()
            if item == 0:
                return scalar("0")
            if type(item) is int:
                return scalar(str(item))
            text = format(Decimal.from_float(item), "f").rstrip("0").rstrip(".") if not item.is_integer() else str(int(item))
            return scalar(text)
        if type(item) is str:
            if len(item) > MAX_BYTES or any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise ValueError()
            return scalar(json.dumps(item, ensure_ascii=False))
        if type(item) is list:
            return "[" + ",".join(encode(child, depth + 1) for child in item) + "]"
        if type(item) is dict and all(type(key) is str for key in item):
            return "{" + ",".join(encode(key, depth + 1) + ":" + encode(item[key], depth + 1)
                                   for key in sorted(item)) + "}"
        raise ValueError()
    try:
        result = encode(value).encode("utf-8")
        if len(result) > MAX_BYTES:
            raise ValueError()
        return result
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError):
        raise ReceiptError("invalid_usage_receipt", 400) from None


def _identifier(value):
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ReceiptError("invalid_usage_receipt", 400)
    return value


def _principal(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ReceiptError("invalid_usage_receipt", 400)
    canonical_bytes(value)
    return value


def checked_record(record):
    if type(record) is not dict:
        raise ReceiptError("invalid_usage_receipt", 400)
    def check(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str) or key.lower() in _CONTENT_FIELDS:
                    raise ReceiptError("invalid_usage_receipt", 400)
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    encoded = canonical_bytes(record)
    check(record)
    return json.loads(encoded)


def _signer():
    if not enabled():
        raise ReceiptError("not_found", 404)
    key_id = os.environ.get("USAGE_RECEIPTS_KEY_ID", "")
    reference = os.environ.get("USAGE_RECEIPTS_SIGNING_KEY_REF", "")
    try:
        if not _LABEL.fullmatch(key_id) or not _REF.fullmatch(reference):
            raise ValueError()
        material = os.environ.get(reference, "")
        if not material or len(material) > 8192:
            raise ValueError()
        private = serialization.load_der_private_key(base64.b64decode(material, validate=True), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError()
        public = base64.b64encode(private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        return key_id, private, public
    except Exception:
        raise ReceiptError() from None


def make_receipt(principal, event_id, record, sequence, previous_hash, signer):
    key_id, private, _ = signer
    payload = {"version": 1, "principal": principal, "event_id": event_id, "record": record,
               "sequence": sequence, "previous_hash": previous_hash, "key_id": key_id}
    canonical = canonical_bytes(payload)
    signed = DOMAIN + canonical
    return {"record": record, "canonical_bytes_base64": base64.b64encode(canonical).decode("ascii"),
            "signature_ed25519": base64.b64encode(private.sign(signed)).decode("ascii"),
            "key_id": key_id, "previous_hash": previous_hash,
            "record_hash": hashlib.sha256(signed).hexdigest(), "sequence": sequence}


def verify_chain(receipts, public_keys, *, principal, sequence=0, previous_hash=None) -> bool:
    """A suffix needs an independently trusted starting sequence and hash."""
    try:
        for receipt in receipts:
            canonical = base64.b64decode(receipt["canonical_bytes_base64"], validate=True)
            payload = json.loads(canonical)
            if (canonical != canonical_bytes(payload) or payload["version"] != 1
                    or payload["principal"] != principal or payload["sequence"] != sequence + 1
                    or payload["previous_hash"] != previous_hash
                    or any(canonical_bytes(payload[name]) != canonical_bytes(receipt[name])
                           for name in ("record", "key_id", "sequence", "previous_hash"))):
                return False
            signed = DOMAIN + canonical
            if hashlib.sha256(signed).hexdigest() != receipt["record_hash"]:
                return False
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_keys[receipt["key_id"]], validate=True))
            public.verify(base64.b64decode(receipt["signature_ed25519"], validate=True), signed)
            sequence, previous_hash = receipt["sequence"], receipt["record_hash"]
        return True
    except Exception:
        return False


class SqlReceiptStore:
    """Uses the ledger database; schema application is an explicit operator step."""
    def __init__(self, path=None):
        self.path = Path(path) if path is not None else usage_store.SqlUsageStore.path()

    def _run(self, operation):
        if not enabled():
            raise ReceiptError("not_found", 404)
        try:
            with closing(connect(self.path)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                return operation(db)
        except ReceiptError:
            raise
        except Exception:
            raise ReceiptError() from None

    @staticmethod
    def _ready(db):
        signer = _signer()
        row = db.execute("SELECT public_key_base64 FROM usage_receipt_keys WHERE key_id = ? AND reviewed = 1",
                         (signer[0],)).fetchone()
        if row is None or row["public_key_base64"] != signer[2]:
            raise ReceiptError()
        # Reads also fail closed if any part of the migration is absent.
        db.execute("SELECT principal FROM usage_receipt_heads LIMIT 0")
        db.execute("SELECT id FROM usage_receipts LIMIT 0")
        return signer

    @staticmethod
    def _public(row):
        return json.loads(row["receipt_json"]) if row else None

    def keys(self):
        def read(db):
            self._ready(db)
            return [dict(row) for row in db.execute("SELECT key_id, public_key_base64 FROM usage_receipt_keys "
                                                    "WHERE reviewed = 1 ORDER BY key_id")]
        return self._run(read)

    def get(self, principal, identity):
        _principal(principal)
        if not isinstance(identity, str) or not _HASH.fullmatch(identity):
            return None
        def read(db):
            self._ready(db)
            return self._public(db.execute("SELECT receipt_json FROM usage_receipts WHERE principal = ? AND id = ?",
                                           (principal, identity)).fetchone())
        return self._run(read)

    def find_event(self, principal, event_id):
        def read(db):
            self._ready(db)
            return self._public(db.execute("SELECT receipt_json FROM usage_receipts WHERE principal = ? AND event_id = ?",
                                           (_principal(principal), _identifier(event_id))).fetchone())
        return self._run(read)

    def append(self, principal, event_id, record):
        _principal(principal)
        _identifier(event_id)
        record = checked_record(record)
        def write(db):
            signer = self._ready(db)
            existing = self._public(db.execute("SELECT receipt_json FROM usage_receipts WHERE principal = ? AND event_id = ?",
                                               (principal, event_id)).fetchone())
            if existing:
                if canonical_bytes(existing["record"]) != canonical_bytes(record):
                    raise ReceiptError("usage_receipt_event_conflict", 409)
                return existing
            db.execute("INSERT INTO usage_receipt_heads (principal, sequence, record_hash) VALUES (?, 0, NULL) "
                       "ON CONFLICT(principal) DO NOTHING", (principal,))
            head = db.execute("SELECT sequence, record_hash FROM usage_receipt_heads WHERE principal = ?", (principal,)).fetchone()
            receipt = make_receipt(principal, event_id, record, head["sequence"] + 1, head["record_hash"], signer)
            db.execute("INSERT INTO usage_receipts (id, principal, event_id, sequence, previous_hash, key_id, receipt_json) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?)", (receipt["record_hash"], principal, event_id, receipt["sequence"],
                                                      receipt["previous_hash"], receipt["key_id"], json.dumps(receipt, ensure_ascii=False)))
            changed = db.execute("UPDATE usage_receipt_heads SET sequence = ?, record_hash = ? "
                                 "WHERE principal = ? AND sequence = ? AND COALESCE(record_hash, '') = ?",
                                 (receipt["sequence"], receipt["record_hash"], principal, head["sequence"], head["record_hash"] or "")).rowcount
            if changed != 1:
                raise ReceiptError("usage_receipt_conflict", 409)
            return receipt
        return self._run(write)


class D1ReceiptStore:
    """The Worker owns signing and CAS; the private transport can be injected."""
    def __init__(self, *, call=None):
        self.call = call or self._private

    @staticmethod
    def _private(body):
        return intelligence_d1_store.request_private_intelligence(body, endpoint="usage-receipts")

    def _call(self, body, field):
        if not enabled():
            raise ReceiptError("not_found", 404)
        try:
            result = self.call(body)
            if not isinstance(result, dict) or result.get("version") != 1 or field not in result:
                raise ReceiptError()
            return result[field]
        except ReceiptError:
            raise
        except Exception:
            raise ReceiptError() from None

    def append(self, principal, event_id, record):
        return self._call({"operation": "append", "principal": _principal(principal),
                           "event_id": _identifier(event_id), "record": checked_record(record)}, "receipt")

    def get(self, principal, identity):
        return self._call({"operation": "get", "principal": _principal(principal), "id": identity}, "receipt")

    def keys(self):
        return self._call({"operation": "keys"}, "keys")


def open_store():
    return D1ReceiptStore() if usage_store.selected_backend() == "d1" else SqlReceiptStore()


def record_settled_usage(principal, event_id, record, *, store=None):
    """Static settlement/reconciliation callback; failures never change metering."""
    if not enabled():
        return None
    try:
        return (store or open_store()).append(principal, event_id, record)
    except Exception:
        logger.warning("Usage receipt unavailable")
        return None


def record_flushed_usage(batch_id, rows):
    if not enabled():
        return
    for index, row in enumerate(rows):
        record = dict(row)
        if record.get("cost_basis") is None:
            record.setdefault("usage_basis", "unknown")
        record_settled_usage(row.get("principal"), f"{batch_id}:{index}", record)
