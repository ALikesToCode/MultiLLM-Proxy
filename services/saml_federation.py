"""Pinned broker JWS verification and durable, explicitly linked identity."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Callable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from services.enterprise_contract import AuthorityDenied, AuthorityOperation, IdentityAssertion, IdentityAuthority, TenantContext

logger = logging.getLogger(__name__)
MAX_AGE = 300
CLOCK_SKEW = 5
MAX_TOKEN_BYTES = 16384
PRIVATE_ENDPOINT = "saml"
OPAQUE = re.compile(r"[A-Za-z0-9_:.\-]{1,128}\Z")
RANDOM = re.compile(r"[A-Za-z0-9_-]{43}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
LINK_ID = re.compile(r"[a-f0-9]{32}\Z")


class SamlError(Exception):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code, self.status = code, status

    def envelope(self) -> dict:
        return {"error": {"code": self.code, "message": "SAML federation request could not be completed.", "retryable": False}}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _text(value: object, maximum: int = 1024) -> bool:
    if not isinstance(value, str) or not 0 < len(value) <= maximum or re.search(r"[\x00-\x1f\x7f]", value):
        return False
    try:
        value.encode("utf-8")
        return True
    except UnicodeError:
        return False


def _json(value: str) -> dict:
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = item
        return result
    result = json.loads(value, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid number")))
    if not isinstance(result, dict):
        raise ValueError("JSON object required")
    return result


def _https(value: object, *, callback: bool = False) -> str:
    if not isinstance(value, str) or not _text(value, 2048) or any(character.isspace() for character in value) or "\\" in value:
        raise ValueError("Invalid HTTPS target")
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None
            or url.fragment or url.port == 0):
        raise ValueError("Invalid HTTPS target")
    if callback:
        if url.path != "/auth/saml/callback" or url.query:
            raise ValueError("Invalid callback target")
    elif any(key in {"nonce", "state", "recipient"} for key, _ in parse_qsl(url.query, keep_blank_values=True)):
        raise ValueError("Reserved broker query parameter")
    return value


@lru_cache(maxsize=1)
def _warn_once() -> None:
    logger.warning("Invalid SAML federation configuration; federation disabled")


@dataclass(frozen=True)
class TrustKey:
    alg: str
    public_key: object


@dataclass(frozen=True)
class SamlConfig:
    enabled: bool = False
    broker_url: str = ""
    callback_url: str = ""
    issuer: str = ""
    audience: str = ""
    keys: Mapping[str, TrustKey] | None = None
    max_age_seconds: int = MAX_AGE


def load_config(env: Mapping[str, str] | None = None, *, callback_url: str | None = None) -> SamlConfig:
    env = os.environ if env is None else env
    flag = env.get("SAML_ENABLED", "")
    flag = flag.strip().lower() if isinstance(flag, str) else "invalid"
    if flag in {"", "0", "false", "no", "off"}:
        return SamlConfig()
    if flag not in {"1", "true", "yes", "on"}:
        _warn_once()
        return SamlConfig()
    try:
        broker = _https(env.get("SAML_BROKER_URL", ""))
        callback = _https(callback_url if callback_url is not None else env.get("SAML_CALLBACK_URL", ""), callback=True)
        raw = env.get("SAML_TRUST_CONFIG_JSON", "") or "{}"
        if not isinstance(raw, str) or len(raw) > 65536:
            raise ValueError("Invalid trust document")
        trust = _json(raw)
        if set(trust) != {"issuer", "audience", "keys", "max_age_seconds"}:
            raise ValueError("Invalid trust fields")
        age = trust["max_age_seconds"]
        if not _text(trust["issuer"]) or not _text(trust["audience"]) or type(age) is not int or not 1 <= age <= MAX_AGE:
            raise ValueError("Invalid trust bounds")
        if not isinstance(trust["keys"], list) or not 1 <= len(trust["keys"]) <= 16:
            raise ValueError("Pinned keys required")
        keys = {}
        for entry in trust["keys"]:
            if not isinstance(entry, dict) or set(entry) != {"kid", "alg", "public_key_pem"}:
                raise ValueError("Invalid key fields")
            pem = entry["public_key_pem"]
            if (not _text(entry["kid"], 128) or entry["kid"] in keys or not isinstance(pem, str)
                    or not 1 <= len(pem) <= 8192):
                raise ValueError("Invalid pinned key")
            key = serialization.load_pem_public_key(entry["public_key_pem"].encode("ascii"))
            alg = entry["alg"]
            if not ((alg == "RS256" and isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048)
                    or (alg == "EdDSA" and isinstance(key, ed25519.Ed25519PublicKey))):
                raise ValueError("Invalid pinned algorithm")
            keys[entry["kid"]] = TrustKey(alg, key)
        return SamlConfig(True, broker, callback, trust["issuer"], trust["audience"], keys, age)
    except (ValueError, TypeError, UnicodeError, KeyError, RecursionError, UnsupportedAlgorithm):
        _warn_once()
        return SamlConfig()


def _decode(segment: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise ValueError("Invalid compact JWS")
    result = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(result).rstrip(b"=").decode() != segment:
        raise ValueError("Noncanonical compact JWS")
    return result


def verify_assertion(token: str, config: SamlConfig, now: int) -> dict:
    """Verify only configured asymmetric keys; assertion attributes grant nothing."""
    try:
        if not config.enabled or not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES:
            raise ValueError("Invalid token")
        head, payload, signature = token.split(".")
        header = _json(_decode(head).decode("utf-8"))
        if set(header) - {"kid", "alg", "typ"} or header.get("typ", "JWT") != "JWT":
            raise ValueError("Unsupported JWS header")
        key = (config.keys or {}).get(header.get("kid"))
        if key is None or header.get("alg") != key.alg:
            raise ValueError("Unpinned key or algorithm")
        signed_bytes = (head + "." + payload).encode("ascii")
        if key.alg == "RS256" and isinstance(key.public_key, rsa.RSAPublicKey):
            key.public_key.verify(_decode(signature), signed_bytes, padding.PKCS1v15(), hashes.SHA256())
        elif key.alg == "EdDSA" and isinstance(key.public_key, ed25519.Ed25519PublicKey):
            key.public_key.verify(_decode(signature), signed_bytes)
        else:
            raise ValueError("Unsupported key")
        claims = _json(_decode(payload).decode("utf-8"))
        iat, exp = claims.get("iat"), claims.get("exp")
        if (type(iat) is not int or type(exp) is not int or iat < 0 or exp >= 9007199254740991
                or not 0 < exp - iat <= config.max_age_seconds or iat > now + CLOCK_SKEW
                or exp <= now - CLOCK_SKEW or now - iat > config.max_age_seconds + CLOCK_SKEW):
            raise ValueError("Invalid assertion time")
        if (claims.get("iss") != config.issuer or claims.get("aud") != config.audience
                or claims.get("recipient") != config.callback_url or not _text(claims.get("sub"))
                or not isinstance(claims.get("nonce"), str) or not RANDOM.fullmatch(claims["nonce"])
                or not isinstance(claims.get("state"), str) or not RANDOM.fullmatch(claims["state"])):
            raise ValueError("Invalid assertion binding")
        if "nbf" in claims and (type(claims["nbf"]) is not int or claims["nbf"] > now + CLOCK_SKEW):
            raise ValueError("Assertion not active")
        return claims
    except (ValueError, TypeError, UnicodeError, KeyError, InvalidSignature, RecursionError):
        raise SamlError("saml_assertion_invalid") from None


class SamlStore:
    """Fixed private RPC operations, without volatile identity fallback or retries."""
    def __init__(self, call: Callable | None = None):
        self._call = call

    def call(self, operation: str, **values) -> dict:
        try:
            body = {"version": 1, "operation": operation, **values}
            if self._call is None:
                if os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip().lower() != "d1":
                    raise SamlError("saml_storage_unavailable", 503)
                from services.intelligence_d1_store import request_private_intelligence
                result = request_private_intelligence(body, endpoint=PRIVATE_ENDPOINT)
            else:
                result = self._call(body)
            if not isinstance(result, dict) or type(result.get("version")) is not int or result.get("version") != 1 or "error" in result:
                raise ValueError("Invalid storage reply")
            return result
        except Exception:
            raise SamlError("saml_storage_unavailable", 503) from None

    def ready(self) -> None:
        if self.call("ready").get("ready") is not True:
            raise SamlError("saml_storage_unavailable", 503)


def lookup_gateway_account(account: str) -> dict | None:
    from services.auth_service import AuthService
    return AuthService.get_user_record(account)


def issue_dashboard_session(account: str, context: TenantContext) -> bool:
    """Use the password-login session issuer after verifying the linked account scope."""
    from services.auth_service import AuthService
    principal = account if OPAQUE.fullmatch(account) else "account:" + digest(account)
    if type(context) is not TenantContext or context.principal_id != principal:
        raise SamlError("saml_identity_denied", 403)
    return AuthService.issue_dashboard_session(account)


def _active_account(record: object, account: str, now: int) -> bool:
    if not isinstance(record, dict) or record.get("username") != account or record.get("revoked_at"):
        return False
    expires = record.get("expires_at")
    if expires:
        try:
            instant = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if instant.tzinfo is None:
                instant = instant.replace(tzinfo=timezone.utc)
            return instant.timestamp() > now
        except (TypeError, ValueError, AttributeError):
            return False
    return True


def stored_link_authority(assertion: IdentityAssertion, operation: AuthorityOperation) -> TenantContext:
    """The caller constructs the context only from the active stored subject link."""
    if assertion.verified is not True:
        raise AuthorityDenied("identity_unverified")
    return operation.context


class SamlFederation:
    def __init__(self, config: SamlConfig, store: SamlStore | None = None, *,
                 session_issuer: Callable = issue_dashboard_session, account_lookup: Callable = lookup_gateway_account,
                 identity_authority: IdentityAuthority = stored_link_authority, clock: Callable = time.time):
        self.config, self.store = config, store or SamlStore()
        self.session_issuer, self.account_lookup = session_issuer, account_lookup
        self.identity_authority, self.clock = identity_authority, clock

    def begin(self) -> tuple[str, str]:
        self.store.ready()
        now, nonce, state = int(self.clock()), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        result = self.store.call("create_request", state_digest=digest(state), nonce_digest=digest(nonce),
                                 recipient_digest=digest(self.config.callback_url), now=now, expires_at=now + MAX_AGE)
        if result.get("created") is not True:
            raise SamlError("saml_storage_unavailable", 503)
        url = urlsplit(self.config.broker_url)
        query = parse_qsl(url.query, keep_blank_values=True) + [("nonce", nonce), ("state", state), ("recipient", self.config.callback_url)]
        return urlunsplit((url.scheme, url.netloc, url.path, urlencode(query), "")), digest(state)

    def _audit(self, outcome: str, account: str | None = None) -> None:
        result = self.store.call("audit", issuer_digest=digest(self.config.issuer), account=account, outcome=outcome, now=int(self.clock()))
        if result.get("recorded") is not True:
            raise SamlError("saml_storage_unavailable", 503)

    def complete(self, token: str, state: str, browser_state_digest: str) -> None:
        self.store.ready()
        account = None
        try:
            now = int(self.clock())
            claims = verify_assertion(token, self.config, now)
            if (not isinstance(state, str) or state != claims["state"] or not isinstance(browser_state_digest, str)
                    or not DIGEST.fullmatch(browser_state_digest) or not hmac.compare_digest(digest(state), browser_state_digest)):
                raise SamlError("saml_assertion_invalid")
            claimed = self.store.call("claim_request", state_digest=digest(state), nonce_digest=digest(claims["nonce"]),
                                      recipient_digest=digest(self.config.callback_url), now=now)
            if claimed.get("claimed") is not True:
                raise SamlError("saml_assertion_replayed")
            linked = self.store.call("lookup_link", issuer_digest=digest(claims["iss"]), subject_digest=digest(claims["sub"])).get("link")
            if not isinstance(linked, dict) or linked.get("active") != 1:
                raise SamlError("saml_subject_unlinked", 403)
            account = linked["account"]
            if not _active_account(self.account_lookup(account), account, now):
                raise SamlError("saml_subject_unlinked", 403)
            principal = account if OPAQUE.fullmatch(account) else "account:" + digest(account)
            context = TenantContext(principal, linked.get("org_id"), linked.get("team_id"), linked["grants_revision"])
            assertion = IdentityAssertion(digest(claims["iss"]), digest(claims["sub"]), digest(claims["aud"]),
                                          digest(state), digest(claims["nonce"]), claims["exp"], True)
            operation = AuthorityOperation(context, linked["id"], context.grants_revision, digest(state))
            try:
                resolved = self.identity_authority(assertion, operation)
                if type(resolved) is not TenantContext or resolved != context:
                    raise AuthorityDenied("authority_scope_mismatch")
            except AuthorityDenied:
                raise SamlError("saml_identity_denied", 403) from None
            # Record permission before session mutation so an audit outage cannot admit a login.
            self._audit("authorized", account)
            try:
                issued = self.session_issuer(account, context)
            except Exception:
                raise SamlError("saml_session_unavailable", 503) from None
            if issued is not True:
                raise SamlError("saml_session_unavailable", 503)
        except SamlError as error:
            if error.code != "saml_storage_unavailable":
                self._audit(error.code, account)
            raise
        except Exception:
            self._audit("saml_identity_unavailable", account)
            raise SamlError("saml_identity_unavailable", 503) from None

    def list_links(self, offset: int = 0) -> dict:
        self.store.ready()
        return self.store.call("list_links", offset=offset)

    def get_link(self, identifier: str) -> dict:
        self.store.ready()
        if not LINK_ID.fullmatch(identifier):
            raise SamlError("saml_link_invalid")
        return self.store.call("get_link", id=identifier)

    def put_link(self, payload: object, actor: str, identifier: str | None = None) -> dict:
        self.store.ready()
        allowed = {"issuer", "subject", "account", "org_id", "team_id", "grants_revision"}
        if not isinstance(payload, dict) or set(payload) - allowed or not {"issuer", "subject", "account"} <= set(payload):
            raise SamlError("saml_link_invalid")
        if payload["issuer"] != self.config.issuer or not _text(payload["subject"]) or not _text(payload["account"], 128):
            raise SamlError("saml_link_invalid")
        account = payload["account"]
        try:
            record = self.account_lookup(account)
        except Exception:
            raise SamlError("saml_identity_unavailable", 503) from None
        if not _active_account(record, account, int(self.clock())):
            raise SamlError("saml_subject_unlinked", 403)
        try:
            principal = account if OPAQUE.fullmatch(account) else "account:" + digest(account)
            context = TenantContext(principal, payload.get("org_id"), payload.get("team_id"), payload.get("grants_revision", 0))
            if identifier is not None and not LINK_ID.fullmatch(identifier):
                raise ValueError("Invalid link identifier")
        except (ValueError, TypeError):
            raise SamlError("saml_link_invalid") from None
        # A subject has one stable link ID; edits retain its audit history.
        identifier = identifier or digest(self.config.issuer + "\0" + payload["subject"])[:32]
        linked = {"id": identifier, "issuer_digest": digest(payload["issuer"]), "subject_digest": digest(payload["subject"]),
                  "account": account, "org_id": context.org_id, "team_id": context.team_id, "grants_revision": context.grants_revision}
        return self.store.call("put_link", link=linked, actor=actor, now=int(self.clock()))

    def deactivate_link(self, identifier: str, actor: str) -> dict:
        self.store.ready()
        if not LINK_ID.fullmatch(identifier):
            raise SamlError("saml_link_invalid")
        return self.store.call("deactivate_link", id=identifier, actor=actor, now=int(self.clock()))
