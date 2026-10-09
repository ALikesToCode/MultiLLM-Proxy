# Signed usage receipts

Usage receipts prove that the gateway signed a particular usage record. They do
not prove provider-billed truth, correct pricing, complete metering, payment,
invoicing, or external anchoring. Unknown costs and token counts remain `null`;
estimated and unknown evidence remains explicitly labelled. Records contain
usage metadata only. They do not contain prompts, completions, or credentials.

## Configuration and storage

`USAGE_RECEIPTS_ENABLED` is off by default. An empty value is off. Accepted true
values are `true`, `1`, `yes`, and `on`; false values are `false`, `0`, `no`, and
`off`, case-insensitively. An invalid value disables receipts with one warning
that does not print the value. While off, usage rows, storage and responses keep
their existing shape, and receipt routes return 404.

For example, an enabled configuration names a key and a secret reference:

```text
USAGE_RECEIPTS_ENABLED=true
USAGE_RECEIPTS_KEY_ID=usage-2026-10
USAGE_RECEIPTS_SIGNING_KEY_REF=USAGE_RECEIPT_PRIVATE
```

The referenced environment variable or Worker secret binding contains a
base64-encoded DER PKCS#8 Ed25519 private key. The reference setting contains only
its binding name. Provision private material through the deployment's secret
mechanism. Neither responses nor errors expose it. Python uses `cryptography`;
the Worker uses WebCrypto Ed25519. Unsupported signing runtimes return 503.

Apply `0032_usage_receipts.sql` to the usage database before enabling receipts.
It creates `usage_receipt_heads`, `usage_receipts`, and `usage_receipt_keys`.
Local SQL uses the ledger's database path. D1 uses the private managed-state
authority. Schema application and public-key review are explicit operator steps.
The migration is additive and does not rewrite existing usage rows.

Independently review the public key, then insert its unique key ID, raw 32-byte
public key encoded as base64, and `reviewed=1` into `usage_receipt_keys`. An
unreviewed key is not published or used to sign. A reviewed active public key
must match the private key. Never reuse an existing key ID for different material.
To rotate, add a newly reviewed public key and change the active key ID/reference.
Keep the old reviewed public keys so old receipts remain verifiable.

With receipts enabled, missing tables, missing or unusable private material,
or an unreviewed/mismatched active key makes receipt reads and writes unavailable
with a JSON 503 error. Usage recording continues. Receipt failures produce only
a fixed warning; they never authorize another provider request.

## Reads and immutable corrections

`GET /v1/usage/receipts/<id>` requires authenticated model-read scope and returns
only a receipt owned by the caller. Its ID is the hexadecimal `record_hash`.
A missing receipt or another principal's receipt returns 404, including for an
administrator. `GET /v1/usage/receipt-keys` requires the same scope and returns
`{"keys":[{"key_id":"...","public_key_base64":"..."}]}`, with reviewed keys
only. Responses use `Cache-Control: no-store`.

A receipt has exactly these fields:

```json
{
  "record": {"cost_usd": null, "cost_basis": "unknown"},
  "canonical_bytes_base64": "...",
  "signature_ed25519": "...",
  "key_id": "usage-2026-10",
  "previous_hash": null,
  "record_hash": "...",
  "sequence": 1
}
```

Sequences start at 1 for each principal. Atomic compare-and-swap advances the
head and stores the receipt in one transaction. A stable event ID is unique
within its principal: repeating the same event and metadata returns the same
receipt, while changing that metadata under the same ID returns 409. Ledger
flush events use `<batch-id>:<row-index>`, distinct from a provider request ID.
Use a new event ID for a settlement correction and include the old receipt's
hash as metadata such as `corrects`. The correction appends to the chain; it
never replaces the original record. Reservation reconciliation uses that same
settled-event interface with its immutable settlement/transition identity.

## Canonical bytes and verification

The decoded `canonical_bytes_base64` is the UTF-8 canonical JSON object containing
`version=1`, `principal`, `event_id`, `key_id`, `record`, `sequence`, and
`previous_hash`. Every unknown metadata field and every exact JSON null is kept.
Object keys sort by Unicode codepoint; arrays keep their order. Strings use JSON
escaping with scalar Unicode encoded directly in UTF-8. Lone surrogates are
rejected. Booleans remain distinct from numbers.

Finite floating-point numbers use the exact decimal expansion of their IEEE-754
value, without exponent notation. Negative zero becomes `0`. Integer values
must fit in the JavaScript safe-integer range. This is a versioned gateway
canonical format, rather than the shortest-number encoding used by JSON JCS.
For example, `0.1` becomes
`0.1000000000000000055511151231257827021181583404541015625`.

Signed bytes are the ASCII prefix `MultiLLM usage receipt v1` followed by the
two literal characters backslash and lowercase `n`, followed by canonical JSON
bytes. `signature_ed25519` is the base64-encoded Ed25519 signature of those bytes;
`record_hash` is their SHA-256 digest in lowercase hexadecimal. The signed
context binds the key ID, principal, event, sequence and previous hash.

Verify the signature with a trusted reviewed public key, recompute canonical
bytes and the hash, and compare all displayed fields with the signed payload.
For a complete chain, require sequence 1 and a null previous hash, followed by
consecutive sequence numbers and matching previous hashes. To verify a suffix,
supply an independently trusted starting sequence and hash. Reordering, missing
records and modified metadata fail verification. A chain cannot prove that a
tail was not truncated without an independently trusted latest head. Public key
delivery still depends on trusting the gateway or separately distributing keys.

Both runtime test files check this public RFC 8032 test vector:

```text
public_key_base64: 11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
key_id: test-1
canonical UTF-8:
{"event_id":"settlement-1","key_id":"test-1","previous_hash":null,"principal":"alice","record":{"cost_basis":"unknown","cost_usd":null,"extra":{"fraction":0.5,"nullable":null,"text":"é","zero":0}},"sequence":1,"version":1}
signature_ed25519: bj6tfJIYOfMT4NdUChDUckhAsA4PLn+ZRTkFoMgFkJ688dug9EXuyw01kUt39d17bJJ+qAP7rzhdROvEgJ9ADg==
record_hash: 500716026bf9836219938f4e6bba0cb435e940bcf6db76910f1ee9f6279ad256
```

## Operational bounds and retention

Canonical documents are limited to 64 KiB, 32 nested levels, and 4,096 visited
values/keys. The private request body is limited to 128 KiB. Content-bearing or
credential-bearing field names are rejected recursively; unknown fields must
still be content-free metadata. Event IDs and key IDs are limited to 128 safe
ASCII characters, principals to 256 Unicode characters. The Worker makes at
most 16 metadata CAS attempts before returning 409 on contention.

Receipts are separate from usage rollups and raw-ledger pruning. There is no
automatic receipt or public-key deletion. Plan storage growth and access with
your retention policy; this feature does not create an immutable external
archive or override a legal deletion requirement. Receipts are written after
successful ledger storage, so a crash or unavailable signing authority can
leave a stored usage event without a receipt. Replaying its stable metadata
event ID can fill that gap without double metering or calling a provider.
Historic ledger rows are not automatically backfilled. Raw/passthrough request
or response bodies are never rewritten.
