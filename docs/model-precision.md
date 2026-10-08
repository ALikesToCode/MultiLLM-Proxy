# Quantization and precision catalog preferences

`MODEL_PRECISION_PREFERENCE` is unset by default. Unset, blank, or `[]` keeps
catalog serialization and intelligence candidate order unchanged. No precision
fields are added to catalog storage while disabled. There is no migration.

Enable it with an ordered JSON array:

```sh
MODEL_PRECISION_PREFERENCE='["int4","fp8","bf16"]'
```

The accepted values are `fp32`, `fp16`, `bf16`, `fp8`, `int8`, `int4`, and
`unknown`. Lists are limited to seven distinct values and environment text to
256 characters. Invalid configuration fails validation rather than selecting
a guessed preference. Candidate permissions and existing safety limits still
apply. Unlisted precisions remain eligible and retain stable order.

Refresh the configured provider catalog after enabling the preference. Only
explicit `precision`, `quantization_scheme`, and `precision_source` fields from
that provider's catalog are accepted. Model names, capability enrichment, and
quantization scheme names do not imply precision. `fp8` is supported because
providers may explicitly declare it; it is never inferred from an identifier.
Unsupported precision enums remain unknown. Unknown entries without declarations
retain their original catalog shape. A declared scheme without precision is
exposed as `precision: unknown`.

`quantization_scheme` is at most 128 characters. `precision_source` is at most
512 characters; both must be nonempty printable strings. Missing provenance is
recorded as `provider_catalog:<provider>` with per-field `metadata_provenance`.
This identifies the declaration source, not independent verification of the
provider's serving hardware or numerical behavior.

An enabled `/v1/models` entry can expose:

```json
{
  "precision": "int4",
  "quantization_scheme": "AWQ",
  "precision_source": "provider_catalog:openai",
  "metadata_provenance": {
    "precision": "provider_catalog:openai",
    "quantization_scheme": "provider_catalog:openai"
  }
}
```

The existing validated intelligence policy JSON can contain the optional
`precision_preference` array. Its explicit value, including `[]`, overrides the
environment ranking preference. It is not added to default policy documents.
Keep the environment setting enabled to retain provider precision metadata.
The existing SQLite and Flask D1 policy readers validate and retain this field.

```json
{"precision_preference": ["bf16", "fp16"]}
```

For `auto:intelligence`, precision can break ties in `quality` and `fast`
profiles only. Existing capability, context, entitlement, privacy, billing,
model-status and adapter checks run first. Every existing ranking dimension
precedes precision, including health and measured speed in the fast profile.
Only contiguous candidates with identical existing rank dimensions and reviewed
quality tier are reordered. Precision cannot cross these groups, add a candidate,
or change an explicitly requested model. The balanced profile preserves the
operator's approved chain order, including policies read through Flask D1.
Existing budget admission runs unchanged before dispatch.

Requests use the existing registered `/v1/chat/completions` intelligence path,
for example `model: auto:intelligence` with `routing.profile: quality`. The
request parser currently rejects `routing.precision_preference`; supporting that
request field needs a separate coordinator change to the strict contract.
Do not send it as an upstream parameter. Ordinary routes and native Worker model
paths remain unchanged; this implementation covers Flask and forwarded routes.

Malformed declaration fields are discarded. Invalid policy preferences raise
the existing policy validation error when the policy is saved. An invalid
environment preference is logged once as a warning and treated as unset, so a
typo leaves catalog listings and routing unchanged instead of failing requests. This feature
introduces no retry, download, provider call, GPU serving, kernel configuration,
price adjustment, or response rewriting. Catalog declarations remain in the
existing local metadata store; no prompts or completions are recorded by this
feature. Precision is not a cost estimate or a guarantee of provider metering,
quality, health, or capabilities. Tests use fake providers and local storage;
deployment and live provider claims require separate verification.
