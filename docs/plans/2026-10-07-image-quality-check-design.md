# Image quality check with judge and retry

## Contract

Opt-in QA applies to `/v1/images/generations`, including reference-image generation,
`/v1/images/batch`, and asynchronous `/v1/images/batches`. The shared Flask generation
dispatcher implements it; the Worker continues forwarding generation to the Container.
`worker/cors-policy.mjs` owns the allowed and exposed header policy; API path gating
remains in the Worker. Generation, judge dispatch and model validation collaborators
are injected into the focused QA and raw image modules.
Native provider endpoints and `/v1/images/edits` do not enable QA.

`quality_check` accepts true or an object with `judge_model` (model ID), `min_score`
(finite number 0–10, default 7), `max_attempts` (integer 1–3, default 2, including
the first generation), and `criteria` (up to five strings, each up to
200 characters). No other option is accepted. `X-MultiLLM-Image-QA: on` enables
defaults; any other header value is invalid. Batch top-level options precede
`defaults`, which precede item options. Both controls are removed before upstream
dispatch. Validation happens before batch work starts.

## Judge and objective scoring

`IMAGE_QA_JUDGE_MODEL` selects the default, falling back to `free:vision`. The Worker
passes this variable to the Container. Gemini is never selected as the default.
Explicit judges use the existing chat target validation; free aliases use the free
request validator. All judges must match the authenticated key's model allowlist.

The judge uses the gateway's chat dispatcher with non-streaming JSON output,
700 output tokens, and a 120-second request timeout where the dispatcher supports it.
The existing free pool retains its own 120-second overall deadline and quota failover.
The system prompt requests exactly `score`, `prompt_adherence`, `text_accuracy`,
`artifacts`, `visible_text`, `issues`, and `fix_instructions`. Scores are finite
numbers from 0–10; text_accuracy can be null when no text was requested; artifacts
10 means no artifacts. Transcription is capped at 2,000 characters, issues at five
strings of 200 characters, and fixes at 300 characters. Judge content is capped at
8 KiB, its enclosing response at 64 KiB. Strict JSON rejects duplicate keys,
non-finite values, markdown fences, missing fields and malformed contracts.

Straight and curly single/double quoted spans in the original prompt form the
expected text; apostrophes inside words are excluded. Expected and visible text
are capped at 2,000 characters, normalized with NFKC, casefolding and whitespace
collapse. Levenshtein similarity is `1 - distance / max(lengths)`. When text is
expected, final score is the smaller of judge score and similarity times ten,
rounded to one decimal. This bounds the dynamic-programming matrix to a single
row of at most 2,001 entries.

Image input uses generated base64 bytes, data URLs, or reads from owned media
storage. Provider URLs are imported through the existing storage service; arbitrary
provider URLs are not sent straight to the judge. Existing file IDs require owner
and image-kind checks. Reads are capped at 50 MiB; inline decoded bytes at 4 MiB.
Pillow reduces larger images to at most 2048x2048 JPEG; images over 40 million pixels
are not decoded. When reduction fails, existing or newly stored R2 bytes supply a
gateway signed URL and `judge_image_source: "signed_url"`. Without accessible bytes
or storage, judging fails safely and the generated image is retained.

## Retry, usage and response

Each image is generated with n=1 and judged independently. A failing image receives
the original prompt plus `\n\nAvoid: ` and bounded fixes. Retries pin the exact
selected provider/model from the first automatic-route response and reuse its
provider-specific parameter preparation. GGUU remains selected when it produced
the first image. The highest score wins, with ties retaining the earlier image.
A judge error stops that image's loop; an error on a later take retains the prior
best image and reports the error. Maximum generations are n times max_attempts.
Images within an item run sequentially; batch items retain four-way concurrency.
Each new take derives a distinct upstream idempotency key when the caller supplied
one, preserving provider-side transport replay for that take.

Gateway-owned subrequests use the existing budget reservations, rate admission,
cost estimates, ledger rows and telemetry records. They replace the aggregate outer
reservation/row to avoid double charging. Each generation and each dispatched
judge receives its own row; actual judge token usage is recorded. The first single
request generation uses the already-admitted outer rate allowance. Subsequent work
and batch item work receive their own allowance checks. Copied Flask request contexts
carry the authenticated principal and its controls. Async submissions remain
deferred; QA records its own subrequests instead of an extra batch-item aggregate.

Returned images gain `quality` with score, passed, attempts, issues and judge_model,
plus text_similarity when applicable, judge_error on failure, stopped_reason for
an admission/generation refusal, and judge_image_source for URL fallback. Synchronous
generation and batch responses include `X-MultiLLM-Image-QA: attempts=<total>
best=<score>` (`unknown` when no image could be graded). Async result file entries
persist the same quality object in the existing D1 JSON field without a schema change.

## Operations and limits

No dependency, binding, D1 migration or Durable Object migration is added. Configure
eligible free vision providers, or optionally set an approved IMAGE_QA_JUDGE_MODEL
Worker variable. Provider URL input and signed fallback need the existing MEDIA_BUCKET
storage configuration. Existing MEDIA_JOBS and D1 bindings are required only for
async batches. Extra generations and paid judges are billable. Large requests can
exceed client/proxy timeouts; prefer async batches and confirm deployment timeout
settings before enabling QA for large n. Crash recovery can recover stored images
through the existing media workflow; it cannot reconstruct an in-flight judge grade.
All acceptance evidence is synthetic/local; no live inference or deployment was run.
