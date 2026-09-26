# Media storage, batches and webhooks

Provider image and video URLs expire, some within an hour, which can be shorter than
the task that needs them. With an R2 bucket bound to the Worker, MultiLLM keeps a copy
of generated media and returns its own links instead. With a Workflow binding as well,
it runs large image batches in the background and posts signed webhooks. Without the
bindings, every media response is exactly as before.

## What is stored

- Images from `POST /v1/images/generations`, `POST /v1/images/edits` and
  `POST /v1/images/batch`: every provider URL is copied, and base64 images are stored
  when the request asked for `response_format: "url"`. Each image in the reply then has
  `url` (a gateway link) and `file_id`, and `X-MultiLLM-Media-Stored` counts the
  stored images. If a copy fails, that image keeps the provider's result.
- Videos: the first `GET /v1/videos/{id}` that reports `completed` copies the file (so
  that poll takes as long as the download), and the reply gains `file_id` with
  `content_url` pointing at the stored copy. A failed copy is retried on the next poll.
  `GET /v1/videos/{id}/content` then streams from R2. Videos up to 512 MiB with a known
  size are stored; others stay with the provider.

## Links and access

A gateway link looks like `https://<gateway>/v1/media/files/{file_id}?expires=…&signature=…`.
The signature is an HMAC of the file ID and expiry, so the link works without an API key
until it expires, and nothing else can be derived from it. The Worker checks it and
serves the file from R2 without waking the Container, with `Range` support for video
seeking. Expired or altered links return `403` (`link_expired` or `invalid_link`).

Links last `MEDIA_LINK_TTL_SECONDS` (default seven days, at most 30). The signing key is
derived from `MEDIA_SIGNING_SECRET`, or from `FLASK_SECRET_KEY` when that is unset; both
the Worker and the Container read it, so set it as a Worker secret. Changing it
invalidates every link issued so far.

With an API key, the owner (the key's user) or an administrator can:

- `GET /v1/media/files/{file_id}`: the file itself.
- `GET /v1/media/files/{file_id}?format=json`: size, type, model and a fresh signed link.
- `DELETE /v1/media/files/{file_id}`: delete it now.

Other keys get `404`.

## Asynchronous image batches

`POST /v1/images/batches` takes the same `items` and `defaults` as the synchronous
`/v1/images/batch`, but up to 500 items and 1,000 images, and returns at once:

```json
{
  "defaults": {"model": "auto:image", "size": "1536x1024"},
  "items": [{"id": "hero", "prompt": "Mountain lake at dawn"}, {"id": "icon", "prompt": "Flat lake icon", "n": 2}],
  "webhook_url": "https://example.com/hooks/multillm",
  "metadata": {"project": "launch"}
}
```

Items accept `id` (unique, at most 64 of `A-Z a-z 0-9 _ . : -`), `model`, `prompt` (at
most 32,000 characters), `n`, `size`, `quality`, `background`, `output_format`,
`output_compression`, `moderation`, `user`, `aspect_ratio`, `resolution` and `style`.
Every image is stored in R2, so `response_format` is ignored. The request body may be
2 MiB. `metadata` holds up to 16 string values. An `Idempotency-Key` header makes the
request repeatable: the same key and body return the same batch, and the same key with
a different body is refused with `409 idempotency_conflict`.

- `GET /v1/images/batches/{id}`: `status` (`queued`, `in_progress`, `cancelling`,
  `completed`, `cancelled`, or `failed` when no item succeeded) and `request_counts`.
- `GET /v1/images/batches/{id}/results?after=&limit=`: up to 100 items per page, each
  with `status`, `model`, `images` (fresh signed links) or `error`; `next_after` pages on.
- `GET /v1/images/batches`: your recent batches, newest first (`limit`, `before`).
- `POST /v1/images/batches/{id}/cancel`: queued items are cancelled; running ones finish.

A Cloudflare Workflow in the Worker drives each batch, so it survives Container sleep
and restarts. It sends four items at a time (`MEDIA_BATCH_CHUNK_SIZE`, 1 to 8) to the
Container, which runs each through the normal image dispatch with its route's failover.
At most two batches run at once (`MEDIA_BATCH_MAX_RUNNING`); others wait as `queued`.
Each key owner may have three batches queued or running (`MEDIA_BATCH_MAX_ACTIVE`),
beyond which creation returns `429 too_many_active_batches`. These are Worker variables.
Finished batches are deleted from D1 after 30 days (`MEDIA_JOB_RETENTION_DAYS`); their
images follow the bucket's lifecycle rule. A batch counts as one request against rate
limits.

Items are never generated twice. An item is claimed before it is sent; if that attempt
is interrupted (a Worker or Container restart), the item is marked from the images it
already stored, or failed with `outcome_unknown`, because the provider may have billed
it. A failed item reports the provider's status and message.

The Workflow calls the Container at `/internal/media/*`, which the Worker never exposes.
It sends a signed principal naming the batch and its owner, not the owner's API key, and
the Container checks that the account still exists before each call. Deleting the
account stops the batch (`principal_rejected`).

Without the Workflow, D1 or the bucket, the batch endpoints return
`503 batches_not_configured`; everything else keeps working.

## Webhooks

Batches and videos (`POST /v1/videos` with `webhook_url`) can notify an HTTPS URL when
they end. Webhook URLs must use `https` on a public host with the default port; IP
addresses, `localhost`, internal names and credentials in the URL are refused, and
redirects are not followed. The Worker sends:

```json
{"type": "image.batch.completed", "created_at": 1790000000,
 "data": {"id": "imgbatch_…", "object": "image.batch", "status": "completed", "request_counts": {…}, "metadata": {…}}}
```

Video events are `video.completed`, `video.failed` or `video.expired` (not finished
within about six hours), with the video job `id`, `status` and `model`. Fetch results
with your API key; links are not included in the payload.

Payloads are signed as [Standard Webhooks](https://www.standardwebhooks.com/): headers
`webhook-id`, `webhook-timestamp` and `webhook-signature` (`v1,` and the base64
HMAC-SHA256 of `id.timestamp.body`). The secret is per key owner: it is returned when a
webhook is registered and by `GET /v1/media/webhook-secret` (`whsec_…`; sign with the
base64-decoded bytes after the prefix). A receiver that answers with a server error,
`408`, `409`, `425` or `429` is retried six times with backoff; other client errors are
final. The batch's `webhook.status` reports `delivered`, `rejected` or `failed`. Video
webhooks need the Workflow and D1 but not the bucket; without them `POST /v1/videos`
with `webhook_url` returns `503 webhooks_not_configured` before creating a job.

## Setup

1. Create the bucket: `npx wrangler r2 bucket create multillm-media`.
2. Expire old files with a lifecycle rule, for example after 30 days:
   `npx wrangler r2 bucket lifecycle add multillm-media expire-media media/ --expire-days 30`.
   R2 removes expired objects within about a day. Links outlive neither the rule nor a
   deletion.
3. Apply the D1 migrations, including `0008_media_jobs.sql`:
   `npx wrangler d1 migrations apply multillm-intelligence --remote`. `/ready` reports
   `d1_schema_missing` until it is applied.
4. Add the bindings to `wrangler.jsonc` and deploy. The Workflow is created by the
   deploy itself; only the bucket must exist first.

   ```json
   "r2_buckets": [{ "binding": "MEDIA_BUCKET", "bucket_name": "multillm-media" }],
   "workflows": [{ "name": "multillm-media-jobs", "binding": "MEDIA_JOBS", "class_name": "MediaJobWorkflow" }]
   ```

The bindings are not in `wrangler.jsonc` by default: Cloudflare rejects an upload whose
R2 binding names a bucket that does not exist (`R2 bucket '…' not found`, code 10085),
so adding it before step 1 would break deploys. Storage needs only `MEDIA_BUCKET`; video
webhooks need `MEDIA_JOBS` and D1; batches need all three. The Worker tells the
Container which are bound (`MEDIA_STORAGE_ENABLED`, `MEDIA_JOBS_ENABLED`), so nothing
else needs configuring.

Objects live under `media/{file_id}` with the owner, kind and model as custom metadata.
