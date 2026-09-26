# Media storage

Provider image and video URLs expire, some within an hour, which can be shorter than
the task that needs them. With an R2 bucket bound to the Worker, MultiLLM keeps a copy
of generated media and returns its own links instead. Without the binding, every media
response is exactly as before.

## What is stored

- Images from `POST /v1/images/generations`, `POST /v1/images/edits` and
  `POST /v1/images/batch`: every provider URL is copied, and base64 images are stored
  when the request asked for `response_format: "url"`. Each image in the reply then has
  `url` (a gateway link) and `file_id`, and `X-MultiLLM-Media-Stored` counts the
  stored images. If a copy fails, that image keeps the provider's result.
- Videos: the first `GET /v1/videos/{id}` that reports `completed` copies the file, and
  the reply gains `file_id` with `content_url` pointing at the stored copy.
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

## Setup

1. Create the bucket: `npx wrangler r2 bucket create multillm-media`.
2. Expire old files with a lifecycle rule, for example after 30 days:
   `npx wrangler r2 bucket lifecycle add multillm-media expire-media media/ --expire-days 30`.
   R2 removes expired objects within about a day. Links outlive neither the rule nor a
   deletion.
3. Add the binding to `wrangler.jsonc` and deploy:

   ```json
   "r2_buckets": [{ "binding": "MEDIA_BUCKET", "bucket_name": "multillm-media" }]
   ```

The binding is not in `wrangler.jsonc` by default: Cloudflare rejects an upload whose
R2 binding names a bucket that does not exist (`R2 bucket '…' not found`, code 10085),
so adding it before step 1 would break deploys. The Worker tells the Container about the
binding (`MEDIA_STORAGE_ENABLED`), so nothing else needs configuring.

Objects live under `media/{file_id}` with the owner, kind and model as custom metadata.
