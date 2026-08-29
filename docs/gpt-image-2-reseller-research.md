# GPT Image 2 relay research

Verified against public provider pages on 2026-08-29. Prices, model routes, and retention terms can change without notice. Treat the entries below as a qualification snapshot, then re-check the provider dashboard before adding funds.

## Recommendation

Use the routes in this order:

1. **AIHubMix free** for zero-cost validation while the free model remains available.
2. **GGUU AI** for the funded low-cost trial: its live catalog and guide advertise one flat ¥0.04 price across 1K, 2K, and 4K with `quality=high` supported.
3. **Together AI** for a conventional OpenAI-compatible production route with an explicit account privacy control.
4. **Latix** for low-risk testing after confirming the current dashboard price and the exact debug-log retention period.
5. **AIMLAPI, A6api, or ePhone** only for non-sensitive workloads until their API-data retention terms are made precise.
6. **Replicate, fal, Runware, Cloudflare Workers AI, or Vercel AI Gateway** through dedicated adapters, not the generic OpenAI-compatible relay configuration.

Do not pre-fund an opaque relay based only on a comparison-table price. Run the same 20–50 prompts and measure successful-generation cost, latency, edit fidelity, refusals, output provenance, and support responsiveness first.

## Evidence matrix

| Provider | Observed GPT Image 2 route | Protocol | Observed price | API-data posture | MultiLLM support |
| --- | --- | --- | --- | --- | --- |
| [AIHubMix](https://aihubmix.com/model/gpt-image-2-free/llms.txt) | `gpt-image-2-free` | OpenAI Images | Free route advertised | Review current account terms before sensitive use | First-class `aihubmix:gpt-image-2-free` |
| [GGUU AI](https://gguuai.com) | `gpt-image-2` | OpenAI-compatible generation/edit | Live catalog showed ¥0.04/image with 1K/2K/4K at the same price; current guide supports `quality=high` | Precise API payload-retention terms were not established; keep sensitive workloads out until verified | First-class `gguu:gpt-image-2` with bounded `api.aiaimax.com` backup |
| [Together AI](https://www.together.ai/models/gpt-image-2) | `openai/gpt-image-2` | OpenAI-compatible Images | $0.053/image on the inspected model page | Account setting can disable storage/training; verify it after signup | First-class `together:openai/gpt-image-2` |
| [Latix](https://api.latix.ai) | `gpt-image-2` | OpenAI-compatible Images | Dashboard verification required | Public material says prompts/outputs are not persistently stored, with short debugging logs; duration was not precise | First-class `latix:gpt-image-2` |
| [A6api](https://a6api.com) | `gpt-image-2` | OpenAI-compatible generation/edit | Dashboard verification required | Terms describe forwarding and necessary retention without a precise API payload period | First-class `a6api:gpt-image-2` |
| [ePhone AI](https://api.ephone.ai) | `gpt-image-2` | OpenAI-compatible Images | Multiple discounted channels shown | Public policy states prompts/outputs can be retained 30–90 days | First-class `ephone:gpt-image-2` |
| [AIMLAPI](https://aimlapi.com/models/gpt-image-2) | `openai/gpt-image-2` | OpenAI-compatible Images | Token prices shown on the model page | Public privacy material did not provide a precise API inference-retention promise | First-class `aimlapi:openai/gpt-image-2` |
| [Replicate](https://replicate.com/openai/gpt-image-2) | `openai/gpt-image-2` | Predictions API | $0.012 low, $0.047 medium, $0.128 high/auto on the inspected page | General retention language; exact prediction retention was not established | Requires a Predictions adapter |
| [fal](https://fal.ai/models/openai/gpt-image-2) | `fal-ai/gpt-image-2` | Queue/subscription API | Token-based official-model pricing | Inputs/outputs stored for 30 days by default; documented opt-out header available | Requires a fal queue adapter |
| [Runware](https://runware.ai/docs/models/openai-gpt-image-2/examples) | `openai:gpt-image@2` | Runware task API | Examples were about $0.15–$0.165 for high-quality images | Verify current account policy | Requires a Runware task adapter |
| [Cloudflare Workers AI](https://developers.cloudflare.com/ai/models/openai/gpt-image-2/) | `openai/gpt-image-2` | Workers AI binding/API | Dashboard pricing | Model page advertises zero-data-retention handling | Requires a Workers AI adapter |
| [Vercel AI Gateway](https://vercel.com/ai-gateway/models/gpt-image-2) | `openai/gpt-image-2` | AI SDK/Gateway | Provider-dependent | Storage and routing depend on the selected upstream | Requires an AI Gateway adapter |

The [TokenPlus comparison index](https://www.tokenplus.app/gpt-image) showed 143 GPT Image 2 relay sites and 160 tiers. Its own ranking is price-normalized; it does not establish model provenance, availability, retention, or billing accuracy. Plinero, 728code, and similar generic “New API” panels therefore remain rejected by default until operator identity, legal terms, payload retention, and a small funded test are verified.

## Account status

No passwords, OAuth tokens, API keys, or mailbox identifiers are stored in this repository.

| Provider | Status | Next manual step |
| --- | --- | --- |
| GGUU AI | Funded trial account | Create an image-group API token and run a small high-quality 4K smoke test |
| Together AI | Google OAuth initiated | Select the already signed-in account and approve Google consent in the visible browser |
| Latix | Not started | Complete its Google OAuth flow after Together is finished |
| A6api | Not started | Complete Google OAuth, then inspect terms and pricing before funding |
| ePhone AI | Not started | Complete Google OAuth and any CAPTCHA manually |
| AIMLAPI | Not started | Create only if its current signup offers Google OAuth |

Account creation does not authorize purchases, subscriptions, balance top-ups, or paid generations.

## MultiLLM setup

The unified generation endpoint uses a provider-qualified model ID:

```bash
curl "$PROXY_BASE_URL/v1/images/generations" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -H "Idempotency-Key: $REQUEST_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "together:openai/gpt-image-2",
    "prompt": "A cinematic lighthouse at dusk",
    "size": "1024x1024"
  }'
```

The built-in relay credential names are:

```dotenv
TOGETHER_API_KEY=...
A6API_API_KEY=...
AIMLAPI_API_KEY=...
EPHONE_API_KEY=...
GGUU_API_KEY=...
LATIX_API_KEY=...
```

Generation and editing are also exposed through each provider's native namespace. The proxy accepts only model discovery, chat, Responses, image generation, and image editing on generic relay namespaces; account, billing, file, and arbitrary paths are rejected.

```bash
curl "$PROXY_BASE_URL/latix/v1/images/edits" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -H "Idempotency-Key: $REQUEST_ID" \
  -F "model=gpt-image-2" \
  -F "prompt=Add warm evening light" \
  -F "image=@input.png"
```

### Add another OpenAI-compatible relay

Set a public, credential-free HTTPS origin and declare only the models that actually generate images:

```dotenv
IMAGE_RELAY_PROVIDERS_JSON='{"myrelay":{"display_name":"My Relay","base_url":"https://api.example.com","backup_base_url":"https://api-backup.example.com","credential_env":"MYRELAY_API_KEY","models":["gpt-image-2"],"supports_chat":true,"supports_edits":true}}'
MYRELAY_API_KEY=...
```

For Cloudflare, put credentials in Worker secrets rather than `wrangler.jsonc`. `wrangler secret put` creates and deploys a new Worker version, so run it only when ready to publish:

```bash
npx wrangler secret put MYRELAY_API_KEY
```

If dynamically named secrets cannot be forwarded to the Container, store the bounded provider-to-key map as a Worker secret:

```bash
npx wrangler secret put IMAGE_RELAY_API_KEYS_JSON
```

Never commit either secret value. `IMAGE_RELAY_PROVIDERS_JSON` may be a non-secret `vars` value, while `IMAGE_RELAY_API_KEYS_JSON` must remain secret.

## Why proprietary providers are separate

Replicate Predictions, fal queues, Runware tasks, Workers AI, and Vercel AI Gateway do not share the OpenAI Images request/response lifecycle. Pretending they do would lose async job IDs, polling, cancellation, storage controls, provider-specific errors, or billing metadata. They should each receive a small adapter with contract tests before being advertised as compatible.
