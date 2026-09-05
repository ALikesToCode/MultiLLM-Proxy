# Free provider setup checklist

The free pools support **11 services**, including six additional opt-in
destinations. You do not need all of them. Start with OpenRouter, OpenCode Zen,
AIHubMix, and a verified Groq Free account; add destinations as needed.
Ordering is a preference, not a measured speed or quality ranking.

For a compact account-opening reference, see [signup links and key names](free-provider-signup-links.md).

Reviewed September 5, 2026: public documentation was checked; authenticated
generation and your account's billing tier were not. Offerings, capacity,
model IDs and terms can change. The community list supplies leads, not API or
pricing guarantees.

## Accounts and secrets to configure

Store these **on the proxy server**, never in browser/client JSON. Clients use
a MultiLLM proxy key. New services are available in the free pools, not newly
added general-purpose paid routes or dashboard provider adapters.

| Service | Account / key setup | Server secret name | Pool coverage | Admission rule |
| --- | --- | --- | --- | --- |
| OpenRouter | [API keys](https://openrouter.ai/settings/keys) | `OPENROUTER_API_KEY` | Text + vision | `openrouter/free` and eligible discovered `:free` models |
| OpenCode Zen | [Zen account](https://opencode.ai/zen) | `OPENCODE_API_KEY` (existing `OPENCODE_GO_API_KEY` takes precedence if both exist) | Text; vision when exact model metadata confirms it | Free Zen Chat Completions models only |
| AIHubMix | [Platform account](https://aihubmix.com/) | `AIHUBMIX_API_KEY` | Text; vision when exact model metadata confirms it | `-free` text-output models only |
| Groq | [API keys](https://console.groq.com/keys); check organization plan | `GROQ_API_KEY` | Text + vision | Explicit Free-plan assertion |
| Gemini | [AI Studio API keys](https://aistudio.google.com/apikey); check the key's project | `GEMINI_API_KEY` | Text + vision | Explicit unbilled free-project assertion |
| **Mistral** | [Mistral Studio](https://console.mistral.ai/); create API key in **Free mode** | `MISTRAL_API_KEY` | Text + vision: `mistral-small-latest` | Extra-provider opt-in + Free-mode assertion |
| **Cloudflare Workers AI** | [Cloudflare dashboard](https://dash.cloudflare.com/); select a **Workers Free** account and create an account-scoped Workers AI inference token | `WORKERSAI_API_KEY` | Text + vision: `@cf/meta/llama-4-scout-17b-16e-instruct` | Extra-provider opt-in + Workers Free assertion + account ID |
| **Z.ai** | Follow [Z.ai API setup](https://docs.z.ai/guides/llm/glm-4.5) for the international `api.z.ai` platform | `ZAI_API_KEY` | Text: `glm-4.5-flash` | Extra-provider opt-in; exact documented free model only |
| **OrcaRouter** | [Register](https://www.orcarouter.ai/register); key must allow `orcarouter/free` | `ORCAROUTER_API_KEY` | Text; alias vision unconfirmed | Extra-provider opt-in; `orcarouter/free` only |
| **BazaarLink** | [BazaarLink](https://bazaarlink.ai/); create a **standard inference key**, not a management key | `BAZAARLINK_API_KEY` | Text: `auto:free`; free vision tier currently disabled | Extra-provider opt-in; server forces `X-Free-Fallback: false` |
| **LLM7** | [LLM7 dashboard](https://dash.llm7.io/); create a **Free token**, without Pro or top-up billing | `LLM7_API_KEY` | Text: `fast`; selector vision unconfirmed | Extra-provider opt-in + free-account assertion |

New destinations remain disabled even if their credentials already exist.
Enabling one allows fallback to send the conversation and images to it. Check
retention, training, regional and permitted-use terms first. Free access is
often intended for evaluation or prototyping.

The proxy does not create accounts, accept terms, buy credits, verify identity,
or inspect billing accounts. Complete those steps yourself. Never paste keys
into chat or commit `.env`/private client configuration.

### New-provider configuration

Enable only providers whose accounts you have set up and approved:

```dotenv
FREE_ROUTE_EXTRA_PROVIDERS=mistral,workersai,zai,orcarouter,bazaarlink,llm7
```

For account-tier services, also assert that each credential is **not billable**.
This is an operator assertion, not a live billing check:

```dotenv
FREE_ROUTE_FREE_TIER_PROVIDERS=groq,gemini,mistral,workersai,llm7
```

Leave out accounts you have not confirmed. Remove their assertions before
upgrading or funding a balance. The proxy cannot enforce a zero-dollar cap on
a billable Mistral/Groq/Gemini/Workers AI/LLM7 account. For model-level free
contracts only, leave this setting empty and use OpenRouter, OpenCode Zen,
AIHubMix, Z.ai, OrcaRouter or BazaarLink.

Cloudflare also needs `FREE_ROUTE_WORKERSAI_ACCOUNT_ID`: the 32-character
hexadecimal account ID. Store a separate least-privilege inference token in
`WORKERSAI_API_KEY`; do not reuse the deployment API token. A Workers Paid
account hosting this proxy is **not** an eligible Workers Free inference
account. This integration calls REST; no AI binding, gateway, GPU download or
infrastructure deployment is added.

Optional server-owned priority, with established providers first:

```dotenv
FREE_ROUTE_PROVIDER_ORDER=groq,opencode,aihubmix,gemini,openrouter,mistral,workersai,zai,orcarouter,bazaarlink,llm7
```

Unlisted known providers remain fallbacks; ordering is not an enable switch.
Keep `FREE_ROUTE_EXTRA_PROVIDERS` narrow to restrict new destinations. The six
new services use reviewed seeds, not a blanket catalog import. **Refresh live
models** still enriches existing supported catalogs, not these six services.
Unknown vision capability never qualifies for image requests.

### Local and Cloudflare deployment

- Locally: configure the server environment/private `.env`, then restart it.
- Cloudflare: add inference keys as Worker **secrets** and nonsecret settings
  as Worker **variables**. This revision forwards them to the container.
  Deploy this revision and let containers restart before testing.
- Do not put keys in Wrangler source files, example JSON, or client settings.
- `/v1/free/providers` returns key **names**, enablement/attestation booleans,
  and missing setup reasons, never key values or account IDs. `ready` means
  configuration is complete, not that credentials/quota have been tested.
- `/v1/free/models` shows eligible candidates and cooldowns. Both discovery
  endpoints require a proxy key with `models` scope; generation requires `chat`.

## Public contracts checked

- [Mistral Free mode / Scale](https://github.com/mistralai/platform-docs-public/blob/main/public/admin/security-access/api-keys.md): Free mode supports evaluation/prototyping; Scale enables billing. Its [vision API](https://github.com/mistralai/platform-docs-public/blob/main/public/studio-api/conversations/vision.md) documents `mistral-small-latest` with Chat Completions.
- [Cloudflare pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/): Workers Free stops at the daily allowance; Workers Paid can bill overages. Paid-only frontier models are not seeded. [Scout vision](https://developers.cloudflare.com/workers-ai/models/llama-4-scout-17b-16e-instruct/) and [OpenAI compatibility](https://developers.cloudflare.com/workers-ai/configuration/open-ai-compatibility/) are documented.
- [Z.ai GLM-4.5 family](https://docs.z.ai/guides/llm/glm-4.5) identifies Flash as free and documents `https://api.z.ai/api/paas/v4/chat/completions`. Other GLM versions are not inferred to be free or vision-capable.
- [OrcaRouter free routing](https://docs.orcarouter.ai/routing/free-models) documents a free-only alias. `429` with `Retry-After` is a quota window; without it, the prompt is too large. The latter does not cool the whole account. [API setup](https://docs.orcarouter.ai/getting-started/quickstart) confirms `https://api.orcarouter.ai/v1`.
- [BazaarLink docs](https://bazaarlink.ai/en/docs) permit paid spillover even with `auto:free`. The proxy enforces `X-Free-Fallback: false` and ignores caller overrides. Its public free vision tier was disabled when checked. A `:free` suffix alone is not a sufficient guard here.
- [LLM7 models](https://docs.llm7.io/guides/models) distinguish general chat from paid `pro`; [limits](https://docs.llm7.io/limits) distinguish anonymous, free-token and paid access. Only an approved free-token account is admitted, not Pro, topped-up balances, or media-generation endpoints. Anonymous access is not enabled automatically.

Do not copy fixed community-list quotas into code. The pool uses quota
responses/reset headers, bounded failover and shared cooldowns. See
[pool behavior and test requests](free-model-pools.md). Each provider's access
limits and terms still apply when another provider has capacity.

## Remaining entries: not setup requirements

None of these receive prompts from the free pools. They are not certified
free simply because the supplied list calls them free.

| Entries | Treatment / reason |
| --- | --- |
| SiliconFlow | Not admitted. Its current [international catalog](https://www.siliconflow.com/models) prices Qwen3-8B above zero. China-region free models need separate verification; signup credits are not proof. |
| NVIDIA NIM | Not admitted as permanently free: [authentication](https://docs.api.nvidia.com/nim/docs/authentication), [FAQ](https://docs.api.nvidia.com/nim/docs/faq), and [developer access](https://docs.api.nvidia.com/nim/docs/setup-overview-self-hosting-vs-managed-endpoints) documentation mixes trial credits with prototyping access. Confirm account-specific entitlement first. |
| AnyAPI, ModelScope, Zhipu China, OVHcloud, ZeroLimitAI, Requesty, Free.ai, FreeTheAi, Kilo, Aion Labs, Agnes AI, Nscale | Pending review of exact chat endpoint, billing/fallback contract, eligible models, image schema and data-use terms. No inferred endpoints or keys added. |
| Hugging Face Inference Providers, DeepInfra, Vercel AI Gateway, Alibaba DashScope | Credit or region/account-dependent offers; need a hard no-paid-spillover contract. No generic credit-budget pool is implemented. |
| Together, Fireworks, Replicate, DeepSeek, Hyperbolic, Novita, Nebius, Fal, AI21, Bedrock, Azure, RunPod, Cerebras, SambaNova, Kimi API, LongCat | Supplied list describes purchases, trials, grants, limited credits or ambiguous API billing. Not automatic free fallbacks. Existing general integrations are unchanged. |
| Chutes, AINative Studio, CloudCode.ONE | Supplied list itself labels them paid-only / ended free tiers. Excluded. |
| Oriper, Glhf.chat | Listed as unreachable; not integrated or relied on. |
| Poe, Qwen Studio, Anakin, Coze | Free web chat/application credits do not prove free API inference. Not wired to these pools. |
| Cohere | Evaluation-key terms and native chat/vision compatibility need a separate integration review. Not included. |
| Black Forest Labs, Pollinations, image/video services | Generation is different from image **understanding**. Not chat fallback targets. |
| Ollama Cloud | Session/concurrency terms and authentication need review; no cloud integration added. |
| Open-weight models, local inference | Downloads are not hosted capacity. Self-hosting needs hardware and operations; no weights/packages installed. |
| 9Router, OmniRoute, LiteLLM, Portkey | Gateway software, not inference quota. MultiLLM already provides routing. |
| Chat UIs, audio, embeddings, RAG, agents, MCP, fine-tuning, prompt tools, evaluations, datasets, hosting platforms, courses, leaderboards, communities | Outside the free text/image-understanding endpoint. No account setup required. |

Start with short synthetic text and a public/synthetic image. Mock tests do
not establish live quality, speed, account eligibility or quota. Do not exhaust
real daily quotas just to test failover.
