# Free provider signup links

Account and API-key pages for the services supported by the free pools.
Create accounts only for providers you want to enable; all eleven are optional.
These links are not a guarantee of free access on every account or model.

| Service | Signup / account page | Server secret name |
| --- | --- | --- |
| Groq | [Create account](https://console.groq.com/authenticate/signup); then [API keys](https://console.groq.com/keys) | `GROQ_API_KEY` |
| OpenRouter | [OpenRouter](https://openrouter.ai/) → Sign up; then [API keys](https://openrouter.ai/settings/keys) | `OPENROUTER_API_KEY` |
| Gemini | [Google AI Studio — API keys](https://aistudio.google.com/apikey) | `GEMINI_API_KEY` |
| AIHubMix | [AIHubMix console](https://console.aihubmix.com/) | `AIHUBMIX_API_KEY` |
| Mistral | [Mistral console](https://console.mistral.ai/) → Sign up | `MISTRAL_API_KEY` |
| Cloudflare Workers AI | [Create Cloudflare account](https://dash.cloudflare.com/sign-up) | `WORKERSAI_API_KEY` |
| Z.ai | [Developer API-key page](https://z.ai/manage-apikey/apikey-list) | `ZAI_API_KEY` |
| OrcaRouter | [Register](https://www.orcarouter.ai/register) | `ORCAROUTER_API_KEY` |
| BazaarLink | [BazaarLink](https://bazaarlink.ai/) | `BAZAARLINK_API_KEY` |
| LLM7 | [LLM7 dashboard](https://dash.llm7.io/) | `LLM7_API_KEY` |
| OpenCode Zen | [Zen account](https://opencode.ai/zen) | `OPENCODE_API_KEY` |

OpenCode Zen is already integrated. Keep its existing key if configured;
`OPENCODE_GO_API_KEY` takes precedence over `OPENCODE_API_KEY` when both exist.
Account pages may redirect to a login or registration form.

## Before enabling a provider

- Save provider keys only in the server's private `.env` or Worker secrets.
  Never paste them into chat, client JSON, this document, or a Git commit.
  Clients authenticate with a MultiLLM proxy key, not these provider keys.
- Use free access for this pool. Do not buy credits or upgrade an account just
  to test it; a billable account can incur charges even with a free-tier model.
- Groq, Gemini, Mistral, Workers AI, and LLM7 require explicit confirmation
  that the configured account is not billable. This is not a live billing check.
- Workers AI also needs `FREE_ROUTE_WORKERSAI_ACCOUNT_ID`. Use a separate
  account-scoped inference token, not the proxy's deployment token.
- Adding a key alone does not enable the six additional providers. Configure
  the opt-in and free-account settings in the [setup checklist](free-provider-setup.md).
  Enabling a provider permits fallback to send it the conversation and images.

After configuration and deployment, `GET /v1/free/providers` reports missing
setup requirements without returning secret values. It requires a proxy key
with `models` scope; readiness does not establish live quota or credential validity.
