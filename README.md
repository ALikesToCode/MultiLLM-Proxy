# MultiLLM Proxy

A powerful proxy server that provides a unified interface for multiple LLM providers. This project simplifies the integration and management of various AI models by providing a single, consistent API endpoint while handling provider-specific requirements behind the scenes.

## Features

- 🔒 Secure authentication system with user management and JWT tokens
- 🔑 Universal API key support with provider-specific key management
- 🔄 Automatic token-based rate limiting and request distribution
- 🌐 Support for multiple LLM providers:
  - OpenAI (GPT models)
  - Groq (ultra-fast inference)
  - Together AI
  - Google AI (Gemini models)
  - Cerebras
  - X.AI (formerly Twitter)
  - Azure AI
  - Scaleway
  - Hyperbolic
  - SambaNova
  - OpenRouter
  - Xiaomi MiMo Token Plan
  - NanoGPT
  - Codex Everywhere
  - LinkAPI
  - PaLM API
  - Nineteen AI
- 🎨 Beautiful web dashboard with dark mode support
- 🔄 Real-time status monitoring and provider health checks
- 📊 Request statistics and monitoring
- 🚀 Streaming support for compatible providers
- ⚡ Configurable timeouts and retry mechanisms per provider
- 🔄 Automatic parameter handling and compatibility checks

## Setup

1. Clone the repository:
```bash
git clone https://github.com/ALikesToCode/MultiLLM-Proxy.git
cd MultiLLM-Proxy
```

2. Create a virtual environment and install dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Copy the example environment file and configure your settings:
```bash
cp .env.example .env
```

4. Configure the required environment variables in `.env`:

### Required Configuration:
```env
# Server Configuration
SERVER_HOST=localhost
SERVER_PORT=1400

# Authentication (Required)
ADMIN_USERNAME=admin
ADMIN_API_KEY=your-universal-api-key
FLASK_SECRET_KEY=your-flask-secret-key
JWT_SECRET=your-jwt-secret-key
```

### Provider-Specific Configuration:
```env
# OpenAI
OPENAI_API_KEY=your-openai-api-key

# Cerebras
CEREBRAS_API_KEY=your-cerebras-api-key

# X.AI
XAI_API_KEY=your-xai-api-key

# Google AI
GOOGLE_APPLICATION_CREDENTIALS=path-to-your-google-credentials.json

# Groq (supports multiple keys for rate limiting)
GROQ_API_KEY_1=your-first-groq-api-key
GROQ_API_KEY_2=your-second-groq-api-key

# Together AI
TOGETHER_API_KEY=your-together-api-key

# Azure AI
AZURE_API_KEY=your-azure-api-key

# Scaleway
SCALEWAY_API_KEY=your-scaleway-api-key

# Hyperbolic
HYPERBOLIC_API_KEY=your-hyperbolic-api-key

# SambaNova
SAMBANOVA_API_KEY=your-sambanova-api-key

# OpenRouter
OPENROUTER_API_KEY=your-openrouter-api-key

# Xiaomi MiMo Token Plan
MIMO_API_KEY=your-mimo-token-plan-api-key

# NanoGPT
NANOGPT_API_KEY=your-nanogpt-api-key

# Codex Everywhere (preferred key name)
CODEX_EASY_API_KEY=your-codex-everywhere-key
# Optional compatibility alias: CODEX_API_KEY=your-codex-everywhere-key

# LinkAPI (preferred key name)
LINKAPI_KEY=your-linkapi-key

# Optional Cloudflare Worker fast-path override; Flask uses the global endpoint
LINKAPI_BASE_URL=https://api.linkapi.ai

# PaLM API
PALM_API_KEY=your-palm-api-key

# Nineteen AI
NINETEEN_API_KEY=your-nineteen-api-key
```

5. Run the server:
```bash
python app.py
```

The server will start at `http://localhost:1400` (or your configured host/port).

## Usage

### Authentication

The proxy uses a secure authentication system with:
- Session-based authentication for web dashboard
- JWT token generation for API access
- Universal API key system
- Secure password hashing
- CSRF protection

### API Endpoints

Each provider is accessible through their respective endpoints:

```bash
# OpenAI-compatible endpoint
curl -X POST "http://localhost:1400/openai/v1/chat/completions" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Groq endpoint
curl -X POST "http://localhost:1400/groq/openai/v1/chat/completions" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3-70b-8192",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### Provider Endpoints

Quick reference for all provider endpoint URLs:

```plaintext
# OpenAI
http://localhost:1400/openai/v1/chat/completions

# Groq
http://localhost:1400/groq/openai/v1/chat/completions

# Together AI
http://localhost:1400/together/v1/chat/completions

# Google AI (Gemini)
http://localhost:1400/googleai/predict

# Cerebras
http://localhost:1400/cerebras/v1/chat/completions

# X.AI
http://localhost:1400/xai/v1/chat/completions

# Azure AI
http://localhost:1400/azure/v1/chat/completions

# Scaleway
http://localhost:1400/scaleway/chat/completions

# Hyperbolic
http://localhost:1400/hyperbolic/chat/completions

# SambaNova
http://localhost:1400/sambanova/chat/completions
http://localhost:1400/sambanova/completions

# OpenRouter
http://localhost:1400/openrouter/chat/completions
http://localhost:1400/openrouter/models

# Xiaomi MiMo Token Plan
http://localhost:1400/mimo/chat/completions

# NanoGPT
http://localhost:1400/nanogpt/v1/chat/completions
http://localhost:1400/nanogpt/v1/models?detailed=true

# Codex Everywhere OpenAI-compatible routes
http://localhost:1400/codex-easy/v1/models
http://localhost:1400/codex-easy/v1/responses
http://localhost:1400/codex-easy/v1/chat/completions
http://localhost:1400/codex-easy/v1/images/*

# LinkAPI native and OpenAI-compatible routes
http://localhost:1400/linkapi/v1/messages
http://localhost:1400/linkapi/v1/responses
http://localhost:1400/linkapi/v1/chat/completions
http://localhost:1400/linkapi/v1beta/models/{model}:generateContent

# PaLM
http://localhost:1400/palm/models/chat-bison-001:generateText

# Nineteen AI
http://localhost:1400/nineteen/v1/completions
```

For detailed usage examples with headers and request bodies, refer to the API Endpoints section above.

### Provider-Specific Features

- **OpenAI**: Full support for chat completions, embeddings, and function calling
- **Groq**: Ultra-fast inference with token-based rate limiting
- **Google AI**: Support for Gemini models and multimodal tasks
- **Together AI**: Access to various open-source models
- **Cerebras**: Text generation and chat capabilities
- **X.AI**: Access to X-1 and other models
- **Azure AI**: Support for Azure-hosted models
- **SambaNova**: Text generation with streaming support
- **OpenRouter**: Gateway to multiple AI providers
- **Xiaomi MiMo Token Plan**: MiMo-V2.5-Pro through the SGP OpenAI-compatible endpoint
- **NanoGPT**: OpenAI-compatible chat, streaming, model catalog, embeddings, images, audio, memory, and search via `/nanogpt/v1/*`; use `/nanogpt/v1/models?detailed=true` before selecting model IDs
- **Codex Everywhere**: Raw OpenAI Responses, Chat Completions, key-group-specific model discovery, and conditional image routes under `/codex-easy/v1/*`
- **LinkAPI**: Native Claude Messages, Gemini `generateContent`, OpenAI Responses, and OpenAI-compatible routes under `/linkapi/*`; consult LinkAPI's live pricing/model page instead of relying on a hard-coded model list
- **PaLM API**: Google's PaLM language models
- **Nineteen AI**: High-performance inference for open-source models with streaming support

### Codex Everywhere OpenAI fast path

Cloudflare serves `/codex-easy/*` directly from the Worker without waking the Flask Container. The upstream is fixed to `https://codex-easy.ai`. Configure the preferred `CODEX_EASY_API_KEY` Worker secret; the existing `CODEX_API_KEY` name remains a fallback alias.

Choose the deployed base URL according to what the client appends:

| Client behavior | Proxy base URL |
| --- | --- |
| Client appends `/v1` itself, including Codex Responses clients | `$PROXY_BASE_URL/codex-easy` |
| Client expects a base URL that already ends in `/v1`, including many Hermes and OpenAI-compatible setups | `$PROXY_BASE_URL/codex-easy/v1` |

Direct routes are:

| Operation | Proxy route | Caller authentication |
| --- | --- | --- |
| Key-group model catalog | `$PROXY_BASE_URL/codex-easy/v1/models` | `Authorization: Bearer $ADMIN_API_KEY` |
| OpenAI Responses | `$PROXY_BASE_URL/codex-easy/v1/responses` | `Authorization: Bearer $ADMIN_API_KEY` |
| Chat Completions | `$PROXY_BASE_URL/codex-easy/v1/chat/completions` | `Authorization: Bearer $ADMIN_API_KEY` |
| Images | `$PROXY_BASE_URL/codex-easy/v1/images/*` | `Authorization: Bearer $ADMIN_API_KEY` |

The Worker verifies the caller against `ADMIN_API_KEY`, removes that credential, and authenticates upstream with `CODEX_EASY_API_KEY` or its `CODEX_API_KEY` alias. The direct path is admin-only and bypasses Flask dashboard-user authentication, application-level request-size checks, RPM/TPM/daily limits, Flask request/rate-limit accounting, and request metrics. Use the Container-backed `/v1/responses` or `/v1/chat/completions` route with a `codex-easy:<model>` model ID when those controls are required.

Model catalogs are specific to the purchased API-key group. Query `/codex-easy/v1/models` before selecting a model. The `grok-4.5` requests below demonstrate current Responses and Chat request shapes only; use the exact model ID returned for your key group:

```bash
curl "$PROXY_BASE_URL/codex-easy/v1/responses" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"grok-4.5","reasoning":{"effort":"high"},"prompt_cache_key":"conversation-123","input":"Explain this repository","stream":true}'

curl "$PROXY_BASE_URL/codex-easy/v1/chat/completions" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "X-Grok-Conv-Id: conversation-123" \
  -H "Content-Type: application/json" \
  -d '{"model":"grok-4.5","reasoning_effort":"high","messages":[{"role":"user","content":"Explain this repository"}],"stream":true}'
```

Request and response bytes are passed through unchanged, including native SSE and multipart/image bodies. Both raw OpenAI fast paths, `/codex-easy/v1/*` and `/linkapi/v1/*`, preserve a Responses `prompt_cache_key` in the request body and forward the Chat `X-Grok-Conv-Id` header. For Grok requests, [xAI's prompt-caching guidance](https://docs.x.ai/developers/advanced-api-usage/prompt-caching/maximizing-cache-hits) recommends a stable `prompt_cache_key` for Responses or `x-grok-conv-id` for Chat to improve cache routing. These fields do not guarantee a cache hit; caching remains an upstream behavior and stable request prefixes still matter.

`/v1/images/*` works only for image-generation key groups. Generation POSTs are single-attempt: the proxy never retries them and does not provide idempotency. Retry only when the selected upstream endpoint explicitly documents an idempotency guarantee.

### LinkAPI native fast path

On Cloudflare, requests under `/linkapi/*` run directly in the Worker and do not wake the Flask Container. Use your deployed Worker origin as `PROXY_BASE_URL`:

| Client protocol | Proxy URL | Caller authentication |
| --- | --- | --- |
| Claude Messages | `$PROXY_BASE_URL/linkapi/v1/messages` | `x-api-key: $ADMIN_API_KEY` plus `anthropic-version` |
| OpenAI Responses | `$PROXY_BASE_URL/linkapi/v1/responses` | `Authorization: Bearer $ADMIN_API_KEY` |
| OpenAI compatible | `$PROXY_BASE_URL/linkapi/v1/chat/completions` | `Authorization: Bearer $ADMIN_API_KEY` |
| Gemini native | `$PROXY_BASE_URL/linkapi/v1beta/models/{model}:generateContent` | Prefer `x-goog-api-key: $ADMIN_API_KEY`; `?key=$ADMIN_API_KEY` is compatibility-only |

The Worker validates the caller against `ADMIN_API_KEY`, removes that credential, and authenticates upstream with `LINKAPI_KEY`. `LINKAPI_BASE_URL` is restricted to the allowlisted official LinkAPI hosts; arbitrary HTTPS origins are rejected.

This fast path is `ADMIN_API_KEY`-only and intentionally bypasses Flask dashboard-user authentication, application-level request-size checks, RPM/TPM/daily limits, Flask request/rate-limit accounting, and request metrics. When those controls are required, use the Container-backed `/v1/chat/completions` endpoint with a `linkapi:<model>` model ID.

Gemini clients should prefer the `x-goog-api-key` header. Query-string `?key=` authentication is supported for compatibility, but it places the caller key in the URL, where clients and intermediaries may retain it, even though automatic Worker invocation logs are disabled.

Native request and response bodies, including SSE event types and bytes, are streamed without compatibility translation. On the raw OpenAI routes, the Worker leaves `prompt_cache_key` in Responses bodies and forwards the Chat `X-Grok-Conv-Id` header; for Grok, these are the request shapes recommended by xAI for cache routing, not a proxy or provider-level cache guarantee. The proxy never retries generation POSTs and does not provide idempotency, because repeating a request can duplicate work and billing. A caller should retry only when the selected upstream protocol and endpoint explicitly document an idempotency guarantee, using its own retry policy.

## Configuration Options

The proxy server supports extensive configuration through environment variables and the config.py file:

- Custom timeouts per provider
- Retry mechanisms with configurable backoff
- Token rate limiting
- Model-specific parameter handling
- Development and production environment settings

## Documentation

Additional setup and deployment notes are organized under [`docs/`](docs/README.md).

## Testing

Python tests live in `tests/` and can be run with:

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

The Cloudflare Worker test suite uses Node's built-in runner:

```bash
node --test tests/test_cloudflare_worker.mjs
```

## Security

- All API keys are securely handled and never exposed
- Request validation and sanitization
- Rate limiting and quota management
- Secure session handling
- CSRF protection

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
