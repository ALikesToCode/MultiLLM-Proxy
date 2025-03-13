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
- **PaLM API**: Google's PaLM language models
- **Nineteen AI**: High-performance inference for open-source models with streaming support

## Configuration Options

The proxy server supports extensive configuration through environment variables and the config.py file:

- Custom timeouts per provider
- Retry mechanisms with configurable backoff
- Token rate limiting
- Model-specific parameter handling
- Development and production environment settings

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
