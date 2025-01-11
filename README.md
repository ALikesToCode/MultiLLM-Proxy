# MultiLLM Proxy

A powerful proxy server that provides a unified interface for multiple LLM providers including OpenAI, Groq, Together AI, Google AI, and more.

## Features

- 🔒 Secure authentication system with user management
- 🔑 Universal API key support for all providers
- 🔄 Automatic token-based rate limiting
- 🌐 Support for multiple LLM providers:
  - OpenAI
  - Groq
  - Together AI
  - Google AI
  - Cerebras
  - XAI
- 🎨 Beautiful web dashboard with dark mode support
- 🔄 Real-time status monitoring
- 📊 Request statistics and monitoring
- 🚀 Streaming support for compatible providers

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/MultiLLM-Proxy.git
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

### Optional Provider-Specific Keys:
```env
# Provider API Keys (Optional - if you want to use different keys for different providers)
OPENAI_API_KEY=your-openai-api-key
CEREBRAS_API_KEY=your-cerebras-api-key
XAI_API_KEY=your-xai-api-key
GOOGLE_APPLICATION_CREDENTIALS=path-to-your-google-credentials.json

# Multiple Groq API keys for token-based rate limiting
GROQ_API_KEY_1=your-first-groq-api-key
GROQ_API_KEY_2=your-second-groq-api-key

# Together AI API key
TOGETHER_API_KEY=your-together-api-key
```

5. Run the server:
```bash
python app.py
```

The server will start at `http://localhost:1400` (or your configured host/port).

## Authentication

The proxy uses a secure authentication system with the following features:

- Session-based authentication
- JWT token generation for API access
- Universal API key system
- Secure password hashing
- CSRF protection

### Login

1. Access the dashboard at `http://localhost:1400`
2. Login with your configured credentials:
   - Username: Value of `ADMIN_USERNAME` (defaults to "admin")
   - API Key: Value of `ADMIN_API_KEY`

### API Usage

After authentication, you can use the proxy with any supported provider. The universal API key will be used for all providers.

Example using curl:
```bash
curl -X POST "http://localhost:1400/openai/v1/chat/completions" \
  -H "Authorization: Bearer your-universal-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Rate Limiting

- Default rate limit: 500 requests per minute per provider
- Groq-specific token limit: 6000 tokens per minute per API key
- Configurable rate limits in `config.py`

## Development

### Running Tests
```bash
pytest
```

### Code Style
```bash
black .
flake8
```

## Security Considerations

1. Always use strong, unique values for:
   - `FLASK_SECRET_KEY`
   - `JWT_SECRET`
   - `ADMIN_API_KEY`

2. In production:
   - Use HTTPS
   - Set secure cookie flags
   - Configure proper CORS settings
   - Use a production-grade server (e.g., gunicorn)
   - Use a proper database for user management

## License

MIT License - See LICENSE file for details