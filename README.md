# MultiLLM Proxy

A unified API proxy service for multiple LLM providers (OpenAI, Cerebras, X.AI, and Google AI) with a beautiful dashboard interface.

## Quick Setup

```bash
# Clone and setup
git clone https://github.com/ALikesToCode/MultiLLM-Proxy.git
cd multillm-proxy
chmod +x setup.sh
./setup.sh
```

## Configuration

Edit `.env` file with your API keys:
```env
OPENAI_API_KEY=your-openai-api-key
CEREBRAS_API_KEY=your-cerebras-api-key
XAI_API_KEY=your-xai-api-key
GOOGLE_APPLICATION_CREDENTIALS=path/to/credentials.json
```

## Run

```bash
# Activate virtual environment (if not already activated)
source venv/bin/activate

# Start the application
python app.py
```

Visit `http://localhost:1400` to access the dashboard.

## Features

- 🔄 **Unified API**: Single endpoint for multiple LLM providers
- 🔑 **Secure**: Environment-based API key management
- 🚦 **Monitoring**: Real-time status updates
- 🛡️ **Protected**: Rate limiting and error handling
- 📊 **Dashboard**: Dark/light theme, responsive design
- 🚀 **Optimized**: Response caching and compression

## Endpoints

- OpenAI: `/openai/v1/chat/completions`
- Cerebras: `/cerebras/v1/chat/completions`
- X.AI: `/xai/v1/chat/completions`
- Google AI: `/googleai/predict`

## Development

```bash
# Run in development mode
export FLASK_ENV=development
python app.py
```

## Rate Limits

Default limits per minute:
- OpenAI: 60
- Cerebras: 40
- X.AI: 50
- Google AI: 30
- Default: 100

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| SERVER_HOST | Host address | localhost |
| SERVER_PORT | Port number | 1400 |
| FLASK_ENV | Environment | production |
| *_API_KEY | Provider keys | None |

## Troubleshooting

1. **Rate Limit (429)**
   - Reduce request frequency
   - Check `rate_limit_service.py`

2. **Auth Failed (500)**
   - Verify API keys in `.env`
   - Check permissions

3. **Provider Down (503)**
   - Check provider status
   - Verify connectivity

## Support

- 📖 [Wiki](https://github.com/ALikesToCode/MultiLLM-Proxy/wiki)
- 🐛 [Issues](https://github.com/ALikesToCode/MultiLLM-Proxy/issues)
- 💬 [Discussions](https://github.com/ALikesToCode/MultiLLM-Proxy/discussions)

## License

[MIT License](LICENSE)