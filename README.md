# MultiLLM Proxy

A unified API proxy service for multiple LLM providers (OpenAI, Cerebras, X.AI, and Google AI) with a beautiful dashboard interface.

## Quick Start

1. **Clone and Setup**
```bash
# Clone repository
git clone https://github.com/yourusername/multillm-proxy.git
cd multillm-proxy

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
npm install
```

2. **Configure Environment**
```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your API keys
OPENAI_API_KEY=your-openai-api-key
CEREBRAS_API_KEY=your-cerebras-api-key
XAI_API_KEY=your-xai-api-key
GOOGLE_APPLICATION_CREDENTIALS=path/to/credentials.json
```

3. **Build Frontend Assets**
```bash
npm run build
```

4. **Run the Application**
```bash
python app.py
```

Visit `http://localhost:1400` to access the dashboard.

## Features

- 🔄 **Unified API Access**: Single endpoint for multiple LLM providers
- 🔑 **Secure Key Management**: Environment-based API key handling
- 🚦 **Real-time Monitoring**: Live status updates for all providers
- 🛡️ **Built-in Protection**: Rate limiting and error handling
- 📊 **Modern Dashboard**: Dark/light theme, responsive design
- 🚀 **Performance Optimized**: Response caching and compression

## Supported Endpoints

- OpenAI: `/openai/v1/chat/completions`
- Cerebras: `/cerebras/v1/chat/completions`
- X.AI: `/xai/v1/chat/completions`
- Google AI: `/googleai/predict`

## Development

```bash
# Run in development mode
export FLASK_ENV=development
python app.py

# Watch frontend changes
npm run dev
```

## Docker Deployment

```bash
# Build image
docker build -t multillm-proxy .

# Run container
docker run -p 1400:1400 \
  --env-file .env \
  multillm-proxy
```

## Configuration

### Rate Limits (per minute)
- OpenAI: 60 requests
- Cerebras: 40 requests
- X.AI: 50 requests
- Google AI: 30 requests
- Default: 100 requests

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| SERVER_HOST | Host address | localhost |
| SERVER_PORT | Port number | 1400 |
| FLASK_ENV | Environment mode | production |
| *_API_KEY | Provider API keys | None |

## Project Structure
```
multillm-proxy/
├── app.py                # Main application
├── services/            # Core services
│   ├── auth_service.py   # Authentication
│   ├── cache_service.py  # Response caching
│   ├── proxy_service.py  # Request proxying
│   └── rate_limit.py     # Rate limiting
├── static/              # Frontend assets
│   ├── css/             # Stylesheets
│   └── js/              # JavaScript
└── templates/           # HTML templates
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Troubleshooting

### Common Issues

1. **Rate Limit Exceeded (429)**
   - Reduce request frequency
   - Check rate limits in `rate_limit_service.py`

2. **Authentication Failed (500)**
   - Verify API keys in `.env`
   - Check key permissions

3. **Provider Unavailable (503)**
   - Confirm provider status
   - Check network connectivity

## License

[MIT License](LICENSE) - feel free to use and modify for your needs.

## Support

- 📖 [Documentation](https://github.com/yourusername/multillm-proxy/wiki)
- 🐛 [Issue Tracker](https://github.com/yourusername/multillm-proxy/issues)
- 💬 [Discussions](https://github.com/yourusername/multillm-proxy/discussions)