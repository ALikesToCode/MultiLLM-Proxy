# Setting Up OpenRouter with MultiLLM-Proxy

This guide will help you set up OpenRouter integration for MultiLLM-Proxy. OpenRouter provides a unified API that gives you access to hundreds of AI models through a single endpoint.

## 1. Get an OpenRouter API Key

1. Go to [OpenRouter](https://openrouter.ai)
2. Sign up for an account or log in
3. Navigate to the API Keys section
4. Create a new API key
5. Copy your API key

## 2. Add Your API Key to the MultiLLM-Proxy

Add the following line to your `.env` file:

```
OPENROUTER_API_KEY=your-openrouter-api-key-here
```

## 3. Configure OpenRouter Site Info (Optional)

For better analytics on OpenRouter, you can add these optional settings to your `.env` file:

```
OPENROUTER_SITE_URL=your-website-url
OPENROUTER_APP_NAME=Your App Name
```

These will be passed as the `HTTP-Referer` and `X-Title` headers and allow your app to appear on OpenRouter's leaderboards.

## 4. Testing Your Setup

Test your setup using curl:

```bash
# OpenAI-compatible endpoint
curl -X POST "http://localhost:1400/openrouter/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY" \
  -d '{
    "model": "openai/gpt-4o", 
    "messages": [
      {"role": "user", "content": "What is the meaning of life?"}
    ]
  }'

# Test with streaming
curl -X POST "http://localhost:1400/openrouter/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY" \
  -d '{
    "model": "anthropic/claude-3-opus", 
    "messages": [
      {"role": "user", "content": "Explain quantum computing in simple terms"}
    ],
    "stream": true
  }'
```

## 5. Available Models

OpenRouter provides access to hundreds of models from providers like:

- OpenAI (e.g., `openai/gpt-4o`, `openai/gpt-4-turbo`)
- Anthropic (e.g., `anthropic/claude-3-opus`, `anthropic/claude-3-sonnet`)
- Meta (e.g., `meta/llama-3-70b-instruct`)
- Google (e.g., `google/gemini-pro`)
- Mistral (e.g., `mistralai/mistral-large-latest`)

For a complete list of available models, you can query:

```bash
curl -X GET "http://localhost:1400/openrouter/models" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY"
```

## 6. Cost Management

OpenRouter is a paid service that charges based on your usage. You can check your remaining credits with:

```bash
curl -X GET "http://localhost:1400/openrouter/auth/key" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY"
```

## 7. Troubleshooting

If you see an error like this:

```json
{
  "error": {
    "message": "Authentication failed for OpenRouter: Invalid API key",
    "solution": "Please create a valid API key from OpenRouter (https://openrouter.ai) and update your .env file with OPENROUTER_API_KEY=your-key",
    "details": "The admin API key cannot be used directly - you need to obtain a specific OpenRouter API key and add it to your .env file."
  }
}
```

Make sure:
1. You have a valid OpenRouter API key in your `.env` file
2. You've restarted the proxy service after adding/changing the key
3. Your OpenRouter account has sufficient credits

## 8. Additional Resources

- [OpenRouter Documentation](https://openrouter.ai/docs)
- [OpenRouter Pricing](https://openrouter.ai/pricing)
- [OpenRouter Discord Community](https://discord.gg/openrouter) 