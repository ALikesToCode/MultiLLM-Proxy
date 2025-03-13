# OpenRouter Integration Guide

This guide explains how to set up and use the OpenRouter integration with MultiLLM-Proxy.

## What is OpenRouter?

[OpenRouter](https://openrouter.ai/) is a unified API that gives you access to the latest AI models from Anthropic, Google, Meta, Mistral, OpenAI, and more. With OpenRouter, you can:

- Access 30+ top AI models through a single API
- Pay as you go with credits (no subscriptions)
- Use a single API key for all models
- Get consistent response formats across different providers

## Setting Up OpenRouter

### 1. Create an OpenRouter Account

1. Visit [OpenRouter.ai](https://openrouter.ai/) and sign up for an account
2. After signing up, navigate to your account settings
3. Create a new API key with appropriate permissions

### 2. Add Your OpenRouter API Key to MultiLLM-Proxy

Add your OpenRouter API key to the `.env` file:

```
OPENROUTER_API_KEY=your_openrouter_api_key_here
```

### 3. Restart MultiLLM-Proxy

Restart the MultiLLM-Proxy service to apply the changes:

```bash
# If running directly
python app.py

# If running with Docker
docker-compose restart
```

## Using the OpenRouter Dashboard

The OpenRouter dashboard provides a user-friendly interface to test different models and track your credit usage.

### Features

- **Model Selection**: Choose from a variety of models including GPT-4, Claude, Gemini, Llama, and more
- **Interactive Testing**: Test models with your own prompts
- **Streaming Support**: Enable streaming for real-time responses
- **Credit Tracking**: Monitor your OpenRouter credit usage
- **Response Formatting**: Responses are formatted for readability with support for code blocks and lists

### Testing Models

1. Navigate to the OpenRouter dashboard in MultiLLM-Proxy
2. Select a model from the available options
3. Enter your prompt in the text area
4. Toggle streaming on/off as needed
5. Click "Test Model" to see the response
6. Use the copy button to copy the response to your clipboard

## Using OpenRouter API Endpoints

MultiLLM-Proxy provides OpenAI-compatible endpoints for OpenRouter:

### Chat Completions

```bash
curl -X POST "http://localhost:1400/openrouter/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY" \
  -d '{
    "model": "anthropic/claude-3-opus",
    "messages": [
      {
        "role": "user",
        "content": "Explain quantum computing in simple terms"
      }
    ],
    "stream": false
  }'
```

### Available Models

You can use any model supported by OpenRouter. Some popular options include:

- `openai/gpt-4`
- `anthropic/claude-3-opus`
- `anthropic/claude-3-sonnet`
- `anthropic/claude-3-haiku`
- `google/gemini-pro`
- `meta-llama/llama-3-70b-instruct`
- `mistralai/mistral-7b-instruct`
- `cohere/command-r`
- `perplexity/pplx-7b-online`

For a complete list of models, visit the [OpenRouter Models page](https://openrouter.ai/models).

## Troubleshooting

### API Key Issues

If you encounter authentication errors:

1. Verify your OpenRouter API key is correctly set in the `.env` file
2. Check that your OpenRouter account has sufficient credits
3. Ensure your API key has the necessary permissions

### Model Availability

Some models may be temporarily unavailable due to:

- Provider maintenance
- Rate limiting
- Model deprecation

Check the OpenRouter status page for any known issues.

### Credit Usage

OpenRouter operates on a credit system:

- Different models have different costs per token
- Monitor your credit usage in the dashboard
- Add more credits to your OpenRouter account when running low

## Additional Resources

- [OpenRouter Documentation](https://openrouter.ai/docs)
- [OpenRouter Discord Community](https://discord.gg/openrouter)
- [OpenRouter GitHub](https://github.com/openrouter-dev) 