# Setting Up Gemini API with MultiLLM-Proxy

This guide will help you set up the Gemini API integration for MultiLLM-Proxy.

## 1. Get a Gemini API Key

1. Go to [Google AI Studio](https://aistudio.google.com)
2. Sign in with your Google account
3. Click on "Get API key" in the left-hand menu
4. Create a new API key (API keys start with "AIza...")
5. Copy your API key

## 2. Add Your API Key to the MultiLLM-Proxy

Add the following line to your `.env` file:

```
GEMINI_API_KEY=AIza...your-key-here...
```

## 3. Testing Your Setup

Test your setup using the provided test script:

```bash
./tests/test_gemini.sh
```

Or use curl directly:

```bash
# OpenAI-compatible endpoint
curl -X POST "http://localhost:1400/gemini/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY" \
  -d '{"model": "gemini-2.5-flash", "messages": [{"role": "user", "content": "Hello"}], "stream": true}'

# Direct Gemini API endpoint
curl -X POST "http://localhost:1400/gemini/v1beta/models/gemini-2.5-flash:generateContent" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY" \
  -d '{"contents": [{"parts": [{"text": "Hello"}]}], "stream": true}'
```

## 4. Available Gemini Models

The MultiLLM-Proxy model registry includes current Gemini text models, including:

- `gemini-3.1-pro-preview` - Advanced preview reasoning and coding model
- `gemini-3-flash-preview` - Frontier preview model optimized for speed and scale
- `gemini-3.1-flash-lite-preview` - Cost-efficient preview model for high-volume tasks
- `gemini-2.5-pro` - Stable advanced reasoning model
- `gemini-2.5-flash` - Stable price-performance model
- `gemini-2.5-flash-lite` - Stable low-latency, cost-efficient model
- `gemma-2-9b` - Open model from Google
- `gemma-3-27b` - Open model from Google

Check the official Gemini model documentation for newly released, preview, or deprecated model IDs:
https://ai.google.dev/gemini-api/docs/models

## 5. Troubleshooting

If you see an error like this:

```json
{
  "error": {
    "message": "Authentication failed for gemini. The API key is invalid or does not have access to the requested model.",
    "solution": "Please create a valid API key from Google AI Studio (https://aistudio.google.com) and update your .env file with GEMINI_API_KEY=your-key",
    "details": "Gemini API keys should begin with 'AIza'. The admin API key cannot be used directly - you need to obtain a specific Gemini API key and add it to your .env file."
  }
}
```

Make sure:
1. You have a valid Gemini API key in your `.env` file
2. The API key starts with "AIza"
3. You've restarted the proxy service after adding/changing the key

## 6. Important Notes

- Gemini API keys must start with "AIza" - this is different from the MultiLLM-Proxy admin key
- The admin API key is used for authenticating with the proxy service, but a separate Gemini API key is needed for the actual Gemini API calls
- For Gemma models, use the same API key from Google AI Studio
