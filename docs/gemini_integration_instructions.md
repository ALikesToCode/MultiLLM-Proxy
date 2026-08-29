# Gemini and Gemma Integration Instructions

This document provides instructions for adding support for Google's Gemini and Gemma models to the MultiLLM-Proxy.

## 1. Update the ProxyService class

Open `services/proxy_service.py` and make the following changes:

### a. Add the Gemini handler condition to the make_request method

Find the `make_request` method and add this condition after the `googleai` condition:

```python
elif api_provider == "gemini" or api_provider == "gemma":
    return cls._handle_gemini_request(
        method, url, headers, params, data, json.loads(data) if data else {}, use_cache, api_provider
    )
```

### b. Add the Gemini handler method

Add this method before the `shutdown` method:

```python
@classmethod
def _handle_gemini_request(
    cls,
    method: str,
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    data: bytes,
    request_data: Dict[str, Any],
    use_cache: bool,
    api_provider: str,
) -> requests.Response:
    """
    Handle Gemini requests while preserving caller safety settings
    """
    logger.info("Handling %s request", api_provider)
    
    try:
        # Extract API key from URL parameters and rebuild the URL without it
        api_key = None
        
        # Check if key is in params
        if params and 'key' in params:
            api_key = params.pop('key')
            logger.info(f"Found API key in URL parameters for {api_provider}")
        
        # If no key in params, check if it's in the URL
        elif '?key=' in url:
            base_url, query = url.split('?', 1)
            query_params = {}
            for param in query.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    if k == 'key':
                        api_key = v
                        logger.info(f"Found API key in URL for {api_provider}")
                    else:
                        query_params[k] = v
            
            # Rebuild URL without the key
            url = base_url
            if query_params:
                url += '?' + '&'.join([f"{k}={v}" for k, v in query_params.items()])
        
        # If still no API key, get from auth service
        if not api_key:
            api_key = AuthService.get_api_key(api_provider)
            if not api_key:
                raise APIError(f"No API key found for {api_provider}", status_code=401)
            logger.info(f"Using API key from AuthService for {api_provider}")
        
        # Keep credentials out of URLs and preserve any caller-provided
        # safetySettings instead of weakening them inside the proxy.
        headers["x-goog-api-key"] = api_key

        if request_data:
            # Re-encode the caller's request without changing its safety policy.
            data = json.dumps(request_data).encode('utf-8')
            headers["Content-Length"] = str(len(data))
            logger.info("Prepared %s request data", api_provider)
        
        # Make the request with the modified data
        return cls._make_base_request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            api_provider=api_provider,
            use_cache=use_cache
        )
        
    except Exception as error:
        logger.error(
            "Gemini request failed (%s)",
            type(error).__name__,
        )
        if isinstance(error, APIError):
            raise
        raise APIError("Gemini request failed", status_code=500)
```

## 2. Testing the Integration

After making these changes, you can test the integration using the following curl command:

```bash
curl -X POST "http://localhost:1400/gemini/models/gemini-2.0-flash:generateContent" \
  -H "Content-Type: application/json" \
  -d '{
    "contents": [{
      "parts":[{"text": "Explain how AI works"}]
    }]
  }' -v
```

For Gemma models:

```bash
curl -X POST "http://localhost:1400/gemma/models/gemma-2-9b:generateContent" \
  -H "Content-Type: application/json" \
  -d '{
    "contents": [{
      "parts":[{"text": "Explain how AI works"}]
    }]
  }' -v
```

## 3. Features Implemented

- Support for Gemini models via the Generative Language API
- Support for Gemma models via the Generative Language API
- Preservation of caller-provided safety settings
- Opt-in web search capability for Gemini models
- API key management through environment variables
