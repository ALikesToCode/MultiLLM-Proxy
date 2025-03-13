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
    Handle Gemini requests with safety settings disabled
    """
    logger.info(f"Handling {api_provider} request to {url}")
    
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
        
        # Add API key to params
        if not params:
            params = {}
        params['key'] = api_key
            
        # Process the request data to disable safety settings
        if request_data:
            # Make sure we have safety settings that disable content filtering
            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
            ]
            
            # Overwrite any existing safety settings
            request_data["safetySettings"] = safety_settings
            
            # Add web search capability if needed
            if 'webSearch' not in request_data and api_provider == 'gemini':
                request_data["webSearch"] = True
                request_data["webSearchSpec"] = {"disableSearch": False}
            
            # Re-encode the modified data
            data = json.dumps(request_data).encode('utf-8')
            headers["Content-Length"] = str(len(data))
            logger.info(f"Modified {api_provider} request data to disable safety settings")
        
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
        
    except Exception as e:
        error_msg = f"Error in _handle_gemini_request: {str(e)}"
        logger.error(error_msg)
        if isinstance(e, APIError):
            raise
        raise APIError(error_msg, status_code=500)
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
- Automatic disabling of safety settings to prevent content filtering
- Web search capability for Gemini models
- API key management through environment variables 