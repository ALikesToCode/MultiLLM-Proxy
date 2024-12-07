import json
import logging
import requests
from typing import Optional, Dict, Any, Tuple, List
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import tiktoken
from error_handlers import APIError
from config import Config
from services.cache_service import CacheService
from services.rate_limit_service import RateLimitService

logger = logging.getLogger(__name__)

class ProxyService:
    """
    The ProxyService class handles making proxied requests to various API providers,
    applying caching, rate limits, and token usage rules as needed. With this updated
    logic, if any provider takes more than 2 seconds to respond, the request will 
    be terminated to maintain responsiveness.
    """

    # Limit concurrent requests to avoid overwhelming the system
    _executor = ThreadPoolExecutor(max_workers=10)
    _tokenizer = None  # Lazy load tokenizer
    
    @staticmethod
    def prepare_headers(original_headers: Dict[str, str], 
                        api_provider: str, 
                        auth_token: str) -> Dict[str, str]:
        """
        Prepare headers for the outgoing proxied request. This includes setting 
        authorization, content type, and safe passthrough headers.
        """
        headers = {
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Accept-Encoding': 'identity'
        }
        
        for header_name in ['user-agent', 'x-request-id']:
            if header_name in original_headers:
                headers[header_name] = original_headers[header_name]
                
        return headers

    @staticmethod
    def filter_request_data(api_provider: str, request_data: Optional[bytes]) -> Optional[bytes]:
        """
        Filter and prepare request data for the target provider. This includes:
          - Attempting JSON parsing of request data.
          - Removing unsupported parameters.
          - Applying provider-specific transformations (e.g., default model for Groq).
        """
        if not request_data:
            return None
            
        try:
            data = json.loads(request_data) if isinstance(request_data, bytes) else request_data
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse request data as JSON: {str(e)}")
            return request_data

        unsupported_params = Config.UNSUPPORTED_PARAMS.get(api_provider, [])
        if isinstance(data, dict):
            for param in unsupported_params:
                data.pop(param, None)

        if api_provider == 'groq' and isinstance(data, dict):
            if 'messages' in data and 'model' not in data:
                data['model'] = 'mixtral-8x7b-32768'

        try:
            return json.dumps(data).encode('utf-8')
        except (TypeError, ValueError) as e:
            logger.error(f"Failed to re-encode request data as JSON: {str(e)}")
            return request_data
    
    @classmethod
    def get_tokenizer(cls):
        """Get or create the tokenizer for token counting"""
        if cls._tokenizer is None:
            cls._tokenizer = tiktoken.get_encoding("cl100k_base")  # OpenAI's encoding works well for most models
        return cls._tokenizer
    
    @classmethod
    def count_tokens(cls, text: str) -> int:
        """Count the number of tokens in a text string"""
        return len(cls.get_tokenizer().encode(text))
    
    @classmethod
    def split_messages(cls, messages: List[Dict[str, str]], max_tokens: int = 5500) -> List[List[Dict[str, str]]]:
        """Split a list of messages into chunks that fit within token limits"""
        chunks = []
        current_chunk = []
        current_tokens = 0
        
        # Always keep system message if present
        system_message = None
        if messages and messages[0].get('role') == 'system':
            system_message = messages[0]
            messages = messages[1:]
            
        for message in messages:
            # Count tokens in this message
            message_text = f"{message.get('role', '')}: {message.get('content', '')}"
            message_tokens = cls.count_tokens(message_text)
            
            # If this message alone exceeds limit, split it
            if message_tokens > max_tokens:
                if current_chunk:
                    chunks.append(current_chunk)
                # Split the large message into smaller pieces
                content = message['content']
                while content:
                    chunk_content = content
                    while cls.count_tokens(chunk_content) > max_tokens:
                        # Find last complete sentence within token limit
                        last_period = chunk_content.rfind('.')
                        if last_period == -1:
                            # No complete sentence, just cut at token limit
                            chunk_content = chunk_content[:int(len(chunk_content) * 0.8)]
                        else:
                            chunk_content = chunk_content[:last_period + 1]
                    
                    new_chunk = []
                    if system_message:
                        new_chunk.append(system_message)
                    new_chunk.append({**message, 'content': chunk_content})
                    chunks.append(new_chunk)
                    
                    content = content[len(chunk_content):].strip()
                current_chunk = []
                current_tokens = 0
                continue
            
            # If adding this message would exceed limit, start new chunk
            if current_tokens + message_tokens > max_tokens:
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = []
                if system_message:
                    current_chunk.append(system_message)
                    current_tokens = cls.count_tokens(str(system_message))
                else:
                    current_tokens = 0
            
            current_chunk.append(message)
            current_tokens += message_tokens
        
        # Add any remaining messages
        if current_chunk:
            chunks.append(current_chunk)
        
        return chunks
    
    @classmethod
    def _make_request_with_timeout(cls,
                                   method: str, 
                                   url: str, 
                                   headers: Dict[str, str], 
                                   params: Dict[str, Any], 
                                   data: Optional[bytes], 
                                   timeout: Tuple[int, int]) -> requests.Response:
        """
        Make a single request with a strict timeout. If a service takes more than 2 seconds,
        the request will fail.
        """
        with requests.Session() as session:
            session.max_redirects = 3

            # Check if request is streaming
            is_streaming = False
            if data:
                try:
                    body = json.loads(data)
                    is_streaming = body.get('stream', False)
                except (json.JSONDecodeError, AttributeError):
                    pass

            # Force a maximum of 2 seconds total wait time
            # timeout is a tuple: (connect_timeout, read_timeout)
            # We will override any provider-specific timeouts with a strict 2s limit.
            forced_timeout = (2, 2)

            response = session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                timeout=forced_timeout,
                allow_redirects=True,
                verify=True,
                stream=is_streaming
            )
            
            if not is_streaming:
                _ = response.content

            return response

    @classmethod
    def _make_base_request(cls,
                     method: str,
                     url: str,
                     headers: Dict[str, str],
                     params: Dict[str, Any],
                     data: Optional[bytes],
                     api_provider: Optional[str] = None,
                     use_cache: bool = True,
                     retry_count: int = 0) -> requests.Response:
        """Make a base request without Groq-specific handling"""
        try:
            # Get provider-specific settings
            timeouts = Config.API_TIMEOUTS.get(api_provider, Config.API_TIMEOUTS['default'])
            retry_settings = Config.API_RETRIES.get(api_provider, Config.API_RETRIES['default'])
            
            # Check rate limits
            if api_provider and RateLimitService.is_rate_limited(api_provider):
                logger.warning(f"Rate limit exceeded for provider: {api_provider}")
                raise APIError("Rate limit exceeded", status_code=429)

            # Handle Groq token limits
            if api_provider == 'groq':
                current_key = headers.get('Authorization', '').replace('Bearer ', '')
                if not RateLimitService.check_groq_token_limit(current_key):
                    new_key = RateLimitService.get_next_groq_key()
                    if not new_key:
                        logger.error("All Groq API keys have reached their token limit")
                        raise APIError("All Groq API keys have reached their token limit", status_code=429)
                    headers['Authorization'] = f'Bearer {new_key}'
                    logger.info("Switched to next available Groq API key")

            # Try cache for GET requests if caching is enabled
            if use_cache and method.upper() == 'GET':
                cache_key = CacheService.generate_cache_key(method, url, data)
                cached_response = CacheService.get(cache_key)
                if cached_response:
                    logger.info("Returning cached response")
                    return cached_response

            # Initialize retry counter
            retries = 0
            last_error = None

            while retries <= retry_settings['max_retries']:
                try:
                    # Submit request to thread pool with timeout
                    future = cls._executor.submit(
                        cls._make_request_with_timeout,
                        method, url, headers, params, data,
                        timeouts
                    )
                    
                    try:
                        response = future.result(timeout=timeouts[1] + 5)  # Add buffer for cleanup
                    except FuturesTimeoutError:
                        future.cancel()
                        error_msg = f"Request to {url} timed out after {timeouts[1]} seconds"
                        logger.error(error_msg)
                        raise APIError("Request timed out", status_code=504)

                    # Handle HTTP errors
                    if response.status_code >= 400:
                        try:
                            error_json = response.json()
                            error_message = error_json.get('error', {}).get('message', response.text)
                        except Exception:
                            error_message = response.text
                        
                        # Log error without full traceback
                        logger.error(f"API error response: Status {response.status_code}, Message: {error_message}")
                        
                        # Check if error is retryable
                        if response.status_code in [429, 500, 502, 503, 504] and retries < retry_settings['max_retries']:
                            retries += 1
                            wait_time = retry_settings['backoff_factor'] * (2 ** (retries - 1))
                            logger.warning(f"Request failed with {response.status_code}, retrying in {wait_time}s ({retries}/{retry_settings['max_retries']})")
                            import time
                            time.sleep(wait_time)
                            continue
                            
                        raise APIError(f"API request failed: {error_message}", status_code=response.status_code)

                    # Update Groq token usage for successful requests
                    if api_provider == 'groq' and response.status_code == 200:
                        try:
                            usage = response.json().get('usage', {})
                            total_tokens = usage.get('total_tokens', 0)
                            if total_tokens > 0:
                                current_key = headers.get('Authorization', '').replace('Bearer ', '')
                                RateLimitService.update_groq_token_usage(current_key, total_tokens)
                                logger.info(f"Updated Groq token usage: {total_tokens} tokens")
                        except Exception as e:
                            logger.warning(f"Failed to update Groq token usage: {str(e)}")

                    # Cache successful GET responses if caching is enabled
                    if use_cache and method.upper() == 'GET' and response.status_code == 200:
                        cache_key = CacheService.generate_cache_key(method, url, data)
                        CacheService.set(cache_key, response)

                    return response

                except requests.exceptions.Timeout as e:
                    last_error = f"Request timed out: {str(e)}"
                    logger.error(f"Request to {url} timed out: {str(e)}")
                except requests.exceptions.RequestException as e:
                    last_error = str(e)
                    logger.error(f"Request failed: {str(e)}")
                except Exception as e:
                    last_error = str(e)
                    logger.error(f"Unexpected error: {str(e)}")

                # Handle retries
                retries += 1
                if retries <= retry_settings['max_retries']:
                    wait_time = retry_settings['backoff_factor'] * (2 ** (retries - 1))
                    logger.warning(f"Request failed with error: {last_error}, retrying in {wait_time}s ({retries}/{retry_settings['max_retries']})")
                    import time
                    time.sleep(wait_time)
                else:
                    # If we've exhausted retries, raise the last error
                    if 'timed out' in str(last_error).lower():
                        raise APIError(f"Request timed out after retries: {last_error}", status_code=504)
                    elif isinstance(last_error, str):
                        raise APIError(f"Request failed after retries: {last_error}", status_code=502)
                    else:
                        raise APIError(f"Request failed after retries: Unexpected error", status_code=502)
        except Exception as e:
            # Log error without full traceback
            error_msg = f"Error in make_request: {str(e)}"
            logger.error(error_msg)
            if isinstance(e, APIError):
                raise
            raise APIError(error_msg, status_code=500)

    @classmethod
    def make_request(cls,
                     method: str,
                     url: str,
                     headers: Dict[str, str],
                     params: Dict[str, Any],
                     data: Optional[bytes],
                     api_provider: Optional[str] = None,
                     use_cache: bool = True,
                     retry_count: int = 0) -> requests.Response:
        """Make a proxied request with proper error handling and timeouts"""
        # Special handling for Groq requests
        if api_provider == 'groq' and method.upper() == 'POST':
            try:
                # Parse request data
                request_data = json.loads(data) if data else {}
                messages = request_data.get('messages', [])
                
                # If no messages or streaming, process normally
                if not messages or request_data.get('stream', False):
                    return cls._make_base_request(method, url, headers, params, data, api_provider, use_cache, retry_count)
                
                # Try normal request first
                try:
                    return cls._make_base_request(method, url, headers, params, data, api_provider, use_cache, retry_count)
                except APIError as e:
                    # Check if error is due to token limit
                    if e.status_code == 413 and 'token' in str(e).lower():
                        logger.info("Request exceeded token limit, splitting messages...")
                        # Split messages into smaller chunks
                        message_chunks = cls.split_messages(messages)
                        if len(message_chunks) == 1:
                            # If we couldn't split further, raise original error
                            raise
                        
                        logger.info(f"Split request into {len(message_chunks)} chunks")
                        
                        # Process each chunk
                        responses = []
                        for i, chunk in enumerate(message_chunks):
                            logger.info(f"Processing chunk {i+1}/{len(message_chunks)}")
                            chunk_data = {**request_data, 'messages': chunk}
                            chunk_response = cls._make_base_request(
                                method=method,
                                url=url,
                                headers=headers,
                                params=params,
                                data=json.dumps(chunk_data).encode('utf-8'),
                                api_provider=api_provider,
                                use_cache=use_cache,
                                retry_count=retry_count
                            )
                            responses.append(chunk_response.json()['choices'][0]['message']['content'])
                        
                        # Combine responses
                        combined_response = {
                            'choices': [{
                                'message': {
                                    'role': 'assistant',
                                    'content': ' '.join(responses)
                                }
                            }]
                        }
                        
                        # Create response object
                        response = requests.Response()
                        response._content = json.dumps(combined_response).encode('utf-8')
                        response.status_code = 200
                        response.headers['content-type'] = 'application/json'
                        return response
                    else:
                        raise
            except Exception as e:
                # Log error without full traceback
                error_msg = f"Error handling Groq request: {str(e)}"
                logger.error(error_msg)
                if isinstance(e, APIError):
                    raise
                raise APIError(error_msg, status_code=500)
        
        # For non-Groq requests or non-POST Groq requests
        return cls._make_base_request(method, url, headers, params, data, api_provider, use_cache, retry_count)

    @classmethod
    def shutdown(cls):
        """Cleanup resources"""
        cls._executor.shutdown(wait=False)
