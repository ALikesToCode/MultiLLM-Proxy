import json
import logging
import requests
from typing import Optional, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

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

                # Handle Groq token limit errors
                if api_provider == 'groq' and response.status_code in [429, 413]:
                    try:
                        error_json = response.json()
                        error_message = error_json.get('error', {}).get('message', '')
                        logger.info(f"Groq API response: {error_json}")
                        if 'token' in error_message.lower() and retry_count < len(Config.GROQ_API_KEYS):
                            logger.info(f"Groq token limit reached, retrying with next key ({retry_count + 1})")
                            new_key = RateLimitService.get_next_groq_key()
                            if new_key:
                                headers['Authorization'] = f'Bearer {new_key}'
                                return cls.make_request(
                                    method=method,
                                    url=url,
                                    headers=headers,
                                    params=params,
                                    data=data,
                                    api_provider=api_provider,
                                    use_cache=use_cache,
                                    retry_count=retry_count + 1
                                )
                    except Exception as e:
                        logger.warning(f"Failed to parse Groq error response: {str(e)}")
                        if hasattr(response, 'text'):
                            logger.warning(f"Raw response: {response.text}")

                # Handle HTTP errors
                if response.status_code >= 400:
                    try:
                        error_json = response.json()
                        error_message = error_json.get('error', {}).get('message', response.text)
                    except Exception:
                        error_message = response.text
                    
                    # Log the full error details
                    logger.error(f"API error response: Status {response.status_code}, Message: {error_message}")
                    if hasattr(response, 'text'):
                        logger.error(f"Full response text: {response.text}")
                    
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
                if hasattr(e, 'response') and hasattr(e.response, 'text'):
                    logger.error(f"Error response text: {e.response.text}")
            except Exception as e:
                last_error = str(e)
                logger.error(f"Unexpected error: {str(e)}", exc_info=True)  # Add full traceback

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

    @classmethod
    def shutdown(cls):
        """Cleanup resources"""
        cls._executor.shutdown(wait=False)
