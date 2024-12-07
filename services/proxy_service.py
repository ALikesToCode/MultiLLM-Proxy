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
import threading
from datetime import datetime, timedelta
from services.auth_service import AuthService

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
    
    # Class-level variables for token caching
    _google_token = None
    _google_token_expiry = None
    _google_token_lock = threading.Lock()

    @classmethod
    def get_google_access_token(cls) -> Optional[str]:
        """Get Google Cloud access token using gcloud command with caching."""
        with cls._google_token_lock:
            current_time = datetime.now()
            
            # Check if token exists and is not expired (45 minutes)
            if (cls._google_token and cls._google_token_expiry and 
                current_time < cls._google_token_expiry):
                return cls._google_token

            try:
                import subprocess
                import shutil

                # First check if gcloud is installed
                if not shutil.which('gcloud'):
                    error_msg = "gcloud CLI not found. Please install Google Cloud SDK"
                    logger.error(error_msg)
                    raise APIError(error_msg, status_code=500)

                # Try to get token
                result = subprocess.run(
                    ['gcloud', 'auth', 'print-access-token'], 
                    capture_output=True, 
                    text=True, 
                    check=True
                )

                token = result.stdout.strip()
                if not token:
                    error_msg = "Empty token received from gcloud command. Please run 'gcloud auth login' first"
                    logger.error(error_msg)
                    raise APIError(error_msg, status_code=401)

                logger.info("Successfully retrieved new Google Cloud access token")
                # Set token and expiry (45 minutes from now)
                cls._google_token = token
                cls._google_token_expiry = current_time + timedelta(minutes=45)
                return token

            except subprocess.CalledProcessError as e:
                error_msg = f"Failed to get Google Cloud token: {e.stderr}"
                logger.error(error_msg)
                if "not logged in" in str(e.stderr).lower():
                    raise APIError("Not logged in to gcloud. Please run 'gcloud auth login' first", status_code=401)
                elif "project" in str(e.stderr).lower():
                    raise APIError("No Google Cloud project selected. Please run 'gcloud config set project YOUR_PROJECT_ID'", status_code=401)
                else:
                    raise APIError(f"Error running gcloud command: {e.stderr}", status_code=500)
            except FileNotFoundError:
                error_msg = "gcloud command not found. Please install Google Cloud SDK"
                logger.error(error_msg)
                raise APIError(error_msg, status_code=500)
            except Exception as e:
                error_msg = f"Unexpected error getting Google token: {str(e)}"
                logger.error(error_msg)
                raise APIError(error_msg, status_code=500)

    @classmethod
    def invalidate_google_token(cls):
        """Invalidate the cached Google token to force a refresh."""
        with cls._google_token_lock:
            cls._google_token = None
            cls._google_token_expiry = None
            logger.info("Invalidated Google Cloud token cache")

    @staticmethod
    def prepare_headers(request_headers: Dict[str, str], api_provider: str, auth_token: Optional[str] = None) -> Dict[str, str]:
        """Prepare headers for the target provider."""
        headers = {k: v for k, v in request_headers.items() if k.lower() not in ['host', 'content-length']}
        
        # If auth token is provided, use it
        if auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        # Otherwise use provider-specific auth
        elif api_provider == 'googleai':
            google_token = AuthService.get_google_token()
            if google_token:
                headers['Authorization'] = f'Bearer {google_token}'
            else:
                raise APIError("Failed to get Google Cloud access token", status_code=401)
        elif api_provider == 'groq':
            groq_key = RateLimitService.get_next_groq_key()
            if groq_key:
                headers['Authorization'] = f'Bearer {groq_key}'
            else:
                raise APIError("No available Groq API keys", status_code=401)
        elif api_provider == 'together':
            together_key = Config.TOGETHER_API_KEY
            if together_key:
                headers['Authorization'] = f'Bearer {together_key}'
            else:
                raise APIError("Together API key not configured", status_code=401)
        
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
    def split_messages(cls, messages: List[Dict[str, str]], max_tokens: int = 4500) -> List[List[Dict[str, str]]]:
        """Split a list of messages into chunks that fit within token limits.
        Using 4500 as max_tokens provides a safe buffer below the 6000 TPM limit."""
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
        
        # Verify no chunk exceeds the token limit
        for chunk in chunks:
            total_tokens = sum(cls.count_tokens(f"{msg.get('role', '')}: {msg.get('content', '')}") for msg in chunk)
            if total_tokens > max_tokens:
                logger.warning(f"Chunk with {total_tokens} tokens exceeds limit of {max_tokens}, splitting further")
                # Recursively split this chunk
                sub_chunks = cls.split_messages(chunk, max_tokens)
                # Replace the original chunk with the sub-chunks
                chunks = [c for c in chunks if c != chunk] + sub_chunks
        
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
        Make a single request with a timeout. The timeout is now provider-specific
        to allow for longer processing times.
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

            # Use the provider-specific timeout
            response = session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                timeout=timeout,  # Use the provided timeout
                allow_redirects=True,
                verify=True,
                stream=is_streaming
            )
            
            if not is_streaming:
                _ = response.content
                # Debug log the response
                try:
                    logger.info(f"Response status: {response.status_code}")
                    logger.info(f"Response headers: {response.headers}")
                    if response.headers.get('content-type', '').startswith('application/json'):
                        logger.info(f"Response content: {response.json()}")
                    else:
                        logger.info(f"Response content length: {len(response.content)}")
                except Exception as e:
                    logger.error(f"Error logging response: {str(e)}")

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

            retries = 0
            last_error = None
            
            while retries <= retry_settings['max_retries']:
                try:
                    response = cls._make_request_with_timeout(
                        method=method,
                        url=url,
                        headers=headers,
                        params=params,
                        data=data,
                        timeout=timeouts
                    )
                    
                    if response.status_code >= 400:
                        try:
                            error_json = response.json()
                            error_message = error_json.get('error', {}).get('message', response.text)
                        except Exception:
                            error_message = response.text
                        
                        # Log error without full traceback
                        logger.error(f"API error response: Status {response.status_code}, Message: {error_message}")
                        
                        # For Google token expiration, invalidate token and retry
                        if api_provider == 'googleai' and (
                            response.status_code == 401 or 
                            'token expired' in error_message.lower() or 
                            'invalid token' in error_message.lower()
                        ):
                            AuthService.invalidate_google_token()
                            # Update headers with new token
                            new_token = AuthService.get_google_token()
                            if new_token:
                                headers['Authorization'] = f'Bearer {new_token}'
                                retries += 1
                                continue
                        
                        # For Groq 413 errors, raise immediately without retrying
                        if api_provider == 'groq' and response.status_code == 413:
                            raise APIError(f"API request failed: {error_message}", status_code=response.status_code)
                        
                        # Check if error is retryable
                        if response.status_code in [429, 500, 502, 503, 504] and retries < retry_settings['max_retries']:
                            retries += 1
                            wait_time = retry_settings['backoff_factor'] * (2 ** (retries - 1))
                            logger.warning(f"Request failed with {response.status_code}, retrying in {wait_time}s ({retries}/{retry_settings['max_retries']})")
                            import time
                            time.sleep(wait_time)
                            continue
                            
                        raise APIError(f"API request failed: {error_message}", status_code=response.status_code)

                    return response

                except requests.exceptions.Timeout as e:
                    last_error = f"Request timed out: {str(e)}"
                    logger.error(f"Request to {url} timed out: {str(e)}")
                    if retries < retry_settings['max_retries']:
                        retries += 1
                        wait_time = retry_settings['backoff_factor'] * (2 ** (retries - 1))
                        logger.warning(f"Retrying in {wait_time}s ({retries}/{retry_settings['max_retries']})")
                        time.sleep(wait_time)
                        continue
                    break

            # If we get here, all retries failed
            raise APIError(last_error or "Max retries exceeded", status_code=500)

        except Exception as e:
            error_msg = f"Error in base request: {str(e)}"
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
        try:
            # Parse request data for logging
            request_data = {}
            if data:
                try:
                    request_data = json.loads(data)
                    logger.info(f"Request data: {request_data}")
                except Exception:
                    pass

            # Special handling for Groq requests
            if api_provider == 'groq' and method.upper() == 'POST':
                return cls._handle_groq_request(method, url, headers, params, data, request_data, use_cache, retry_count)
            
            # Special handling for Together AI requests
            if api_provider == 'together' and method.upper() == 'POST':
                return cls._handle_together_request(method, url, headers, params, data, request_data, use_cache, retry_count)
            
            # For other requests
            return cls._make_base_request(method, url, headers, params, data, api_provider, use_cache, retry_count)
        except Exception as e:
            error_msg = f"Error in make_request: {str(e)}"
            logger.error(error_msg)
            if isinstance(e, APIError):
                raise
            raise APIError(error_msg, status_code=500)

    @classmethod
    def _handle_together_request(cls,
                               method: str,
                               url: str,
                               headers: Dict[str, str],
                               params: Dict[str, Any],
                               data: bytes,
                               request_data: Dict[str, Any],
                               use_cache: bool = True,
                               retry_count: int = 0) -> requests.Response:
        """Handle Together AI specific request processing"""
        try:
            # Add default model if not specified
            if 'model' not in request_data and 'messages' in request_data:
                request_data['model'] = Config.TOGETHER_MODELS[0]
                data = json.dumps(request_data).encode('utf-8')
            
            # Check if streaming is requested
            is_streaming = request_data.get('stream', False)
            
            # Log the request details
            logger.info(f"Together AI request URL: {url}")
            logger.info(f"Together AI request headers: {headers}")
            logger.info(f"Together AI request data: {request_data}")
            
            # Make the request
            response = cls._make_base_request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                api_provider='together',
                use_cache=use_cache,
                retry_count=retry_count
            )

            # Log raw response
            logger.info(f"Together AI raw response status: {response.status_code}")
            logger.info(f"Together AI raw response headers: {response.headers}")

            # Handle response
            if response.status_code == 200:
                if is_streaming:
                    # For streaming responses, return as-is to let Flask handle SSE streaming
                    return response
                else:
                    try:
                        # Try to parse JSON response for non-streaming requests
                        if response.content:
                            response_data = response.json()
                            logger.info(f"Together AI parsed response: {response_data}")
                            
                            # Ensure response has required fields
                            if 'choices' not in response_data:
                                # Check different possible response formats
                                if 'output' in response_data:
                                    content = response_data['output'].get('content', '')
                                elif 'response' in response_data:
                                    content = response_data['response']
                                elif 'text' in response_data:
                                    content = response_data['text']
                                else:
                                    content = str(response_data)  # Fallback to string representation
                                
                                # Format response in OpenAI-like structure
                                formatted_response = {
                                    'choices': [{
                                        'message': {
                                            'role': 'assistant',
                                            'content': content
                                        }
                                    }],
                                    'model': request_data.get('model', ''),
                                    'object': 'chat.completion',
                                    'usage': response_data.get('usage', {})
                                }
                                response._content = json.dumps(formatted_response).encode('utf-8')
                        else:
                            logger.error("Empty response content from Together AI")
                            raise APIError("Empty response from Together AI", status_code=500)
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON decode error: {str(e)}")
                        logger.error(f"Raw content causing error: {response.content}")
                        raise APIError("Invalid JSON response from Together AI", status_code=500)
                    except Exception as e:
                        logger.error(f"Error processing Together AI response: {str(e)}")
                        raise APIError(f"Error processing Together AI response: {str(e)}", status_code=500)
            else:
                # Log error response
                try:
                    error_content = response.content.decode('utf-8')
                    logger.error(f"Together AI error response: {error_content}")
                except Exception as e:
                    logger.error(f"Error decoding error response: {str(e)}")
                raise APIError(f"Together AI request failed with status {response.status_code}", 
                             status_code=response.status_code)
            
            return response
        except Exception as e:
            error_msg = f"Error handling Together request: {str(e)}"
            logger.error(error_msg)
            if isinstance(e, APIError):
                raise
            raise APIError(error_msg, status_code=500)

    @classmethod
    def _handle_groq_request(cls,
                            method: str,
                            url: str,
                            headers: Dict[str, str],
                            params: Dict[str, Any],
                            data: bytes,
                            request_data: Dict[str, Any],
                            use_cache: bool = True,
                            retry_count: int = 0) -> requests.Response:
        """Handle Groq specific request processing"""
        try:
            messages = request_data.get('messages', [])
            
            # If no messages or streaming, process normally
            if not messages or request_data.get('stream', False):
                return cls._make_base_request(method, url, headers, params, data, 'groq', use_cache, retry_count)
            
            # Try normal request first
            try:
                return cls._make_base_request(method, url, headers, params, data, 'groq', use_cache, retry_count)
            except APIError as e:
                # Check if error is due to token limit
                if e.status_code == 413:
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
                            api_provider='groq',
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
            error_msg = f"Error handling Groq request: {str(e)}"
            logger.error(error_msg)
            if isinstance(e, APIError):
                raise
            raise APIError(error_msg, status_code=500)

    @classmethod
    def shutdown(cls):
        """Cleanup resources"""
        cls._executor.shutdown(wait=False)
