import json
import logging
import requests
from typing import Optional, Dict, Any, Tuple, List
from concurrent.futures import ThreadPoolExecutor
import tiktoken
from error_handlers import APIError
from config import Config
from services.cache_service import CacheService  # If used
from services.rate_limit_service import RateLimitService
import threading
from datetime import datetime, timedelta
from services.auth_service import AuthService
import time
import uuid
import flask
from flask import Response
import gzip
import io
import re
import os

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAY = 1.0  # Seconds


class ProxyService:
    """
    The ProxyService class handles making proxied requests to various API providers,
    applying caching, rate limits, and token usage rules as needed.
    """

    _executor = ThreadPoolExecutor(max_workers=10)
    _tokenizer = None  # Lazy-load tokenizer

    # Class-level variables for token caching
    _google_token = None
    _google_token_expiry = None
    _google_token_lock = threading.Lock()

    MODEL_MAPPINGS = {
        "TheBloke/Rogue-Rose-103b-v0.2-AWQ": "unsloth/Meta-Llama-3.1-8B-Instruct",  # Map to a supported model
        # Add more model mappings as needed
    }

    @classmethod
    def get_google_access_token(cls) -> Optional[str]:
        """
        Get Google Cloud access token using gcloud command with caching.
        """
        with cls._google_token_lock:
            current_time = datetime.now()
            # Check if token exists and is still valid (with 5-minute buffer)
            if cls._google_token and cls._google_token_expiry and current_time < cls._google_token_expiry - timedelta(minutes=5):
                logger.debug("Using cached Google Cloud access token")
                return cls._google_token

            try:
                import subprocess
                import shutil
                
                logger.info("Getting new Google Cloud access token")
                
                # Try to get credentials from environment first
                credentials_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
                
                # If not in environment, try to get from Flask app config if available
                if not credentials_path:
                    try:
                        from flask import current_app
                        credentials_path = current_app.config.get('GOOGLE_APPLICATION_CREDENTIALS')
                    except RuntimeError:
                        # Handle case when running outside Flask application context
                        logger.warning("Running outside Flask application context, using environment variables only")
                        pass
                
                if not credentials_path:
                    error_msg = "GOOGLE_APPLICATION_CREDENTIALS not configured in environment or app config"
                    logger.error(error_msg)
                    raise APIError(error_msg, status_code=500)

                if not os.path.exists(credentials_path):
                    error_msg = f"Google credentials file not found at {credentials_path}"
                    logger.error(error_msg)
                    raise APIError(error_msg, status_code=500)

                if not shutil.which('gcloud'):
                    error_msg = "gcloud CLI not found. Please install Google Cloud SDK"
                    logger.error(error_msg)
                    raise APIError(error_msg, status_code=500)

                # Set credentials file for gcloud
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials_path

                # Add --quiet flag to avoid interactive prompts
                result = subprocess.run(
                    ['gcloud', 'auth', 'print-access-token', '--quiet'],
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
                cls._google_token = token
                # Set expiry to 40 minutes instead of 45 to ensure we refresh before Google's actual expiry
                cls._google_token_expiry = current_time + timedelta(minutes=40)
                return token

            except subprocess.CalledProcessError as e:
                err_msg = e.stderr.decode('utf-8') if isinstance(e.stderr, bytes) else str(e.stderr)
                # Clear token cache on error
                cls._google_token = None
                cls._google_token_expiry = None
                
                if "not logged in" in err_msg.lower():
                    raise APIError(
                        "Not logged in to gcloud. Please run 'gcloud auth login' first",
                        status_code=401
                    )
                elif "project" in err_msg.lower():
                    raise APIError(
                        "No Google Cloud project selected. Please run 'gcloud config set project YOUR_PROJECT_ID'",
                        status_code=401
                    )
                else:
                    raise APIError(f"Error running gcloud command: {err_msg}", status_code=500)

            except FileNotFoundError:
                # Clear token cache on error
                cls._google_token = None
                cls._google_token_expiry = None
                error_msg = "gcloud command not found. Please install Google Cloud SDK"
                logger.error(error_msg)
                raise APIError(error_msg, status_code=500)

            except Exception as e:
                # Clear token cache on error
                cls._google_token = None
                cls._google_token_expiry = None
                error_msg = f"Unexpected error getting Google token: {str(e)}"
                logger.error(error_msg)
                raise APIError(error_msg, status_code=500)

    @classmethod
    def invalidate_google_token(cls):
        """
        Invalidate the cached Google token to force a refresh.
        """
        with cls._google_token_lock:
            cls._google_token = None
            cls._google_token_expiry = None
            logger.info("Invalidated Google Cloud token cache")

    @classmethod
    def prepare_headers(
        cls,
        request_headers: Dict[str, str],
        api_provider: str,
        auth_token: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Prepare headers for the target provider.
        """
        headers = {k: v for k, v in request_headers.items() if k.lower() not in ['host', 'content-length']}

        if auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        elif api_provider == 'googleai':
            # Try to get Google token from ProxyService first (which has better error handling)
            try:
                google_token = cls.get_google_access_token() if hasattr(cls, 'get_google_access_token') else None
                if not google_token:
                    # Fall back to AuthService if needed
                    google_token = AuthService.get_google_token()
                
                if google_token:
                    headers['Authorization'] = f'Bearer {google_token}'
                    logger.debug("Added Google Cloud token to request headers")
                else:
                    logger.error("Failed to get Google Cloud access token")
                    raise APIError("Failed to get Google Cloud access token", status_code=401)
            except Exception as e:
                logger.error(f"Error getting Google token for request: {str(e)}")
                raise APIError(f"Failed to get Google Cloud access token: {str(e)}", status_code=401)
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
        Attempt to parse and filter request data for the target provider.
        Remove unsupported parameters and apply provider-specific transformations.
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

            # Format for Google AI if needed
            if api_provider == 'googleai' and 'messages' in data:
                formatted_data = {
                    "messages": data['messages'],
                    "model": data.get('model', 'google/gemini-pro'),
                    "temperature": data.get('temperature', 0.7),
                    "maxOutputTokens": data.get('max_tokens', 1024),
                    "topP": data.get('top_p', 0.95),
                    "topK": data.get('top_k', 40)
                }
                data = formatted_data
                logger.info(f"Formatted Google AI request data: {data}")

        try:
            return json.dumps(data).encode('utf-8')
        except (TypeError, ValueError) as e:
            logger.error(f"Failed to re-encode request data as JSON: {str(e)}")
            return request_data

    @classmethod
    def get_tokenizer(cls):
        """
        Get or create the tokenizer for token counting.
        """
        if cls._tokenizer is None:
            cls._tokenizer = tiktoken.get_encoding("cl100k_base")
        return cls._tokenizer

    @classmethod
    def count_tokens(cls, text: str) -> int:
        """
        Count the number of tokens in a text string.
        """
        return len(cls.get_tokenizer().encode(text))

    @classmethod
    def split_messages(cls, messages: List[Dict[str, str]], max_tokens: int = 4500) -> List[List[Dict[str, str]]]:
        """
        Split a list of messages into chunks that fit within token limits.
        Only used for Groq requests. Keeps system message in each chunk if present.
        """
        chunks = []
        current_chunk = []
        current_tokens = 0

        system_message = None
        if messages and messages[0].get('role') == 'system':
            system_message = messages[0]
            messages = messages[1:]

        for message in messages:
            message_text = f"{message.get('role', '')}: {message.get('content', '')}"
            message_tokens = cls.count_tokens(message_text)

            if message_tokens > max_tokens:
                # If a single message is longer than max_tokens, split it further
                if current_chunk:
                    chunks.append(current_chunk)
                content = message['content']
                while content:
                    chunk_content = content
                    while cls.count_tokens(chunk_content) > max_tokens:
                        last_period = chunk_content.rfind('.')
                        if last_period == -1:
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

        if current_chunk:
            chunks.append(current_chunk)

        # Double-check if any chunk still exceeds the limit
        final_chunks = []
        for chunk in chunks:
            total_tokens = sum(cls.count_tokens(f"{msg.get('role', '')}: {msg.get('content', '')}") for msg in chunk)
            if total_tokens > max_tokens:
                logger.warning(
                    f"Chunk with {total_tokens} tokens exceeds limit of {max_tokens}, splitting further"
                )
                sub_chunks = cls.split_messages(chunk, max_tokens)
                final_chunks.extend(sub_chunks)
            else:
                final_chunks.append(chunk)

        return final_chunks

    @classmethod
    def _make_request_with_timeout(
        cls,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        data: Optional[bytes],
        timeout: Tuple[int, int]
    ) -> requests.Response:
        """
        Make a single request with a given timeout (not widely used in code below).
        """
        with requests.Session() as session:
            session.max_redirects = 3
            is_streaming = False
            if data:
                try:
                    body = json.loads(data)
                    is_streaming = body.get('stream', False)
                except (json.JSONDecodeError, AttributeError):
                    pass

            response = session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                timeout=timeout,
                allow_redirects=True,
                verify=True,
                stream=is_streaming
            )

            if not is_streaming:
                _ = response.content
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
    def _make_base_request(
        cls,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        data: bytes,
        api_provider: str,
        use_cache: bool = True,
        retry_count: int = 0
    ) -> requests.Response:
        """
        Make a base request with retries and error handling
        """
        try:
            with requests.Session() as session:
                adapter = requests.adapters.HTTPAdapter()
                session.mount('http://', adapter)
                session.mount('https://', adapter)

                # Only add Accept-Encoding for non-localhost requests
                if not url.startswith(('http://localhost:', 'http://127.0.0.1:', 'http://[::1]:')):
                    if 'Accept-Encoding' not in headers:
                        headers['Accept-Encoding'] = 'gzip, deflate'
                else:
                    # For localhost, explicitly disable compression
                    headers['Accept-Encoding'] = 'identity'

                response = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    stream=True  # always enable streaming
                )

                # Handle response content
                try:
                    if data:
                        # Attempt to see if 'stream' is set to true in JSON
                        parsed_body = json.loads(data)
                        is_streaming = bool(parsed_body.get('stream', False))
                    else:
                        is_streaming = False
                except Exception:
                    is_streaming = False

                if not is_streaming:
                    try:
                        # Let requests handle decompression automatically
                        content = response.content
                        
                        # Try to decode as UTF-8 string
                        if isinstance(content, bytes):
                            try:
                                decoded = content.decode('utf-8', errors='ignore')
                            except UnicodeDecodeError:
                                logger.error("Failed to decode response as UTF-8")
                                error_json = {
                                    "error": {
                                        "message": "Failed to decode response as UTF-8",
                                        "type": "decode_error",
                                        "code": 500
                                    }
                                }
                                response._content = json.dumps(error_json).encode('utf-8')
                                response.headers['Content-Type'] = 'application/json'
                                return response
                        else:
                            decoded = str(content)
                        
                        # Remove any ANSI escape sequences
                        ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]|\x1B[^[]')
                        cleaned = ansi_escape.sub('', decoded)
                        
                        # Try to parse as JSON to validate
                        try:
                            # First try to parse the cleaned content
                            json.loads(cleaned)
                            # If JSON parsing succeeds, use the cleaned content
                            response._content = cleaned.encode('utf-8')
                        except json.JSONDecodeError:
                            # If the response is not JSON, wrap it in a JSON structure
                            try:
                                # Try to parse the original decoded content
                                json.loads(decoded)
                                response._content = decoded.encode('utf-8')
                            except json.JSONDecodeError:
                                # If neither is valid JSON, wrap the content in a JSON structure
                                wrapped_json = {
                                    "data": cleaned,
                                    "status": response.status_code,
                                    "headers": dict(response.headers)
                                }
                                response._content = json.dumps(wrapped_json).encode('utf-8')
                                
                        # Ensure Content-Type is application/json
                        response.headers['Content-Type'] = 'application/json'
                        
                    except Exception as e:
                        logger.error(f"Error processing response: {str(e)}")
                        error_json = {
                            "error": {
                                "message": f"Error processing response: {str(e)}",
                                "type": "processing_error",
                                "code": 500
                            }
                        }
                        response._content = json.dumps(error_json).encode('utf-8')
                        response.headers['Content-Type'] = 'application/json'

                return response

        except requests.exceptions.RequestException as e:
            error_msg = f"Request failed: {str(e)}"
            logger.error(error_msg)
            if retry_count < MAX_RETRIES:
                logger.info(f"Retrying request (attempt {retry_count + 1}/{MAX_RETRIES})")
                time.sleep(RETRY_DELAY * (retry_count + 1))
                return cls._make_base_request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    api_provider=api_provider,
                    use_cache=use_cache,
                    retry_count=retry_count + 1
                )
            
            # If all retries fail, return a JSON error response
            error_response = requests.Response()
            error_response.status_code = 500
            error_json = {
                "error": {
                    "message": error_msg,
                    "type": "request_error",
                    "code": 500,
                    "details": str(e)
                }
            }
            error_response._content = json.dumps(error_json).encode('utf-8')
            error_response.headers = {'Content-Type': 'application/json'}
            return error_response

    @classmethod
    def _handle_together_request(
        cls,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        data: bytes,
        request_data: Dict[str, Any],
        use_cache: bool = True,
        retry_count: int = 0
    ) -> requests.Response:
        """
        Handle Together AI specific request.
        """
        try:
            if 'model' not in request_data and 'messages' in request_data:
                request_data['model'] = Config.TOGETHER_MODELS[0]
                data = json.dumps(request_data).encode('utf-8')

            is_streaming = request_data.get('stream', False)
            logger.info(f"Together AI request URL: {url}")
            logger.info(f"Together AI request headers: {headers}")
            logger.info(f"Together AI request data: {request_data}")

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

            logger.info(f"Together AI raw response status: {response.status_code}")
            logger.info(f"Together AI raw response headers: {response.headers}")

            if response.status_code == 200:
                try:
                    if is_streaming:
                        return response
                    else:
                        if response.content:
                            response_data = response.json()
                            logger.info(f"Together AI parsed response: {response_data}")

                            # If listing /models, do not attempt to parse choices
                            if url.endswith('/models'):
                                return response

                            if 'choices' not in response_data:
                                # Attempt to unify response shape
                                if 'output' in response_data:
                                    content = response_data['output'].get('content', '')
                                elif 'response' in response_data:
                                    content = response_data['response']
                                elif 'text' in response_data:
                                    content = response_data['text']
                                else:
                                    content = str(response_data)

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
                            # else: already has 'choices' in response_data
                        else:
                            logger.error("Empty response content from Together AI")
                            raise APIError("Empty response from Together AI", status_code=500)
                        return response
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error: {str(e)}")
                    logger.error(f"Raw content: {response.content}")
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
                raise APIError(
                    f"Together AI request failed with status {response.status_code}",
                    status_code=response.status_code
                )
        except Exception as e:
            error_msg = f"Error handling Together request: {str(e)}"
            logger.error(error_msg)
            if isinstance(e, APIError):
                raise
            raise APIError(error_msg, status_code=500)

    @classmethod
    def _handle_groq_request(
        cls,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        data: bytes,
        request_data: Dict[str, Any],
        use_cache: bool = True,
        retry_count: int = 0
    ) -> requests.Response:
        """
        Handle Groq specific request processing with message chunking.
        """
        try:
            messages = request_data.get('messages', [])
            # If no messages or streaming is used, just make a single request
            if not messages or request_data.get('stream', False):
                return cls._make_base_request(method, url, headers, params, data, 'groq', use_cache, retry_count)

            # Attempt normal request first
            try:
                return cls._make_base_request(method, url, headers, params, data, 'groq', use_cache, retry_count)
            except APIError as e:
                # If token limit error, we can split messages
                if e.status_code == 413:
                    logger.info("Request exceeded token limit, splitting messages...")
                    message_chunks = cls.split_messages(messages)
                    if len(message_chunks) == 1:
                        # Only one chunk => can't really split further
                        raise
                    logger.info(f"Split request into {len(message_chunks)} chunks")

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
                        # Gather partial content
                        content_part = chunk_response.json()['choices'][0]['message']['content']
                        responses.append(content_part)

                    combined_response = {
                        'choices': [{
                            'message': {
                                'role': 'assistant',
                                'content': ' '.join(responses)
                            }
                        }]
                    }
                    response = requests.Response()
                    response._content = json.dumps(combined_response).encode('utf-8')
                    response.status_code = 200
                    response.headers['content-type'] = 'application/json'
                    return response
                else:
                    raise

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            raise APIError(f"Unexpected error occurred: {str(e)}", status_code=500)

    @classmethod
    def _handle_googleai_request(
        cls,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        data: bytes,
        request_data: Dict[str, Any],
        use_cache: bool = True,
        retry_count: int = 0
    ) -> requests.Response:
        """
        Handle Google AI specific request processing
        """
        try:
            # Check retry count to prevent infinite loops
            if retry_count >= 3:
                raise APIError("Maximum retry count exceeded for Google AI request", status_code=500)
                
            # Update URL to use chat completions endpoint
            project_id = os.environ.get('PROJECT_ID')
            location = os.environ.get('LOCATION')
            ENDPOINT = os.environ.get('GOOGLE_ENDPOINT')
            
            if not all([project_id, location, ENDPOINT]):
                missing = []
                if not project_id: missing.append("PROJECT_ID")
                if not location: missing.append("LOCATION")
                if not ENDPOINT: missing.append("GOOGLE_ENDPOINT")
                raise APIError(f"Missing required Google AI environment variables: {', '.join(missing)}", status_code=500)
                
            url = (
                f"https://{ENDPOINT}/v1/"
                f"projects/{project_id}/locations/{location}/endpoints/openapi/chat/completions"
            )

            # Format request for chat completions API
            chat_request = {
                "model": request_data.get("model", "meta/llama-3.1-405b-instruct-maas"),
                "messages": request_data.get("messages", []),
                "max_tokens": request_data.get("max_tokens", 1024),
                "stream": request_data.get("stream", False),
                "extra_body": {
                    "google": {
                        "model_safety_settings": {
                            "enabled": request_data.get("extra_body", {}).get("google", {})
                                .get("model_safety_settings", {})
                                .get("enabled", False),
                            "llama_guard_settings": request_data.get("extra_body", {})
                                .get("google", {})
                                .get("model_safety_settings", {})
                                .get("llama_guard_settings", {})
                        }
                    }
                }
            }

            data = json.dumps(chat_request).encode('utf-8')

            logger.info(f"Google AI chat request URL: {url}")
            logger.debug(f"Google AI chat request data: {chat_request}")

            # Ensure we have a valid token before making the request
            if 'Authorization' not in headers or not headers['Authorization'].startswith('Bearer '):
                logger.info("No valid authorization token found, getting a fresh token")
                token = cls.get_google_access_token()
                if token:
                    headers['Authorization'] = f'Bearer {token}'
                else:
                    raise APIError("Failed to get Google Cloud access token", status_code=401)

            response = cls._make_base_request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                api_provider='googleai',
                use_cache=use_cache,
                retry_count=retry_count
            )

            logger.info(f"Google AI raw response status: {response.status_code}")
            logger.debug(f"Google AI raw response headers: {response.headers}")

            if response.status_code == 200:
                try:
                    # For streaming responses
                    if chat_request.get("stream", False):
                        def generate():
                            for line in response.iter_lines():
                                if line:
                                    try:
                                        line_str = line.decode('utf-8') if isinstance(line, bytes) else line
                                        if line_str.startswith('data: '):
                                            line_str = line_str[6:]  # Remove 'data: ' prefix if present
                                        
                                        if line_str.strip() == '[DONE]':
                                            yield "data: [DONE]\n\n"
                                            continue
                                            
                                        json_data = json.loads(line_str)
                                        yield f"data: {json.dumps(json_data)}\n\n"
                                    except json.JSONDecodeError as e:
                                        logger.error(f"Error parsing streaming response: {e}, line: {line}")
                                        continue
                            yield "data: [DONE]\n\n"

                        streaming_response = Response(
                            generate(),
                            mimetype='text/event-stream',
                            headers={
                                'Cache-Control': 'no-cache',
                                'Connection': 'keep-alive',
                                'Content-Type': 'text/event-stream',
                                'X-Accel-Buffering': 'no'
                            }
                        )
                        return streaming_response
                    else:
                        # Non-streaming response
                        try:
                            response_data = response.json()
                        except json.JSONDecodeError as e:
                            logger.error(f"Error parsing JSON response: {e}, content: {response.content[:200]}")
                            response_data = {"error": "Invalid JSON response from Google AI"}
                            
                        logger.debug(f"Google AI parsed response: {response_data}")

                        # Create new Response to unify return type
                        response_json = json.dumps(response_data)
                        response_bytes = response_json.encode('utf-8')

                        new_response = requests.Response()
                        new_response.status_code = 200
                        new_response._content = response_bytes
                        new_response.headers.update({
                            'Content-Type': 'application/json; charset=utf-8',
                            'Content-Length': str(len(response_bytes))
                        })
                        return new_response

                except Exception as e:
                    logger.error(f"Error processing response: {str(e)}")
                    raise APIError(f"Error processing response: {str(e)}", status_code=500)
            else:
                # Check for token-related errors (401 Unauthorized)
                if response.status_code == 401:
                    logger.info("Google AI token error detected, refreshing token...")
                    # Invalidate and refresh token
                    cls.invalidate_google_token()
                    # Update headers with new token
                    new_token = cls.get_google_access_token()
                    if new_token:
                        headers['Authorization'] = f'Bearer {new_token}'
                        # Retry the request with new token
                        return cls._handle_googleai_request(
                            method=method,
                            url=url,
                            headers=headers,
                            params=params,
                            data=data,
                            request_data=request_data,
                            use_cache=use_cache,
                            retry_count=retry_count + 1
                        )
                
                # Log error response
                try:
                    error_content = response.content.decode('utf-8')
                    logger.error(f"Google AI error response: {error_content}")
                except Exception as e:
                    logger.error(f"Error decoding error response: {str(e)}")

                raise APIError(
                    f"Google AI request failed with status {response.status_code}",
                    status_code=response.status_code
                )
        except Exception as e:
            error_msg = f"Error handling Google AI request: {str(e)}"
            logger.error(error_msg)
            if isinstance(e, APIError):
                raise
            raise APIError(error_msg, status_code=500)

    @classmethod
    def _handle_rogue_rose_request(
        cls,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        data: bytes,
        request_data: Dict[str, Any],
        use_cache: bool = True,
    ) -> requests.Response:
        """Handle requests for the Rogue Rose model, converting chat to completion format"""
        try:
            # Convert chat format to completion format
            messages = request_data.get("messages", [])
            
            # Process messages in order
            prompt = ""
            for msg in messages:
                role = msg.get("role", "")
                content = msg.get("content", "")
                if role == "system":
                    prompt += f"{content}\n"
                elif role == "user":
                    prompt += f"{content}\n"
            
            # Create completion request
            completion_data = {
                "model": cls.MODEL_MAPPINGS[request_data["model"]],  # Map to supported model
                "prompt": prompt.strip(),
                "temperature": request_data.get("temperature", 0.7),
                "max_tokens": request_data.get("max_tokens", 100),
                "top_p": request_data.get("top_p", 1.0),
                "stream": request_data.get("stream", False),
                "frequency_penalty": request_data.get("frequency_penalty", 0),
                "presence_penalty": request_data.get("presence_penalty", 0)
            }

            logger.info(f"Original request data: {request_data}")
            logger.info(f"Completion data: {completion_data}")

            # Update URL to use completions endpoint while maintaining the nineteen path
            completion_url = url.replace("/chat/completions", "/completions")
            
            # Create new request data
            completion_data_bytes = json.dumps(completion_data).encode('utf-8')
            headers["Content-Length"] = str(len(completion_data_bytes))

            logger.info(f"Converted chat request to completion for Rogue Rose: {completion_data}")
            logger.info(f"New URL: {completion_url}")

            # Make the request
            response = cls._make_base_request(
                method=method,
                url=completion_url,
                headers=headers,
                params=params,
                data=completion_data_bytes,
                api_provider="nineteen",
                use_cache=use_cache
            )

            # Handle streaming response
            if completion_data.get("stream", False):
                def generate():
                    try:
                        for line in response.iter_lines():
                            if line:
                                try:
                                    completion_chunk = json.loads(line)
                                    # Convert completion chunk to chat format
                                    chat_chunk = {
                                        "id": completion_chunk.get("id", str(uuid.uuid4())),
                                        "object": "chat.completion.chunk",
                                        "created": completion_chunk.get("created", int(time.time())),
                                        "model": request_data["model"],  # Use original model name
                                        "choices": [
                                            {
                                                "index": 0,
                                                "delta": {
                                                    "role": "assistant" if "role" not in completion_chunk else None,
                                                    "content": completion_chunk["choices"][0]["text"]
                                                },
                                                "finish_reason": completion_chunk["choices"][0].get("finish_reason")
                                            }
                                        ]
                                    }
                                    yield f"data: {json.dumps(chat_chunk)}\n\n"
                                except json.JSONDecodeError as e:
                                    logger.error(f"Error parsing streaming response: {e}")
                                    continue
                        yield "data: [DONE]\n\n"
                    except Exception as e:
                        logger.error(f"Error in stream generation: {str(e)}")
                        raise APIError(f"Error in stream generation: {str(e)}", status_code=500)

                return Response(
                    generate(),
                    mimetype='text/event-stream',
                    headers={
                        'Cache-Control': 'no-cache',
                        'Connection': 'keep-alive',
                        'Content-Type': 'text/event-stream',
                        'X-Accel-Buffering': 'no'
                    }
                )

            # Handle non-streaming response
            if response.status_code == 200:
                try:
                    completion_response = response.json()
                    chat_response = {
                        "id": completion_response.get("id", str(uuid.uuid4())),
                        "object": "chat.completion",
                        "created": completion_response.get("created", int(time.time())),
                        "model": request_data["model"],  # Use original model name
                        "choices": [
                            {
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": completion_response["choices"][0]["text"]
                                },
                                "finish_reason": completion_response["choices"][0].get("finish_reason", "stop")
                            }
                        ],
                        "usage": completion_response.get("usage", {})
                    }

                    # Create new response with chat format
                    chat_response_bytes = json.dumps(chat_response).encode('utf-8')
                    new_response = requests.Response()
                    new_response.status_code = 200
                    new_response._content = chat_response_bytes
                    new_response.headers.update({
                        'Content-Type': 'application/json',
                        'Content-Length': str(len(chat_response_bytes))
                    })

                    return new_response
                except Exception as e:
                    logger.error(f"Error converting completion to chat response: {str(e)}")
                    raise APIError(f"Error converting completion to chat response: {str(e)}", status_code=500)

            return response
        except Exception as e:
            error_msg = f"Error in Rogue Rose request handler: {str(e)}"
            logger.error(error_msg)
            raise APIError(error_msg, status_code=500)

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
        auth_token: Optional[str] = None,
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
            
            # If still no API key, use the auth token passed from make_request
            # But first check if it's the admin API key - if so, use the Gemini key from env instead
            if not api_key and auth_token:
                admin_api_key = os.environ.get('ADMIN_API_KEY')
                if auth_token == admin_api_key:
                    # Using admin key, look up the actual provider key instead
                    logger.info(f"Admin API key detected - using {api_provider} API key from env instead")
                    api_key = AuthService.get_api_key(api_provider)
                    if not api_key:
                        # Try alternative keys
                        if api_provider == 'gemma':
                            api_key = AuthService.get_api_key('gemini')
                        elif api_provider == 'gemini':
                            api_key = AuthService.get_api_key('gemma')
                else:
                    # Not the admin key, might be a direct Gemini key
                    api_key = auth_token
                    logger.info(f"Using API key from Authorization header for {api_provider}")
            
            # If still no API key, get from auth service
            if not api_key:
                # First try with the exact api_provider
                api_key = AuthService.get_api_key(api_provider)
                
                # If using 'gemma' as provider but no gemma key found, try with 'gemini' as they share the same key
                if not api_key and api_provider == 'gemma':
                    api_key = AuthService.get_api_key('gemini')
                    logger.info("Using Gemini API key for Gemma model")
                
                # If using 'gemini' as provider but no gemini key found, try with 'gemma' as a fallback
                elif not api_key and api_provider == 'gemini':
                    api_key = AuthService.get_api_key('gemma')
                    logger.info("Using Gemma API key for Gemini model")
                
                if not api_key:
                    raise APIError(f"No API key found for {api_provider}. Please set {api_provider.upper()}_API_KEY in your .env file.", status_code=401)
                
                logger.info(f"Using API key from AuthService for {api_provider}")
            
            # Validate API key format - Gemini keys should start with "AIza"
            if not api_key.startswith("AIza"):
                logger.warning(f"API key for {api_provider} doesn't match expected format (should start with 'AIza')")
                # Try to find a valid key from the environment
                env_key = os.environ.get(f'{api_provider.upper()}_API_KEY')
                if env_key and env_key.startswith("AIza"):
                    logger.info(f"Found valid {api_provider} API key format in environment, using it instead")
                    api_key = env_key
            
            # Log partial key for debugging (first 4 + last 4 chars)
            if api_key and len(api_key) > 10:
                masked_key = f"{api_key[:4]}...{api_key[-4:]}"
                logger.info(f"Using API key: {masked_key}")
            
            # Add API key to params - THIS IS CRUCIAL FOR GEMINI API
            if not params:
                params = {}
            params['key'] = api_key
            
            # Remove the Authorization header as Gemini doesn't use it
            if 'Authorization' in headers:
                headers.pop('Authorization')
                logger.info("Removed Authorization header for Gemini API request")
            
            # Extract model if it's in the URL path for direct model invocation
            # Format like /v1beta/models/gemini-1.5-pro:generateContent or /models/gemini-1.5-flash:generateContent
            model = None
            if '/models/' in url and ':' in url:
                try:
                    # Extract the model name from the URL
                    model_part = url.split('/models/')[1].split(':')[0]
                    if model_part:
                        model = model_part
                        logger.info(f"Extracted model from URL path: {model}")
                except Exception as e:
                    logger.warning(f"Failed to extract model from URL: {str(e)}")
            
            # Transformation: Convert OpenAI-style endpoint to Google Generative Language API style
            if '/chat/completions' in url:
                # Extract the base URL and replace the path
                parsed_url = url.split('/v1beta/')[0] if '/v1beta/' in url else url.split('/v1/')[0]
                
                # Default model to use for each provider
                default_model = 'gemini-2.0-flash' if api_provider == 'gemini' else 'gemma-2-9b'
                
                # Get model from request data or use default
                model = request_data.get('model', default_model)
                
                # Check if model is appropriate for the provider
                if api_provider == 'gemini' and model.startswith('gemma-'):
                    logger.warning(f"Using Gemma model ({model}) with Gemini API provider - this may cause auth issues")
                elif api_provider == 'gemma' and model.startswith('gemini-'):
                    logger.warning(f"Using Gemini model ({model}) with Gemma API provider - this may cause auth issues")
                
                # Build the correct endpoint URL for generateContent
                url = f"{parsed_url}/v1beta/models/{model}:generateContent"
                logger.info(f"Transformed URL to {url}")
                
                # Transform OpenAI-style request to Google Generative Language API format
                if 'messages' in request_data:
                    messages = request_data.get('messages', [])
                    contents = []
                    
                    # Process messages to build 'contents'
                    for message in messages:
                        role = message.get('role', '')
                        content = message.get('content', '')
                        
                        # Skip system messages for now or consider adding as context
                        if role == 'system':
                            continue
                        
                        # Add content from user or assistant messages
                        contents.append({
                            "parts": [{"text": content}]
                        })
                    
                    # Create the new request format
                    new_request_data = {
                        "contents": contents
                    }
                    
                    # Copy relevant parameters
                    if 'temperature' in request_data:
                        new_request_data['generationConfig'] = new_request_data.get('generationConfig', {})
                        new_request_data['generationConfig']['temperature'] = request_data['temperature']
                    
                    if 'max_tokens' in request_data:
                        new_request_data['generationConfig'] = new_request_data.get('generationConfig', {})
                        new_request_data['generationConfig']['maxOutputTokens'] = request_data['max_tokens']
                    
                    if 'top_p' in request_data:
                        new_request_data['generationConfig'] = new_request_data.get('generationConfig', {})
                        new_request_data['generationConfig']['topP'] = request_data['top_p']
                    
                    # Use streaming if requested
                    if 'stream' in request_data and request_data['stream']:
                        new_request_data['stream'] = True
                    
                    # Update request data
                    request_data = new_request_data
                
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
                
                # Add web search capability if needed for Gemini models
                if 'webSearch' not in request_data and api_provider == 'gemini':
                    # Only add web search for models that support it
                    if model and 'gemini' in model and not 'gemma' in model:
                        request_data["webSearch"] = True
                        request_data["webSearchSpec"] = {"disableSearch": False}
                        logger.info(f"Enabling web search for Gemini model: {model}")
                
                # Re-encode the modified data
                data = json.dumps(request_data).encode('utf-8')
                headers["Content-Length"] = str(len(data))
                logger.info(f"Modified {api_provider} request data to disable safety settings")
            
            # Log the final URL with params
            full_url = url
            if params:
                param_str = '&'.join([f"{k}={'REDACTED' if k=='key' else v}" for k, v in params.items()])
                full_url = f"{url}?{param_str}" if '?' not in url else f"{url}&{param_str}"
            logger.info(f"Making {api_provider} request to: {full_url}")
            
            # Make the request with the modified data
            response = cls._make_base_request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                api_provider=api_provider,
                use_cache=use_cache
            )
            
            # Handle authentication errors with more detailed logging
            if response.status_code == 401:
                logger.error(f"Authentication failed for {api_provider}. Response: {response.text}")
                # Try to parse the error response for more details
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', {}).get('message', 'Unknown authentication error')
                    logger.error(f"Detailed error: {error_message}")
                    
                    # Create a more informative error response
                    error_response = requests.Response()
                    error_response.status_code = 401
                    error_data = {
                        "error": {
                            "message": f"Authentication failed for {api_provider}. The API key is invalid or does not have access to the requested model ({model}). Error: {error_message}",
                            "solution": "Please create a valid API key from Google AI Studio (https://aistudio.google.com) and update your .env file with GEMINI_API_KEY=your-key",
                            "details": "Gemini API keys should begin with 'AIza'. The admin API key cannot be used directly - you need to obtain a specific Gemini API key and add it to your .env file."
                        }
                    }
                    error_response._content = json.dumps(error_data).encode('utf-8')
                    error_response.headers.update({
                        'Content-Type': 'application/json',
                        'Content-Length': str(len(error_response._content))
                    })
                    return error_response
                except Exception as e:
                    logger.error(f"Could not parse error response: {response.text}, {str(e)}")
                    
                    # Return a generic error
                    error_response = requests.Response()
                    error_response.status_code = 401
                    error_data = {
                        "error": {
                            "message": f"Authentication failed for {api_provider}. The API key is invalid or does not have access to the requested model.",
                            "solution": "Please create a valid API key from Google AI Studio (https://aistudio.google.com) and update your .env file with GEMINI_API_KEY=your-key",
                            "details": "Gemini API keys should begin with 'AIza'. The admin API key cannot be used directly - you need to obtain a specific Gemini API key and add it to your .env file."
                        }
                    }
                    error_response._content = json.dumps(error_data).encode('utf-8')
                    error_response.headers.update({
                        'Content-Type': 'application/json',
                        'Content-Length': str(len(error_response._content))
                    })
                    return error_response
            
            # Process response to convert from Google's format to OpenAI compatible format
            if response.status_code == 200:
                # Check if this is a streaming response
                is_streaming = request_data.get('stream', False)
                
                if is_streaming:
                    # Handle streaming response
                    def generate_stream():
                        try:
                            for line in response.iter_lines():
                                if line:
                                    try:
                                        line_str = line.decode('utf-8') if isinstance(line, bytes) else line
                                        
                                        # Strip 'data: ' prefix if present
                                        if line_str.startswith('data: '):
                                            line_str = line_str[6:]
                                            
                                        # Check for stream end marker
                                        if line_str.strip() == '[DONE]':
                                            yield "data: [DONE]\n\n"
                                            continue
                                        
                                        # Parse Google's SSE format
                                        google_chunk = json.loads(line_str)
                                        
                                        # For chat/completions endpoints, convert to OpenAI format
                                        if '/chat/completions' in url:
                                            # Extract content if available in this chunk
                                            content = ""
                                            finish_reason = None
                                            
                                            if 'candidates' in google_chunk and google_chunk['candidates']:
                                                candidate = google_chunk['candidates'][0]
                                                if 'content' in candidate and 'parts' in candidate['content']:
                                                    for part in candidate['content']['parts']:
                                                        if 'text' in part:
                                                            content = part['text']
                                                
                                                if 'finishReason' in candidate:
                                                    finish_reason = candidate['finishReason']
                                            
                                            # Create OpenAI-compatible chunk
                                            openai_chunk = {
                                                "id": google_chunk.get("id", str(uuid.uuid4())),
                                                "object": "chat.completion.chunk",
                                                "created": int(time.time()),
                                                "model": model,
                                                "choices": [
                                                    {
                                                        "index": 0,
                                                        "delta": {
                                                            "content": content
                                                        },
                                                        "finish_reason": finish_reason
                                                    }
                                                ]
                                            }
                                            
                                            # First chunk should include role: assistant
                                            if 'role' not in locals():
                                                openai_chunk['choices'][0]['delta']['role'] = 'assistant'
                                                role = 'sent'  # Mark that we've sent the role
                                            
                                            yield f"data: {json.dumps(openai_chunk)}\n\n"
                                        else:
                                            # For direct model endpoints, pass through the chunk with just the formatting needed
                                            yield f"data: {json.dumps(google_chunk)}\n\n"
                                            
                                    except json.JSONDecodeError as e:
                                        logger.error(f"Error parsing streaming response from Gemini: {e}, line: {line}")
                                        continue
                                    except Exception as e:
                                        logger.error(f"Error processing Gemini streaming chunk: {e}")
                                        continue
                            
                            # Make sure to send the final [DONE] marker
                            yield "data: [DONE]\n\n"
                        except Exception as e:
                            logger.error(f"Error in Gemini streaming response: {str(e)}")
                            yield f"data: {json.dumps({'error': str(e)})}\n\n"
                            yield "data: [DONE]\n\n"
                    
                    # Return a streaming response
                    streaming_response = Response(
                        generate_stream(),
                        mimetype='text/event-stream',
                        headers={
                            'Cache-Control': 'no-cache',
                            'Connection': 'keep-alive',
                            'Content-Type': 'text/event-stream',
                            'X-Accel-Buffering': 'no'
                        }
                    )
                    return streaming_response
                elif '/chat/completions' in url:
                    # Handle normal chat/completions response
                    try:
                        google_response = response.json()
                        
                        # Create OpenAI compatible response
                        openai_response = {
                            "id": google_response.get("id", str(uuid.uuid4())),
                            "object": "chat.completion",
                            "created": int(time.time()),
                            "model": model,
                            "choices": [
                                {
                                    "index": 0,
                                    "message": {
                                        "role": "assistant",
                                        "content": google_response.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                                    },
                                    "finish_reason": google_response.get("candidates", [{}])[0].get("finishReason", "stop")
                                }
                            ],
                            "usage": {
                                "prompt_tokens": google_response.get("usageMetadata", {}).get("promptTokenCount", 0),
                                "completion_tokens": google_response.get("usageMetadata", {}).get("candidatesTokenCount", 0),
                                "total_tokens": google_response.get("usageMetadata", {}).get("totalTokenCount", 0)
                            }
                        }
                        
                        # Create new response with OpenAI format
                        openai_response_bytes = json.dumps(openai_response).encode('utf-8')
                        new_response = requests.Response()
                        new_response.status_code = 200
                        new_response._content = openai_response_bytes
                        new_response.headers.update({
                            'Content-Type': 'application/json',
                            'Content-Length': str(len(openai_response_bytes))
                        })
                        
                        return new_response
                    except Exception as e:
                        logger.error(f"Error converting Google response to OpenAI format: {str(e)}")
            
            return response
            
        except Exception as e:
            error_msg = f"Error in _handle_gemini_request: {str(e)}"
            logger.error(error_msg)
            if isinstance(e, APIError):
                raise
            raise APIError(error_msg, status_code=500)

    @classmethod
    def _handle_openrouter_request(
        cls,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        data: bytes,
        request_data: Dict[str, Any],
        use_cache: bool,
        auth_token: Optional[str] = None,
    ) -> requests.Response:
        """
        Handle OpenRouter specific request processing.
        OpenRouter provides access to hundreds of AI models through a single endpoint.
        """
        logger.info(f"Handling OpenRouter request to {url}")
        
        try:
            # Get the OpenRouter API key
            api_key = None
            
            # If auth token is provided and is the admin API key, use the OpenRouter key from env instead
            if auth_token:
                admin_api_key = os.environ.get('ADMIN_API_KEY')
                if auth_token == admin_api_key:
                    # Using admin key, look up the OpenRouter key from env
                    logger.info("Admin API key detected - using OpenRouter API key from env instead")
                    api_key = AuthService.get_api_key('openrouter')
                else:
                    # Not the admin key, use it directly as OpenRouter key
                    api_key = auth_token
                    logger.info("Using API key from Authorization header for OpenRouter")
            
            # If no API key yet, try to get from auth service
            if not api_key:
                api_key = AuthService.get_api_key('openrouter')
                if not api_key:
                    raise APIError("No API key found for OpenRouter. Please set OPENROUTER_API_KEY in your .env file.", status_code=401)
                logger.info("Using API key from AuthService for OpenRouter")
            
            # Log partial key for debugging (first 4 + last 4 chars)
            if api_key and len(api_key) > 10:
                masked_key = f"{api_key[:4]}...{api_key[-4:]}"
                logger.info(f"Using OpenRouter API key: {masked_key}")
            
            # Replace auth header with the real OpenRouter API key
            headers['Authorization'] = f'Bearer {api_key}'
            
            # Add OpenRouter specific headers from environment if available
            site_url = os.environ.get('OPENROUTER_SITE_URL')
            app_name = os.environ.get('OPENROUTER_APP_NAME')
            
            if site_url:
                headers['HTTP-Referer'] = site_url
                logger.debug(f"Added HTTP-Referer header: {site_url}")
            
            if app_name:
                headers['X-Title'] = app_name
                logger.debug(f"Added X-Title header: {app_name}")
            
            # Transform the URL to use OpenRouter's base URL
            # First extract the path portion from the URL
            path = url
            if '://' in url:
                # Extract path from full URL
                path = url.split('://', 1)[1].split('/', 1)[1] if '/' in url.split('://', 1)[1] else ''
                path = f"/{path}" if path else ""
            
            # Build the OpenRouter URL
            # Check if the path already contains "api/v1" to avoid duplication
            if path.startswith('/api/v1'):
                openrouter_url = f"https://openrouter.ai{path}"
            else:
                # Fix the path for consistent API access - ensure v1 is in the path
                # If path starts with /v1, add api prefix
                if path.startswith('/v1'):
                    openrouter_url = f"https://openrouter.ai/api{path}"
                # If path doesn't have v1, add the full /api/v1 prefix
                else:
                    openrouter_url = f"https://openrouter.ai/api/v1{path}"
            
            logger.info(f"Transformed URL to OpenRouter: {openrouter_url}")
            
            # Log the request details
            logger.info(f"Making OpenRouter request to: {openrouter_url}")
            logger.debug(f"Headers: {headers}")
            if data:
                logger.debug(f"Request data: {request_data}")
            
            # Make the request
            response = cls._make_base_request(
                method=method,
                url=openrouter_url,
                headers=headers,
                params=params,
                data=data,
                api_provider='openrouter',
                use_cache=use_cache
            )
            
            # Handle authentication errors
            if response.status_code == 401:
                logger.error(f"Authentication failed for OpenRouter. Response: {response.text}")
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', {}).get('message', 'Unknown authentication error')
                    logger.error(f"Detailed error: {error_message}")
                    
                    error_response = requests.Response()
                    error_response.status_code = 401
                    error_data = {
                        "error": {
                            "message": f"Authentication failed for OpenRouter: {error_message}",
                            "solution": "Please create a valid API key from OpenRouter (https://openrouter.ai) and update your .env file with OPENROUTER_API_KEY=your-key",
                            "details": "The admin API key cannot be used directly - you need to obtain a specific OpenRouter API key and add it to your .env file."
                        }
                    }
                    error_response._content = json.dumps(error_data).encode('utf-8')
                    error_response.headers.update({
                        'Content-Type': 'application/json',
                        'Content-Length': str(len(error_response._content))
                    })
                    return error_response
                except Exception as e:
                    logger.error(f"Could not parse error response: {response.text}, {str(e)}")
            
            # Check for streaming response
            if request_data.get('stream', False) and response.status_code == 200:
                def generate():
                    try:
                        for line in response.iter_lines():
                            if line:
                                try:
                                    line_str = line.decode('utf-8') if isinstance(line, bytes) else line
                                    
                                    # Skip comment lines in SSE
                                    if line_str.startswith(':') or not line_str.strip():
                                        continue
                                    
                                    # Strip 'data: ' prefix if present
                                    if line_str.startswith('data: '):
                                        line_str = line_str[6:]
                                    
                                    # Check for stream end marker
                                    if line_str.strip() == '[DONE]':
                                        yield "data: [DONE]\n\n"
                                        continue
                                    
                                    # Parse the chunk and pass it through
                                    json_data = json.loads(line_str)
                                    yield f"data: {json.dumps(json_data)}\n\n"
                                    
                                except json.JSONDecodeError as e:
                                    logger.error(f"Error parsing streaming response: {e}, line: {line}")
                                    continue
                                except Exception as e:
                                    logger.error(f"Error processing streaming chunk: {e}")
                                    continue
                        
                        # Ensure final [DONE] marker
                        yield "data: [DONE]\n\n"
                    except Exception as e:
                        logger.error(f"Error in streaming generation: {str(e)}")
                        yield f"data: {json.dumps({'error': str(e)})}\n\n"
                        yield "data: [DONE]\n\n"
                
                # Return a proper streaming response
                streaming_response = Response(
                    generate(),
                    mimetype='text/event-stream',
                    headers={
                        'Cache-Control': 'no-cache',
                        'Connection': 'keep-alive',
                        'Content-Type': 'text/event-stream',
                        'X-Accel-Buffering': 'no'
                    }
                )
                return streaming_response
            
            return response
            
        except Exception as e:
            error_msg = f"Error in _handle_openrouter_request: {str(e)}"
            logger.error(error_msg)
            if isinstance(e, APIError):
                raise
            raise APIError(error_msg, status_code=500)

    @classmethod
    def make_request(
        cls,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        data: bytes,
        api_provider: str,
        use_cache: bool = True,
    ) -> requests.Response:
        """
        Make a request with retries and error handling
        """
        logger.info(f"Making request to {url} with method {method}")
        
        try:
            # Extract authentication tokens/keys if needed
            auth_token = None
            auth_header = headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                auth_token = auth_header.replace('Bearer ', '').strip()
                logger.debug(f"Extracted auth token from header: {auth_token[:5]}...")
            
            # Special handling for different providers
            if api_provider == "together":
                return cls._handle_together_request(
                    method, url, headers, params, data, json.loads(data), use_cache
                )
            elif api_provider == "groq":
                return cls._handle_groq_request(
                    method, url, headers, params, data, json.loads(data), use_cache
                )
            elif api_provider == "googleai":
                return cls._handle_googleai_request(
                    method, url, headers, params, data, json.loads(data), use_cache
                )
            elif api_provider == "gemini" or api_provider == "gemma":
                # For Gemini/Gemma, pass the auth token extracted from header if available
                return cls._handle_gemini_request(
                    method, url, headers, params, data, json.loads(data) if data else {}, use_cache, api_provider, auth_token
                )
            elif api_provider == "nineteen":
                request_data = json.loads(data)
                model = request_data.get("model")
                if model in cls.MODEL_MAPPINGS:
                    # Map the model to a supported one
                    request_data["model"] = cls.MODEL_MAPPINGS[model]
                    data = json.dumps(request_data).encode('utf-8')
                    headers["Content-Length"] = str(len(data))
                    logger.info(f"Mapped model {model} to {request_data['model']}")

                # Make the base request
                return cls._make_base_request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    api_provider=api_provider,
                    use_cache=use_cache
                )
            elif api_provider == "openrouter":
                return cls._handle_openrouter_request(
                    method, url, headers, params, data, json.loads(data) if data else {}, use_cache, auth_token
                )

            # Default handling
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
            error_msg = f"Error in make_request: {str(e)}"
            logger.error(error_msg)
            if isinstance(e, APIError):
                raise
            raise APIError(error_msg, status_code=500)

    @classmethod
    def shutdown(cls):
        """
        Cleanup resources.
        """
        cls._executor.shutdown(wait=False)
