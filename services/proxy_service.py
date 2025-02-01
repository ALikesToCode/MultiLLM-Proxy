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
            if cls._google_token and cls._google_token_expiry and current_time < cls._google_token_expiry:
                return cls._google_token

            try:
                import subprocess
                import shutil
                from flask import current_app

                # Check if credentials file is configured
                credentials_path = current_app.config.get('GOOGLE_APPLICATION_CREDENTIALS')
                if not credentials_path:
                    error_msg = "GOOGLE_APPLICATION_CREDENTIALS not configured in environment"
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
                cls._google_token = token
                cls._google_token_expiry = current_time + timedelta(minutes=45)
                return token

            except subprocess.CalledProcessError as e:
                err_msg = str(e.stderr)
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
        """
        Invalidate the cached Google token to force a refresh.
        """
        with cls._google_token_lock:
            cls._google_token = None
            cls._google_token_expiry = None
            logger.info("Invalidated Google Cloud token cache")

    @staticmethod
    def prepare_headers(
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
            # Update URL to use beta1 openapi chat completions endpoint
            project_id = os.environ.get('PROJECT_ID')
            location = os.environ.get('LOCATION')
            ENDPOINT = os.environ.get('GOOGLE_ENDPOINT')
            url = (
                f"https://{ENDPOINT}/v1beta1/"
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
            logger.info(f"Google AI chat request data: {chat_request}")

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
            logger.info(f"Google AI raw response headers: {response.headers}")

            if response.status_code == 200:
                try:
                    # For streaming responses
                    if chat_request.get("stream", False):
                        def generate():
                            for line in response.iter_lines():
                                if line:
                                    try:
                                        json_data = json.loads(line)
                                        yield f"data: {json.dumps(json_data)}\n\n"
                                    except json.JSONDecodeError as e:
                                        logger.error(f"Error parsing streaming response: {e}")
                                        continue
                            yield "data: [DONE]\n\n"

                        streaming_response = flask.Response(
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
                        response_data = response.json()
                        logger.info(f"Google AI parsed response: {response_data}")

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
                            retry_count=retry_count
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

                return flask.Response(
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
