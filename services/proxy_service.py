import json
import logging
import requests
from typing import Optional, Dict, Any, Tuple, List, Generator
from concurrent.futures import ThreadPoolExecutor
import tiktoken
from error_handlers import APIError
from config import Config
from services.cache_service import CacheService  # If used
from services.rate_limit_service import RateLimitService
import threading
from datetime import datetime, timedelta
from services.auth_service import AuthService
from services.redaction import redact_headers, redact_payload, redact_query_params, redact_text
from streaming.openai import sanitize_openai_stream_payload
from streaming.sse import iter_sse_data
import time
import uuid
import flask
from flask import Response
import gzip
import io
import re
import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
    _sessions: Dict[str, requests.Session] = {}
    _session_lock = threading.RLock()
    _circuit_breakers: Dict[str, Dict[str, Any]] = {}
    _circuit_lock = threading.RLock()
    _mojibake_marker_pattern = re.compile(r"[\u0080-\u009f]|[ÃÂâðÐÑ]")
    _cp1252_utf8_continuation_chars = "€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ"
    _utf8_as_single_byte_sequence_pattern = re.compile(
        r"[\u00C2-\u00F4][\u0080-\u00BF"
        + re.escape(_cp1252_utf8_continuation_chars)
        + r"]+"
    )

    # Class-level variables for token caching
    _google_token = None
    _google_token_expiry = None
    _google_token_lock = threading.Lock()

    MODEL_MAPPINGS = {
        "TheBloke/Rogue-Rose-103b-v0.2-AWQ": "unsloth/Meta-Llama-3.1-8B-Instruct",  # Map to a supported model
        # Add more model mappings as needed
    }

    RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
    SAFE_RETRY_METHODS = {"GET", "HEAD", "OPTIONS"}
    UPSTREAM_HEADER_WHITELIST = {
        "accept": "Accept",
        "accept-language": "Accept-Language",
        "anthropic-version": "Anthropic-Version",
        "content-type": "Content-Type",
        "http-referer": "HTTP-Referer",
        "openai-organization": "OpenAI-Organization",
        "user-agent": "User-Agent",
        "x-request-id": "X-Request-ID",
        "x-title": "X-Title",
    }

    @staticmethod
    def _has_header(headers: Dict[str, str], header_name: str) -> bool:
        normalized_name = header_name.lower()
        return any(existing_header.lower() == normalized_name for existing_header in headers)

    @classmethod
    def _get_provider_session(cls, api_provider: str) -> requests.Session:
        with cls._session_lock:
            session = cls._sessions.get(api_provider)
            if session is not None:
                return session

            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=100,
                pool_maxsize=100,
                max_retries=0,
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            cls._sessions[api_provider] = session
            return session

    @classmethod
    def _has_idempotency_key(cls, headers: Dict[str, str]) -> bool:
        return any(key.lower() == "idempotency-key" for key in headers)

    @classmethod
    def _should_retry_status(cls, method: str, headers: Dict[str, str], status_code: int, is_streaming: bool) -> bool:
        if status_code not in cls.RETRYABLE_STATUS_CODES or is_streaming:
            return False
        if method.upper() in cls.SAFE_RETRY_METHODS:
            return True
        return cls._has_idempotency_key(headers)

    @classmethod
    def _should_retry_exception(cls, method: str, data: Optional[bytes], error: requests.exceptions.RequestException) -> bool:
        if isinstance(error, requests.exceptions.ConnectTimeout):
            return True
        return method.upper() in cls.SAFE_RETRY_METHODS and not data

    @classmethod
    def _circuit_settings(cls) -> tuple[int, int]:
        try:
            failure_threshold = int(os.environ.get("CIRCUIT_BREAKER_FAILURES", "5"))
        except ValueError:
            failure_threshold = 5
        try:
            cooldown_seconds = int(os.environ.get("CIRCUIT_BREAKER_COOLDOWN_SECONDS", "30"))
        except ValueError:
            cooldown_seconds = 30
        return max(1, failure_threshold), max(1, cooldown_seconds)

    @classmethod
    def _circuit_open_response(cls, api_provider: str) -> Optional[requests.Response]:
        with cls._circuit_lock:
            state = cls._circuit_breakers.get(api_provider)
            if not state:
                return None
            opened_until = state.get("opened_until", 0)
            if opened_until <= time.time():
                state["opened_until"] = 0
                return None

        response = requests.Response()
        response.status_code = 503
        payload = {
            "error": {
                "message": f"Circuit breaker is open for {api_provider}",
                "type": "circuit_open",
                "code": 503,
            }
        }
        response._content = json.dumps(payload).encode("utf-8")
        response.headers["Content-Type"] = "application/json"
        return response

    @classmethod
    def _record_circuit_result(cls, api_provider: str, status_code: int) -> None:
        failure_threshold, cooldown_seconds = cls._circuit_settings()
        with cls._circuit_lock:
            state = cls._circuit_breakers.setdefault(
                api_provider,
                {"failures": 0, "opened_until": 0},
            )
            if status_code in cls.RETRYABLE_STATUS_CODES:
                state["failures"] += 1
                if state["failures"] >= failure_threshold:
                    state["opened_until"] = time.time() + cooldown_seconds
                return

            state["failures"] = 0
            state["opened_until"] = 0

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
        Prepare headers for API requests, filtering out unnecessary ones.
        """
        headers = {}
        header_whitelist = dict(cls.UPSTREAM_HEADER_WHITELIST)
        if api_provider in ["googleai", "gemini", "gemma"]:
            header_whitelist["x-goog-user-project"] = "X-Goog-User-Project"

        for header, value in request_headers.items():
            canonical_header = header_whitelist.get(header.lower())
            if canonical_header:
                headers[canonical_header] = value

        if not cls._has_header(headers, "Content-Type"):
            headers["Content-Type"] = "application/json"

        if not cls._has_header(headers, "Accept"):
            if 'stream=true' in request_headers.get('Cookie', '').lower() or \
               request_headers.get('X-Stream', '').lower() == 'true':
                headers['Accept'] = 'text/event-stream'
            else:
                headers['Accept'] = 'application/json'

        # Handle API key authentication
        if auth_token:
            headers['Authorization'] = f"Bearer {auth_token}"

        # Add provider-specific headers
        if api_provider == 'openrouter':
            # OpenRouter requires HTTP-Referer and X-Title
            if not cls._has_header(headers, "HTTP-Referer"):
                headers['HTTP-Referer'] = os.environ.get('OPENROUTER_REFERER', 'https://multiproxy.example.com')
            if not cls._has_header(headers, "X-Title"):
                headers['X-Title'] = os.environ.get('APP_NAME', 'MultiLLM Proxy')
        elif api_provider == 'anthropic':
            # Anthropic specific headers
            if not cls._has_header(headers, "Anthropic-Version"):
                headers['Anthropic-Version'] = '2023-06-01'

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
                logger.info("Formatted Google AI request data: %s", redact_payload(data))

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
    def _mojibake_score(cls, text: str) -> int:
        """
        Estimate how likely a string is to contain mojibake.
        """
        if not text:
            return 0

        control_chars = sum(1 for char in text if 0x80 <= ord(char) <= 0x9F)
        marker_chars = len(cls._mojibake_marker_pattern.findall(text))
        replacement_chars = text.count("\ufffd")
        utf8_sequence_chars = sum(
            len(match.group(0))
            for match in cls._utf8_as_single_byte_sequence_pattern.finditer(text)
        )
        return (control_chars * 4) + marker_chars + (replacement_chars * 2) + (utf8_sequence_chars * 2)

    @classmethod
    def _repair_mojibake_substrings(cls, text: str) -> str:
        """
        Repair mojibake substrings inside otherwise valid Unicode text.
        """
        if not text:
            return text

        def replace_match(match: re.Match[str]) -> str:
            return cls._repair_mojibake_fragment(match.group(0))

        repaired = text
        for _ in range(3):
            updated = cls._utf8_as_single_byte_sequence_pattern.sub(replace_match, repaired)
            if updated == repaired:
                break
            repaired = updated

        return repaired

    @classmethod
    def _decode_mojibake_candidate(cls, text: str) -> Tuple[str, int]:
        """
        Try the supported single-byte interpretations and return the best candidate.
        """
        best_text = text
        best_score = cls._mojibake_score(text)

        for source_encoding in ("latin-1", "cp1252"):
            try:
                candidate = text.encode(source_encoding).decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue

            candidate_score = cls._mojibake_score(candidate)
            if candidate_score < best_score:
                best_text = candidate
                best_score = candidate_score

        return best_text, best_score

    @classmethod
    def _repair_mojibake_fragment(cls, text: str) -> str:
        """
        Repair a suspicious substring, even when a valid trailing character was swallowed.
        """
        if not text:
            return text

        best_text, best_score = cls._decode_mojibake_candidate(text)

        for split_index in range(len(text) - 1, 1, -1):
            prefix = text[:split_index]
            repaired_prefix, prefix_score = cls._decode_mojibake_candidate(prefix)
            if prefix_score >= cls._mojibake_score(prefix):
                continue

            suffix = text[split_index:]
            candidate = repaired_prefix + cls._repair_mojibake_fragment(suffix)
            candidate_score = cls._mojibake_score(candidate)
            if candidate_score < best_score:
                best_text = candidate
                best_score = candidate_score

        return best_text

    @classmethod
    def _repair_mojibake_text(cls, text: str) -> str:
        """
        Repair obvious mojibake in a single string.
        """
        if not isinstance(text, str) or not text:
            return text

        best_text = text
        best_score = cls._mojibake_score(text)
        if best_score == 0:
            return text

        best_text, best_score = cls._decode_mojibake_candidate(text)

        substring_repaired = cls._repair_mojibake_substrings(best_text)
        if cls._mojibake_score(substring_repaired) < best_score:
            return substring_repaired

        return best_text

    @staticmethod
    def _is_retryable_timeout_payload(
        api_provider: str,
        status_code: int,
        payload: Any,
    ) -> bool:
        """
        Detect provider error payloads that should be retried automatically.
        """
        if api_provider != "opencode" or status_code != 400 or not isinstance(payload, dict):
            return False

        error = payload.get("error")
        if not isinstance(error, dict):
            return False

        message = str(error.get("message", "")).strip().lower()
        code = str(error.get("code", "")).strip()
        return message == "timeout" and code in {"", "400"}

    @classmethod
    def _strip_embedded_stream_chunk_payload(cls, chunk: str) -> Optional[str]:
        """
        Remove leaked OpenAI-style chunk payloads embedded inside raw text lines.
        """
        if not chunk or chunk.startswith("data: "):
            return None

        cleaned_chunk = chunk
        stripped_any_payload = False
        marker = '"chat.completion.chunk"'

        while True:
            marker_index = cleaned_chunk.find(marker)
            if marker_index == -1:
                break

            object_start = cleaned_chunk.rfind("{", 0, marker_index)
            if object_start == -1:
                break

            depth = 0
            in_string = False
            escape_next = False
            object_end = None

            for index in range(object_start, len(cleaned_chunk)):
                char = cleaned_chunk[index]

                if escape_next:
                    escape_next = False
                    continue

                if char == "\\":
                    escape_next = True
                    continue

                if char == '"':
                    in_string = not in_string
                    continue

                if in_string:
                    continue

                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        object_end = index + 1
                        break

            if object_end is None:
                break

            try:
                parsed_payload = json.loads(cleaned_chunk[object_start:object_end])
            except json.JSONDecodeError:
                break

            if not isinstance(parsed_payload, dict) or parsed_payload.get("object") != "chat.completion.chunk":
                break

            cleaned_chunk = (cleaned_chunk[:object_start] + cleaned_chunk[object_end:]).strip()
            cleaned_chunk = cls._repair_mojibake_text(cleaned_chunk).strip()
            stripped_any_payload = True

        if not stripped_any_payload:
            return None

        if cls._looks_like_meaningful_stream_text(cleaned_chunk):
            return cleaned_chunk

        return ""

    @classmethod
    def _strip_reasoning_block_markup(
        cls,
        chunk: str,
        inside_reasoning_block: bool,
    ) -> Tuple[str, bool]:
        """
        Remove provider-specific <think>...</think> reasoning markup from raw text lines.
        """
        cleaned_chunk = chunk

        if inside_reasoning_block:
            if "</think>" not in cleaned_chunk:
                return "", True
            cleaned_chunk = cleaned_chunk.split("</think>", 1)[1]
            inside_reasoning_block = False

        while "<think>" in cleaned_chunk:
            prefix, _, remainder = cleaned_chunk.partition("<think>")
            if "</think>" in remainder:
                _, _, suffix = remainder.partition("</think>")
                cleaned_chunk = prefix + suffix
                continue

            cleaned_chunk = prefix
            inside_reasoning_block = True
            break

        return cleaned_chunk.strip(), inside_reasoning_block

    @classmethod
    def _looks_like_meaningful_stream_text(cls, text: str) -> bool:
        """
        Distinguish real leaked-prose lines from noise left behind after chunk stripping.
        """
        if not text:
            return False

        alnum_chars = sum(char.isalnum() for char in text)
        ascii_word_chars = sum(char.isascii() and char.isalnum() for char in text)
        if alnum_chars == 0:
            return False

        mojibake_score = cls._mojibake_score(text)
        if any(char.isspace() for char in text):
            return ascii_word_chars >= 4 and mojibake_score <= max(8, len(text) // 3)

        return ascii_word_chars >= 4 and mojibake_score <= max(4, len(text) // 4)

    @classmethod
    def normalize_json_text(cls, value: Any) -> Any:
        """
        Recursively repair mojibake in JSON-like structures.
        """
        if isinstance(value, str):
            return cls._repair_mojibake_text(value)
        if isinstance(value, list):
            return [cls.normalize_json_text(item) for item in value]
        if isinstance(value, dict):
            return {key: cls.normalize_json_text(item) for key, item in value.items()}
        return value

    @classmethod
    def normalize_text_for_token_count(cls, text: str) -> str:
        """
        Repair obvious mojibake before token counting.

        This keeps token estimation aligned with the intended text without mutating
        the message content that will be forwarded upstream.
        """
        return cls._repair_mojibake_text(text)

    @classmethod
    def count_tokens(cls, text: str) -> int:
        """
        Count the number of tokens in a text string.
        """
        normalized_text = cls.normalize_text_for_token_count(text)
        return len(cls.get_tokenizer().encode(normalized_text))

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
                    logger.info("Response status: %s", response.status_code)
                    logger.info("Response headers: %s", redact_headers(response.headers))
                    if response.headers.get('content-type', '').startswith('application/json'):
                        logger.info("Response content: %s", redact_payload(response.json()))
                    else:
                        logger.info("Response content length: %s", len(response.content))
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
        data: Optional[bytes],
        api_provider: str,
        use_cache: bool = True,
        retry_count: int = 0
    ) -> requests.Response:
        """
        Make a base request with retries and error handling
        """
        try:
            circuit_response = cls._circuit_open_response(api_provider)
            if circuit_response is not None:
                return circuit_response

            session = cls._get_provider_session(api_provider)

            # Only advertise encodings we can reliably decode in this runtime.
            if not url.startswith(('http://localhost:', 'http://127.0.0.1:', 'http://[::1]:')):
                headers['Accept-Encoding'] = 'gzip, deflate'
            else:
                # For localhost, explicitly disable compression
                headers['Accept-Encoding'] = 'identity'

            timeout = Config.API_TIMEOUTS.get(
                api_provider,
                Config.API_TIMEOUTS.get("default", (5, 60)),
            )

            response = session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                stream=True,  # always enable streaming
                timeout=timeout,
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

            if (
                cls._should_retry_status(method, headers, response.status_code, is_streaming)
                and retry_count < MAX_RETRIES
            ):
                logger.warning(
                    "Retrying %s request after status %s (attempt %s/%s)",
                    api_provider,
                    response.status_code,
                    retry_count + 1,
                    MAX_RETRIES,
                )
                time.sleep(RETRY_DELAY * (retry_count + 1))
                return cls._make_base_request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    api_provider=api_provider,
                    use_cache=use_cache,
                    retry_count=retry_count + 1,
                )

            if not is_streaming:
                try:
                    # Let requests handle decompression automatically
                    content = response.content
                    content_type = response.headers.get('content-type', '').lower()
                    if not content or "json" not in content_type:
                        cls._record_circuit_result(api_provider, response.status_code)
                        return response

                    decoded = content.decode('utf-8') if isinstance(content, bytes) else str(content)
                    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]|\x1B[^[]')
                    cleaned = ansi_escape.sub('', decoded)

                    normalized_payload = None

                    # Try to parse as JSON to validate
                    try:
                        parsed_cleaned = json.loads(cleaned)
                        normalized_payload = cls.normalize_json_text(parsed_cleaned)
                    except json.JSONDecodeError:
                        try:
                            parsed_decoded = json.loads(decoded)
                            normalized_payload = cls.normalize_json_text(parsed_decoded)
                        except json.JSONDecodeError:
                            normalized_payload = None

                    if normalized_payload is None:
                        cls._record_circuit_result(api_provider, response.status_code)
                        return response

                    if (
                        cls._is_retryable_timeout_payload(
                            api_provider,
                            response.status_code,
                            normalized_payload,
                        )
                        and retry_count < MAX_RETRIES
                    ):
                        logger.warning(
                            "Retrying %s request after timeout payload (attempt %s/%s)",
                            api_provider,
                            retry_count + 1,
                            MAX_RETRIES,
                        )
                        time.sleep(RETRY_DELAY * (retry_count + 1))
                        return cls._make_base_request(
                            method=method,
                            url=url,
                            headers=headers,
                            params=params,
                            data=data,
                            api_provider=api_provider,
                            use_cache=use_cache,
                            retry_count=retry_count + 1,
                        )

                    response._content = json.dumps(normalized_payload).encode('utf-8')
                    response.headers['Content-Type'] = 'application/json'

                except Exception as e:
                    logger.error(f"Error processing response: {str(e)}")
                    cls._record_circuit_result(api_provider, response.status_code)
                    return response

            cls._record_circuit_result(api_provider, response.status_code)
            return response

        except requests.exceptions.RequestException as e:
            error_msg = f"Request failed: {str(e)}"
            logger.error(error_msg)
            if (
                cls._should_retry_exception(method, data, e)
                and retry_count < MAX_RETRIES
            ):
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
            cls._record_circuit_result(api_provider, 503)
            
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
            logger.info(
                "Together AI request provider=%s url=%s model=%s stream=%s headers=%s params=%s payload=%s",
                "together",
                url,
                request_data.get("model"),
                is_streaming,
                redact_headers(headers),
                redact_query_params(params),
                redact_payload(request_data),
            )

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

            logger.info(
                "Together AI response provider=%s status_code=%s headers=%s",
                "together",
                response.status_code,
                redact_headers(response.headers),
            )

            if response.status_code == 200:
                try:
                    if is_streaming:
                        return response
                    else:
                        if response.content:
                            response_data = response.json()
                            logger.info("Together AI parsed response: %s", redact_payload(response_data))

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
                    logger.error("Together AI raw content length: %s", len(response.content))
                    raise APIError("Invalid JSON response from Together AI", status_code=500)
                except Exception as e:
                    logger.error(f"Error processing Together AI response: {str(e)}")
                    raise APIError(f"Error processing Together AI response: {str(e)}", status_code=500)
            else:
                # Log error response
                try:
                    error_content = response.content.decode('utf-8')
                    logger.error("Together AI error response: %s", redact_text(error_content))
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

            # Ensure stream parameter is properly set
            if "stream" in request_data:
                chat_request["stream"] = bool(request_data["stream"])
                logger.debug(f"Google AI stream parameter explicitly set to: {chat_request['stream']}")

            data = json.dumps(chat_request).encode('utf-8')

            logger.info(f"Google AI chat request URL: {url}")
            logger.debug("Google AI chat request data: %s", redact_payload(chat_request))

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
            logger.debug("Google AI raw response headers: %s", redact_headers(response.headers))

            if response.status_code == 200:
                try:
                    # For streaming responses
                    if chat_request.get("stream", False):
                        logger.info("Handling Google AI streaming response")
                        
                        def generate():
                            try:
                                for line in response.iter_lines():
                                    if line:
                                        try:
                                            line_str = line.decode('utf-8') if isinstance(line, bytes) else line
                                            if line_str.startswith('data: '):
                                                line_str = line_str[6:]  # Remove 'data: ' prefix if present
                                            
                                            if line_str.strip() == '[DONE]':
                                                yield "data: [DONE]\n\n"
                                                continue
                                                
                                            # Parse JSON and format as SSE
                                            json_data = json.loads(line_str)
                                            
                                            # Ensure data is in OpenAI streaming format
                                            if not json_data.get('choices'):
                                                # Convert to OpenAI format
                                                content = None
                                                if 'candidates' in json_data:
                                                    try:
                                                        content = json_data['candidates'][0]['content']['parts'][0]['text']
                                                    except (KeyError, IndexError):
                                                        if json_data.get('candidates') and len(json_data['candidates']) > 0:
                                                            # Try other possible structures
                                                            candidate = json_data['candidates'][0]
                                                            if 'text' in candidate:
                                                                content = candidate['text']
                                                            elif 'content' in candidate:
                                                                if isinstance(candidate['content'], str):
                                                                    content = candidate['content']
                                                                elif isinstance(candidate['content'], dict) and 'text' in candidate['content']:
                                                                    content = candidate['content']['text']
                                                
                                                if content is not None:
                                                    # Format in OpenAI streaming format
                                                    formatted_data = {
                                                        "id": str(uuid.uuid4()),
                                                        "object": "chat.completion.chunk",
                                                        "created": int(time.time()),
                                                        "model": "googleai-stream",
                                                        "choices": [{"delta": {"content": content}}]
                                                    }
                                                    json_data = formatted_data
                                            
                                            yield f"data: {json.dumps(json_data)}\n\n"
                                        except json.JSONDecodeError as e:
                                            logger.error(f"Error parsing streaming response: {e}, line: {line}")
                                            continue
                                        except Exception as e:
                                            logger.error(f"Error in Google AI streaming: {str(e)}")
                                            # Try to recover by sending an error message in the stream
                                            error_data = {
                                                "id": str(uuid.uuid4()),
                                                "object": "chat.completion.chunk",
                                                "created": int(time.time()),
                                                "model": "googleai-stream",
                                                "choices": [{"delta": {"content": f"Error: {str(e)}"}}]
                                            }
                                            yield f"data: {json.dumps(error_data)}\n\n"
                                            continue
                                
                                # Ensure we send the final [DONE] marker
                                yield "data: [DONE]\n\n"
                            except Exception as e:
                                logger.error(f"Critical error in Google AI streaming: {str(e)}")
                                error_data = {
                                    "id": str(uuid.uuid4()),
                                    "object": "chat.completion.chunk",
                                    "created": int(time.time()),
                                    "model": "googleai-stream",
                                    "choices": [{"delta": {"content": f"Critical streaming error: {str(e)}"}}]
                                }
                                yield f"data: {json.dumps(error_data)}\n\n"
                                yield "data: [DONE]\n\n"

                        streaming_response = Response(
                            generate(),
                            mimetype='text/event-stream',
                            headers={
                                'Cache-Control': 'no-cache',
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
                            
                        logger.debug("Google AI parsed response: %s", redact_payload(response_data))

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
                    logger.error("Google AI error response: %s", redact_text(error_content))
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

            logger.info("Original request data: %s", redact_payload(request_data))
            logger.info("Completion data: %s", redact_payload(completion_data))

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
                                "finish_reason": completion_response["choices"][0].get("finishReason", "stop")
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

    @staticmethod
    def _gemini_native_part(part: Dict[str, Any]) -> bool:
        native_keys = {
            "text",
            "inlineData",
            "inline_data",
            "fileData",
            "file_data",
            "functionCall",
            "function_call",
            "functionResponse",
            "function_response",
            "thoughtSignature",
            "thought_signature",
            "thought",
            "videoMetadata",
            "video_metadata",
            "executableCode",
            "codeExecutionResult",
        }
        return any(key in part for key in native_keys)

    @staticmethod
    def _normalize_gemini_part(part: Dict[str, Any]) -> Dict[str, Any]:
        normalized = {key: value for key, value in part.items() if key != "type"}
        snake_to_camel = {
            "inline_data": "inlineData",
            "file_data": "fileData",
            "function_call": "functionCall",
            "function_response": "functionResponse",
            "thought_signature": "thoughtSignature",
            "video_metadata": "videoMetadata",
        }

        for snake_key, camel_key in snake_to_camel.items():
            if snake_key in normalized and camel_key not in normalized:
                normalized[camel_key] = normalized[snake_key]
            normalized.pop(snake_key, None)

        for media_key in ("inlineData", "fileData"):
            media = normalized.get(media_key)
            if isinstance(media, dict):
                if "mime_type" in media and "mimeType" not in media:
                    media["mimeType"] = media["mime_type"]
                media.pop("mime_type", None)
                if "file_uri" in media and "fileUri" not in media:
                    media["fileUri"] = media["file_uri"]
                media.pop("file_uri", None)

        return normalized

    @staticmethod
    def _extract_google_thought_signature(value: Dict[str, Any]) -> Optional[str]:
        if not isinstance(value, dict):
            return None

        signature = value.get("thoughtSignature") or value.get("thought_signature")
        if signature:
            return signature

        extra_content = value.get("extra_content") or value.get("extraContent") or {}
        google_extra = extra_content.get("google", {}) if isinstance(extra_content, dict) else {}
        if isinstance(google_extra, dict):
            return google_extra.get("thought_signature") or google_extra.get("thoughtSignature")

        return None

    @staticmethod
    def _parse_gemini_function_args(value: Any) -> Dict[str, Any]:
        if value is None or value == "":
            return {}
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, dict) else {"value": parsed}
            except json.JSONDecodeError:
                return {"value": value}
        return {"value": value}

    @staticmethod
    def _parse_gemini_function_response(value: Any) -> Dict[str, Any]:
        if value is None or value == "":
            return {}
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, dict) else {"content": parsed}
            except json.JSONDecodeError:
                return {"content": value}
        return {"content": value}

    @staticmethod
    def _data_uri_to_gemini_inline_data(url: str) -> Optional[Dict[str, Any]]:
        match = re.match(r"^data:([^;,]+);base64,(.*)$", url, flags=re.DOTALL)
        if not match:
            return None
        return {"mimeType": match.group(1), "data": match.group(2)}

    @classmethod
    def _openai_content_to_gemini_parts(cls, content: Any) -> List[Dict[str, Any]]:
        if content is None:
            return []
        if isinstance(content, str):
            return [{"text": content}] if content else []
        if isinstance(content, dict):
            content = [content]
        if not isinstance(content, list):
            return [{"text": str(content)}]

        parts: List[Dict[str, Any]] = []
        for item in content:
            if item is None:
                continue
            if isinstance(item, str):
                if item:
                    parts.append({"text": item})
                continue
            if not isinstance(item, dict):
                parts.append({"text": str(item)})
                continue

            item_type = item.get("type")
            if item_type in ("text", "input_text"):
                part = {"text": item.get("text", "")}
                signature = cls._extract_google_thought_signature(item)
                if signature:
                    part["thoughtSignature"] = signature
                if "thought" in item:
                    part["thought"] = item["thought"]
                parts.append(part)
                continue

            if item_type in ("image_url", "input_image", "image"):
                image_value = item.get("image_url") or item.get("image") or item.get("url")
                image_url = image_value.get("url") if isinstance(image_value, dict) else image_value
                mime_type = item.get("mime_type") or item.get("mimeType")
                if isinstance(image_value, dict):
                    mime_type = (
                        mime_type
                        or image_value.get("mime_type")
                        or image_value.get("mimeType")
                    )
                if isinstance(image_url, str):
                    inline_data = cls._data_uri_to_gemini_inline_data(image_url)
                    if inline_data:
                        parts.append({"inlineData": inline_data})
                    else:
                        file_data = {"fileUri": image_url}
                        if mime_type:
                            file_data["mimeType"] = mime_type
                        parts.append({"fileData": file_data})
                continue

            if cls._gemini_native_part(item):
                parts.append(cls._normalize_gemini_part(item))
                continue

            if "text" in item:
                parts.append({"text": item.get("text", "")})

        return parts

    @classmethod
    def _openai_tool_calls_to_gemini_parts(cls, tool_calls: Any) -> List[Dict[str, Any]]:
        if not isinstance(tool_calls, list):
            return []

        parts: List[Dict[str, Any]] = []
        for tool_call in tool_calls:
            if not isinstance(tool_call, dict):
                continue
            if "functionCall" in tool_call or "function_call" in tool_call:
                parts.append(cls._normalize_gemini_part(tool_call))
                continue

            function_data = tool_call.get("function", {})
            if not isinstance(function_data, dict):
                continue

            function_call = {
                "name": function_data.get("name") or tool_call.get("name") or "function",
                "args": cls._parse_gemini_function_args(function_data.get("arguments", {})),
            }
            if tool_call.get("id"):
                function_call["id"] = tool_call["id"]

            part = {"functionCall": function_call}
            signature = cls._extract_google_thought_signature(tool_call)
            if signature:
                part["thoughtSignature"] = signature
            parts.append(part)

        return parts

    @classmethod
    def _openai_tool_message_to_gemini_parts(cls, message: Dict[str, Any]) -> List[Dict[str, Any]]:
        function_response = {
            "name": message.get("name") or message.get("tool_call_id") or "tool_response",
            "response": cls._parse_gemini_function_response(message.get("content")),
        }
        if message.get("tool_call_id"):
            function_response["id"] = message["tool_call_id"]

        return [{"functionResponse": function_response}]

    @classmethod
    def _openai_tools_to_gemini_tools(cls, tools: Any) -> Any:
        if not isinstance(tools, list):
            return tools

        native_tools: List[Dict[str, Any]] = []
        function_declarations: List[Dict[str, Any]] = []

        for tool in tools:
            if not isinstance(tool, dict):
                continue
            if "functionDeclarations" in tool or "google_search" in tool or "codeExecution" in tool:
                native_tools.append(tool)
                continue

            if tool.get("type") == "function" and isinstance(tool.get("function"), dict):
                function_data = tool["function"]
                declaration = {
                    "name": function_data.get("name"),
                }
                if function_data.get("description"):
                    declaration["description"] = function_data["description"]
                if function_data.get("parameters"):
                    declaration["parameters"] = function_data["parameters"]
                if declaration["name"]:
                    function_declarations.append(declaration)

        if function_declarations:
            native_tools.append({"functionDeclarations": function_declarations})

        return native_tools

    @classmethod
    def _openai_messages_to_gemini_request(cls, request_data: Dict[str, Any]) -> Dict[str, Any]:
        messages = request_data.get("messages", [])
        contents: List[Dict[str, Any]] = []
        system_parts: List[Dict[str, Any]] = []

        for message in messages:
            if not isinstance(message, dict):
                continue

            role = message.get("role", "user")
            content = message.get("content", message.get("parts"))

            if role in ("system", "developer"):
                system_parts.extend(cls._openai_content_to_gemini_parts(content))
                continue

            if role in ("tool", "function"):
                parts = cls._openai_tool_message_to_gemini_parts(message)
                gemini_role = "user"
            else:
                parts = cls._openai_content_to_gemini_parts(content)
                parts.extend(cls._openai_tool_calls_to_gemini_parts(message.get("tool_calls")))
                gemini_role = "model" if role in ("assistant", "model") else "user"

            if parts:
                contents.append({"role": gemini_role, "parts": parts})

        new_request_data: Dict[str, Any] = {"contents": contents}
        if system_parts:
            new_request_data["system_instruction"] = {"parts": system_parts}

        generation_config = dict(request_data.get("generationConfig") or {})
        parameter_map = {
            "temperature": "temperature",
            "max_tokens": "maxOutputTokens",
            "max_output_tokens": "maxOutputTokens",
            "top_p": "topP",
            "top_k": "topK",
            "stop": "stopSequences",
        }
        for openai_key, gemini_key in parameter_map.items():
            if openai_key in request_data:
                generation_config[gemini_key] = request_data[openai_key]
        if generation_config:
            new_request_data["generationConfig"] = generation_config

        if "tools" in request_data:
            new_request_data["tools"] = cls._openai_tools_to_gemini_tools(request_data["tools"])
        if "toolConfig" in request_data:
            new_request_data["toolConfig"] = request_data["toolConfig"]
        if "tool_config" in request_data and "toolConfig" not in new_request_data:
            new_request_data["toolConfig"] = request_data["tool_config"]
        if "safetySettings" in request_data:
            new_request_data["safetySettings"] = request_data["safetySettings"]

        return new_request_data

    @staticmethod
    def _gemini_count_tokens_url(url: str) -> str:
        if ":streamGenerateContent" in url:
            return url.replace(":streamGenerateContent", ":countTokens", 1)
        return url.replace(":generateContent", ":countTokens", 1)

    @staticmethod
    def _gemini_count_tokens_payload(request_data: Dict[str, Any]) -> Dict[str, Any]:
        count_payload = {
            "generateContentRequest": {
                key: value
                for key, value in request_data.items()
                if key in {
                    "contents",
                    "system_instruction",
                    "systemInstruction",
                    "tools",
                    "toolConfig",
                    "generationConfig",
                    "cachedContent",
                }
            }
        }
        return count_payload

    @classmethod
    def _gemini_parts_to_openai_message(cls, parts: List[Dict[str, Any]]) -> Dict[str, Any]:
        text_parts: List[str] = []
        tool_calls: List[Dict[str, Any]] = []
        message_extra: Dict[str, Any] = {}

        for part in parts:
            if not isinstance(part, dict):
                continue

            if "text" in part and part.get("text"):
                text_parts.append(part["text"])

            signature = cls._extract_google_thought_signature(part)
            if signature and "functionCall" not in part:
                message_extra.setdefault("google", {})["thought_signature"] = signature

            function_call = part.get("functionCall") or part.get("function_call")
            if isinstance(function_call, dict):
                call_id = function_call.get("id") or f"call_{uuid.uuid4().hex}"
                tool_call: Dict[str, Any] = {
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": function_call.get("name", "function"),
                        "arguments": json.dumps(function_call.get("args", {})),
                    },
                }
                if signature:
                    tool_call["extra_content"] = {
                        "google": {"thought_signature": signature}
                    }
                tool_calls.append(tool_call)

        message: Dict[str, Any] = {
            "role": "assistant",
            "content": "".join(text_parts),
        }
        if tool_calls:
            message["tool_calls"] = tool_calls
            if not message["content"]:
                message["content"] = None
        if message_extra:
            message["extra_content"] = message_extra

        return message

    @classmethod
    def _handle_gemini_request(
        cls,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        data: Optional[bytes],
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
            params = dict(params or {})
            headers = dict(headers or {})
            request_data = dict(request_data or {})
            original_url = url
            should_convert_to_openai_response = "/chat/completions" in original_url
            is_streaming_request = bool(request_data.pop("stream", False)) or ":streamGenerateContent" in url
            preflight_count_tokens = bool(request_data.pop("preflight_count_tokens", False))
            enable_google_search = bool(
                request_data.pop("webSearch", False)
                or request_data.pop("enable_google_search", False)
            )
            request_data.pop("webSearchSpec", None)

            # Extract API key from URL parameters and rebuild the URL without it
            api_key = None
            
            # Check if key is in params
            if params and 'key' in params:
                api_key = params.pop('key')
                if isinstance(api_key, (list, tuple)):
                    api_key = api_key[0] if api_key else None
                logger.info(f"Found API key in URL parameters for {api_provider}")
            
            # If no key in params, check if it's in the URL
            else:
                parsed_url = urlsplit(url)
                query_pairs = parse_qsl(parsed_url.query, keep_blank_values=True)
                filtered_query_pairs = []
                for key, value in query_pairs:
                    if key == 'key' and api_key is None:
                        api_key = value
                        logger.info(f"Found API key in URL for {api_provider}")
                    else:
                        filtered_query_pairs.append((key, value))

                if api_key is not None:
                    url = urlunsplit(
                        (
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            urlencode(filtered_query_pairs),
                            parsed_url.fragment,
                        )
                    )
            
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
            
            headers["x-goog-api-key"] = api_key
            
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
                    request_data = cls._openai_messages_to_gemini_request(request_data)

            if is_streaming_request:
                if ":generateContent" in url:
                    url = url.replace(":generateContent", ":streamGenerateContent", 1)
                params["alt"] = "sse"
                logger.info(f"Using Gemini streaming endpoint: {url}")
                
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
                
                if enable_google_search and api_provider == 'gemini':
                    tools = request_data.get("tools")
                    if not isinstance(tools, list):
                        tools = []
                        request_data["tools"] = tools

                    if not any(isinstance(tool, dict) and "google_search" in tool for tool in tools):
                        tools.append({"google_search": {}})
                    logger.info(f"Enabled Google Search grounding for Gemini model: {model}")

                if preflight_count_tokens and (
                    ":generateContent" in url or ":streamGenerateContent" in url
                ):
                    count_url = cls._gemini_count_tokens_url(url)
                    count_payload = cls._gemini_count_tokens_payload(request_data)
                    count_data = json.dumps(count_payload).encode("utf-8")
                    count_headers = dict(headers)
                    count_headers["Content-Length"] = str(len(count_data))
                    count_response = cls._make_base_request(
                        method="POST",
                        url=count_url,
                        headers=count_headers,
                        params=params,
                        data=count_data,
                        api_provider=api_provider,
                        use_cache=False,
                    )
                    if count_response.status_code >= 400:
                        logger.warning(
                            "Gemini countTokens preflight failed provider=%s status=%s",
                            api_provider,
                            count_response.status_code,
                        )
                        return count_response
                    try:
                        token_count = count_response.json().get("totalTokens")
                        logger.info(
                            "Gemini countTokens preflight provider=%s model=%s total_tokens=%s",
                            api_provider,
                            model,
                            token_count,
                        )
                    except ValueError:
                        logger.warning("Gemini countTokens preflight returned non-JSON response")
                
                # Re-encode the modified data
                data = json.dumps(request_data).encode('utf-8')
                headers["Content-Length"] = str(len(data))
                logger.info(f"Modified {api_provider} request data to disable safety settings")
            
            # Log the final URL with params
            full_url = url
            if params:
                param_str = '&'.join([f"{k}={v}" for k, v in params.items()])
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
                logger.error(
                    "Authentication failed for %s status=%s response=%s",
                    api_provider,
                    response.status_code,
                    redact_text(response.text),
                )
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
                    logger.error(
                        "Could not parse error response: %s, %s",
                        redact_text(response.text),
                        str(e),
                    )
                    
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
                if is_streaming_request:
                    # Handle streaming response
                    def generate_stream():
                        done_sent = False
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
                                            done_sent = True
                                            yield "data: [DONE]\n\n"
                                            if hasattr(response, "close"):
                                                response.close()
                                            return
                                        
                                        # Parse Google's SSE format
                                        google_chunk = json.loads(line_str)
                                        
                                        # For chat/completions endpoints, convert to OpenAI format
                                        if should_convert_to_openai_response:
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
                            if not done_sent:
                                yield "data: [DONE]\n\n"
                        except Exception as e:
                            logger.error(f"Error in Gemini streaming response: {str(e)}")
                            yield f"data: {json.dumps({'error': str(e)})}\n\n"
                            yield "data: [DONE]\n\n"
                        finally:
                            if hasattr(response, "close"):
                                response.close()
                    
                    # Return a streaming response
                    streaming_response = Response(
                        generate_stream(),
                        mimetype='text/event-stream',
                        headers={
                            'Cache-Control': 'no-cache',
                            'Content-Type': 'text/event-stream',
                            'X-Accel-Buffering': 'no'
                        }
                    )
                    return streaming_response
                elif should_convert_to_openai_response:
                    # Handle normal chat/completions response
                    try:
                        google_response = response.json()
                        
                        candidates = google_response.get("candidates", [{}])
                        first_candidate = candidates[0] if candidates else {}
                        content = first_candidate.get("content", {})
                        parts = content.get("parts", []) if isinstance(content, dict) else []
                        message = cls._gemini_parts_to_openai_message(parts)

                        # Create OpenAI compatible response
                        openai_response = {
                            "id": google_response.get("id", str(uuid.uuid4())),
                            "object": "chat.completion",
                            "created": int(time.time()),
                            "model": model,
                            "choices": [
                                {
                                    "index": 0,
                                    "message": message,
                                    "finish_reason": first_candidate.get("finishReason", "stop")
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
            logger.debug("Headers: %s", redact_headers(headers))
            if data:
                logger.debug("Request data: %s", redact_payload(request_data))
            
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
                logger.error(
                    "Authentication failed for OpenRouter status=%s response=%s",
                    response.status_code,
                    redact_text(response.text),
                )
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
                    logger.error(
                        "Could not parse error response: %s, %s",
                        redact_text(response.text),
                        str(e),
                    )
            
            # Check for streaming response
            if request_data.get('stream', False) and response.status_code == 200:
                def generate():
                    done_sent = False
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
                                        done_sent = True
                                        yield "data: [DONE]\n\n"
                                        if hasattr(response, "close"):
                                            response.close()
                                        return
                                    
                                    # Parse the chunk and pass it through
                                    json_data = json.loads(line_str)
                                    normalized_data = cls.normalize_json_text(json_data)
                                    yield f"data: {json.dumps(normalized_data)}\n\n"
                                    
                                except json.JSONDecodeError as e:
                                    logger.error(f"Error parsing streaming response: {e}, line: {line}")
                                    continue
                                except Exception as e:
                                    logger.error(f"Error processing streaming chunk: {e}")
                                    continue
                        
                        # Ensure final [DONE] marker
                        if not done_sent:
                            yield "data: [DONE]\n\n"
                    except Exception as e:
                        logger.error(f"Error in streaming generation: {str(e)}")
                        yield f"data: {json.dumps({'choices': [{'delta': {'content': str(e)}}]})}\n\n"
                        yield 'data: [DONE]\n\n'
                    finally:
                        if hasattr(response, "close"):
                            response.close()
                
                # Return a proper streaming response
                streaming_response = Response(
                    generate(),
                    mimetype='text/event-stream',
                    headers={
                        'Cache-Control': 'no-cache',
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
    def _standardize_streaming_chunk(cls, chunk: str, provider: str) -> str:
        """
        Standardize streaming response chunks from different providers to match OpenAI format.
        
        The OpenAI format for streaming is:
        data: {"id":"...", "object":"chat.completion.chunk", "choices":[{"delta":{"content":"token"}}]}
        
        Args:
            chunk: The chunk received from the provider
            provider: The provider name
            
        Returns:
            Standardized chunk in OpenAI-compatible SSE format
        """
        try:
            if isinstance(chunk, bytes):
                chunk = chunk.decode("utf-8")

            stripped_chunk = chunk.strip()
            if not stripped_chunk or stripped_chunk.startswith(":"):
                return ""

            if chunk.startswith("data: "):
                data_payload = chunk[6:].strip()
            else:
                data_payload = stripped_chunk
                
            # If the chunk is the completion signal
            if data_payload == '[DONE]':
                return 'data: [DONE]\n\n'

            # If the chunk is already an OpenAI-compatible SSE payload, preserve it
            if chunk.startswith("data: "):
                try:
                    parsed_payload = json.loads(data_payload)
                    if isinstance(parsed_payload, dict) and (
                        parsed_payload.get("object") == "chat.completion.chunk" or
                        "choices" in parsed_payload
                    ):
                        parsed_payload = sanitize_openai_stream_payload(parsed_payload)
                        normalized_payload = cls.normalize_json_text(parsed_payload)
                        return f"data: {json.dumps(normalized_payload)}\n\n"
                except json.JSONDecodeError:
                    pass

            stripped_embedded_payload = cls._strip_embedded_stream_chunk_payload(stripped_chunk)
            if stripped_embedded_payload is not None:
                if not stripped_embedded_payload:
                    return ""
                chunk = stripped_embedded_payload
                stripped_chunk = chunk.strip()
                data_payload = stripped_chunk
                
            # Extract content from provider-specific format
            content = None
            
            # Handle provider-specific formats
            if provider == 'anthropic':
                # Anthropic format handling
                if 'completion' in chunk:
                    try:
                        data = json.loads(chunk.replace('data: ', ''))
                        content = data.get('completion', '')
                    except json.JSONDecodeError:
                        content = chunk
            elif provider == 'gemini' or provider == 'gemma':
                # Google Gemini/Gemma format handling
                try:
                    if chunk.startswith('data: '):
                        data = json.loads(chunk.replace('data: ', ''))
                        if 'candidates' in data:
                            content = data['candidates'][0]['content']['parts'][0]['text']
                    else:
                        content = chunk
                except (json.JSONDecodeError, KeyError, IndexError):
                    content = chunk
            elif provider == 'together':
                # Together AI format handling
                try:
                    if chunk.startswith('data: '):
                        data = json.loads(chunk.replace('data: ', ''))
                        if 'choices' in data and len(data['choices']) > 0:
                            content = data['choices'][0].get('text', '') or data['choices'][0].get('delta', {}).get('content', '')
                except (json.JSONDecodeError, KeyError, IndexError):
                    content = chunk
            else:
                # Generic handling for other providers
                try:
                    # Try to parse as JSON
                    if chunk.startswith('data: '):
                        chunk = data_payload
                    
                    # Handle case where chunk is already JSON
                    if chunk.strip().startswith('{'):
                        data = json.loads(chunk)
                        # Look for content in common places
                        if 'choices' in data and len(data['choices']) > 0:
                            content = data['choices'][0].get('text', '') or data['choices'][0].get('delta', {}).get('content', '')
                        elif 'text' in data:
                            content = data['text']
                    else:
                        # If not JSON, use the raw text
                        content = chunk
                except (json.JSONDecodeError, KeyError):
                    content = chunk
            
            # If content extraction failed, use the raw chunk
            if content is None:
                content = chunk
            elif isinstance(content, str):
                content = cls._repair_mojibake_text(content)
                
            # Create OpenAI-compatible format
            formatted_chunk = {
                "id": str(uuid.uuid4()),
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": "provider-stream",
                "choices": [{"delta": {"content": content}}]
            }
            
            return f"data: {json.dumps(formatted_chunk)}\n\n"
        except Exception as e:
            logger.error(f"Error standardizing streaming chunk: {str(e)}")
            # Return a safe fallback
            return f"data: {json.dumps({'choices': [{'delta': {'content': chunk}}]})}\n\n"

    @staticmethod
    def _iter_stream_lines(response: requests.Response) -> Generator[str, None, None]:
        content_type = response.headers.get("content-type", "").lower()
        if content_type.startswith("text/event-stream") and hasattr(response, "iter_content"):
            try:
                for data_payload in iter_sse_data(response.iter_content(chunk_size=1024)):
                    yield f"data: {data_payload}"
                return
            except Exception as error:
                logger.warning("SSE parser failed, falling back to line iteration: %s", error)

        for line in response.iter_lines(decode_unicode=True):
            yield line

    @classmethod
    def _create_streaming_response(cls, response: requests.Response, provider: str) -> Generator:
        """
        Create a generator for streaming responses that standardizes the output format.
        
        Args:
            response: The streaming response from the provider
            provider: The provider name
            
        Returns:
            A generator yielding standardized chunks
        """
        try:
            is_gzipped = response.headers.get('content-encoding', '').lower() == 'gzip'
            done_sent = False
            inside_reasoning_block = False
            
            # For gzipped responses, we need to accumulate and decompress
            if is_gzipped:
                buffer = io.BytesIO()
                
                # Read raw response in chunks
                for chunk in response.iter_content(chunk_size=1024):
                    if not chunk:
                        break
                    buffer.write(chunk)
                
                # Decompress and process
                buffer.seek(0)
                with gzip.GzipFile(fileobj=buffer, mode='rb') as gz:
                    decompressed = gz.read().decode('utf-8')
                    parsed_lines = [
                        f"data: {payload}"
                        for payload in iter_sse_data([decompressed])
                    ]
                    lines = parsed_lines or decompressed.split('\n')
                    for line in lines:
                        if provider == "opencode":
                            line, inside_reasoning_block = cls._strip_reasoning_block_markup(
                                line,
                                inside_reasoning_block,
                            )
                            if not line:
                                continue
                        standardized_chunk = cls._standardize_streaming_chunk(line, provider)
                        if standardized_chunk:
                            if standardized_chunk.strip() == "data: [DONE]":
                                done_sent = True
                                yield standardized_chunk
                                if hasattr(response, "close"):
                                    response.close()
                                return
                            yield standardized_chunk
                
                # Signal completion
                if not done_sent:
                    yield 'data: [DONE]\n\n'
            else:
                # For non-gzipped responses
                for line in cls._iter_stream_lines(response):
                    if provider == "opencode":
                        line, inside_reasoning_block = cls._strip_reasoning_block_markup(
                            line,
                            inside_reasoning_block,
                        )
                        if not line:
                            continue
                    standardized_chunk = cls._standardize_streaming_chunk(line, provider)
                    if standardized_chunk:
                        if standardized_chunk.strip() == "data: [DONE]":
                            done_sent = True
                            yield standardized_chunk
                            if hasattr(response, "close"):
                                response.close()
                            return
                        yield standardized_chunk
                
                # Signal completion
                if not done_sent:
                    yield 'data: [DONE]\n\n'
        except Exception as e:
            logger.error(f"Error in streaming response processing: {str(e)}")
            error_msg = f"Error: {str(e)}"
            yield f"data: {json.dumps({'choices': [{'delta': {'content': error_msg}}]})}\n\n"
            yield 'data: [DONE]\n\n'
        finally:
            if hasattr(response, "close"):
                response.close()

    @classmethod
    def make_request(
        cls,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        data: Optional[bytes],
        api_provider: str,
        use_cache: bool = True,
    ) -> requests.Response:
        """
        Make a request with retries and error handling
        """
        logger.info(f"Making request to {url} with method {method}")
        
        try:
            # Check if this is a streaming request
            request_data = cls._decode_json_request_data(data)
            is_streaming = bool(request_data.get('stream', False))
            
            # Extract authentication tokens/keys if needed
            auth_token = None
            auth_header = headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                auth_token = auth_header.replace('Bearer ', '').strip()
                logger.debug(f"Extracted auth token from header: {auth_token[:5]}...")
            
            # Special handling for different providers
            if api_provider == "together":
                return cls._handle_together_request(
                    method, url, headers, params, data, request_data, use_cache
                )
            elif api_provider == "groq":
                return cls._handle_groq_request(
                    method, url, headers, params, data, request_data, use_cache
                )
            elif api_provider == "googleai":
                if not request_data:
                    return cls._make_base_request(
                        method=method,
                        url=url,
                        headers=headers,
                        params=params,
                        data=data,
                        api_provider=api_provider,
                        use_cache=use_cache,
                    )
                return cls._handle_googleai_request(
                    method, url, headers, params, data, request_data, use_cache
                )
            elif api_provider == "gemini" or api_provider == "gemma":
                # For Gemini/Gemma, pass the auth token extracted from header if available
                return cls._handle_gemini_request(
                    method, url, headers, params, data, request_data, use_cache, api_provider, auth_token
                )
            elif api_provider == "nineteen":
                model = request_data.get("model")
                if model in cls.MODEL_MAPPINGS:
                    # Map the model to a supported one
                    request_data["model"] = cls.MODEL_MAPPINGS[model]
                    data = json.dumps(request_data).encode('utf-8')
                    headers["Content-Length"] = str(len(data))
                    logger.info(f"Mapped model {model} to {request_data['model']}")
            elif api_provider == "openrouter":
                return cls._handle_openrouter_request(
                    method, url, headers, params, data, request_data, use_cache, auth_token
                )

            # For all other providers, use the base request but prepare for streaming if needed
            response = cls._make_base_request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                api_provider=api_provider,
                use_cache=use_cache
            )
            
            # If the response should be streamed, wrap it in a streaming response
            if is_streaming and response.headers.get('content-type', '').startswith(('text/event-stream', 'application/json')):
                # Create a Flask response that yields from our generator
                return Response(
                    cls._create_streaming_response(response, api_provider),
                    content_type='text/event-stream',
                    headers={
                        'Cache-Control': 'no-cache',
                        'X-Accel-Buffering': 'no'
                    }
                )
            
            return response
        except Exception as e:
            error_msg = f"Error in make_request: {str(e)}"
            logger.error(error_msg)
            if isinstance(e, APIError):
                raise
            raise APIError(error_msg, status_code=500)

    @staticmethod
    def _decode_json_request_data(data: Optional[bytes]) -> Dict[str, Any]:
        """
        Decode an optional JSON request body for provider-specific dispatch.
        """
        if not data:
            return {}

        parsed = json.loads(data)
        if isinstance(parsed, dict):
            return parsed
        return {}

    @classmethod
    def shutdown(cls):
        """
        Cleanup resources.
        """
        cls._executor.shutdown(wait=False)
