import requests
import json
import logging
from error_handlers import APIError
from config import Config
from services.cache_service import CacheService
from services.rate_limit_service import RateLimitService

logger = logging.getLogger(__name__)

class ProxyService:
    @staticmethod
    def prepare_headers(original_headers, api_provider, auth_token):
        headers = dict(original_headers)
        headers.pop('Host', None)
        headers['Authorization'] = f'Bearer {auth_token}'
        return headers

    @staticmethod
    def filter_request_data(api_provider, request_data):
        if not request_data:
            return request_data
            
        try:
            data = json.loads(request_data)
            unsupported = Config.UNSUPPORTED_PARAMS.get(api_provider, [])
            for param in unsupported:
                data.pop(param, None)
            return json.dumps(data).encode()
        except json.JSONDecodeError:
            return request_data

    @classmethod
    def make_request(cls, method, url, headers, params, data, api_provider=None, use_cache=True):
        # Check rate limits
        if RateLimitService.is_rate_limited(api_provider):
            raise APIError("Rate limit exceeded", status_code=429)

        # Try to get from cache for GET requests
        if use_cache and method.upper() == 'GET':
            cache_key = CacheService.generate_cache_key(method, url, data)
            cached_response = CacheService.get(cache_key)
            if cached_response:
                logger.info(f"Cache hit for {url}")
                return cached_response

        try:
            logger.info(f"Making {method} request to {url}")
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                stream=True,
                timeout=Config.REQUEST_TIMEOUT
            )
            
            logger.info(f"Response status: {response.status_code}")
            
            if response.status_code >= 400:
                raise APIError(
                    f"API request failed: {response.text}",
                    status_code=response.status_code
                )

            # Cache successful GET responses
            if use_cache and method.upper() == 'GET' and response.status_code == 200:
                cache_key = CacheService.generate_cache_key(method, url, data)
                CacheService.set(cache_key, response)
                
            return response
            
        except requests.exceptions.Timeout:
            raise APIError("Request timed out", status_code=504)
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request failed: {str(e)}", status_code=500) 