import requests
import json
from error_handlers import APIError
import logging
from config import Config

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

    @staticmethod
    def make_request(method, url, headers, params, data, timeout=Config.REQUEST_TIMEOUT):
        try:
            logger.info(f"Making {method} request to {url}")
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                stream=True,
                timeout=timeout
            )
            
            logger.info(f"Response status: {response.status_code}")
            
            if response.status_code >= 400:
                raise APIError(
                    f"API request failed: {response.text}",
                    status_code=response.status_code
                )
                
            return response
            
        except requests.exceptions.Timeout:
            raise APIError("Request timed out", status_code=504)
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request failed: {str(e)}", status_code=500) 