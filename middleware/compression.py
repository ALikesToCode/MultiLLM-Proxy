from flask import request, Response
import gzip
import functools

def compress_response(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        response = f(*args, **kwargs)
        
        # Check if client accepts gzip
        if 'gzip' not in request.headers.get('Accept-Encoding', ''):
            return response
            
        # Handle different response types
        if isinstance(response, str):
            data = response.encode('utf-8')
        elif isinstance(response, Response):
            data = response.get_data()
        else:
            return response
            
        # Don't compress small responses
        if len(data) < 500:
            return response
            
        gzip_buffer = gzip.compress(data)
        
        if isinstance(response, Response):
            response.set_data(gzip_buffer)
            response.headers['Content-Encoding'] = 'gzip'
            response.headers['Content-Length'] = len(gzip_buffer)
            return response
        else:
            headers = {
                'Content-Encoding': 'gzip',
                'Content-Length': len(gzip_buffer)
            }
            return Response(gzip_buffer, headers=headers)
            
    return wrapped 