import json
import logging
import secrets

from vercel import init_vercel

logger = logging.getLogger(__name__)

# Initialize Vercel environment
init_vercel()

# Import after Vercel env initialization because app import validates secrets.
from app import create_app

# Create Flask app
app = create_app()

def handler(request):
    """Handle Vercel serverless function requests."""
    try:
        with app.test_client() as test_client:
            # Convert Vercel request to Flask request context
            method = request.get('method', 'GET')
            path = request.get('path', '/')
            headers = request.get('headers', {})
            body = request.get('body', '')
            
            # Make the request to Flask app
            response = test_client.open(
                path,
                method=method,
                headers=headers,
                data=body
            )
            
            # Return response in Vercel format
            return {
                'statusCode': response.status_code,
                'headers': dict(response.headers),
                'body': response.get_data(as_text=True)
            }
    except Exception as error:
        request_id = f"req_{secrets.token_urlsafe(12)}"
        logger.error(
            "Vercel request handling failed request_id=%s type=%s",
            request_id,
            type(error).__name__,
        )
        return {
            'statusCode': 500,
            'body': json.dumps(
                {
                    'error': 'internal_error',
                    'message': 'An unexpected error occurred.',
                    'request_id': request_id,
                }
            ),
            'headers': {
                'Content-Type': 'application/json',
                'X-Request-ID': request_id,
            }
        }
