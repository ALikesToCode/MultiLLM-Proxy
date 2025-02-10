from flask import Flask, request
from app import create_app
from vercel import init_vercel

# Initialize Vercel environment
init_vercel()

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
    except Exception as e:
        # Return error response
        return {
            'statusCode': 500,
            'body': str(e),
            'headers': {'Content-Type': 'text/plain'}
        } 