import os
from flask import Flask
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def init_vercel():
    """Initialize Vercel-specific configuration"""
    # Ensure required directories exist
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('static/img', exist_ok=True)
    
    # Set default environment variables if not set
    if not os.environ.get('FLASK_ENV'):
        os.environ['FLASK_ENV'] = 'production'
    
    # Set default admin API key if not set
    if not os.environ.get('ADMIN_API_KEY'):
        os.environ['ADMIN_API_KEY'] = os.environ.get('VERCEL_ADMIN_API_KEY', 'default-key') 