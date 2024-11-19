#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status messages
print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Main setup process
main() {
    print_status "Starting MultiLLM Proxy setup..."
    
    # Create virtual environment
    print_status "Setting up Python virtual environment..."
    python -m venv venv
    source venv/bin/activate
    
    # Install dependencies
    print_status "Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    
    # Create necessary directories
    print_status "Creating necessary directories..."
    mkdir -p static/css static/js templates
    
    # Setup environment variables
    print_status "Setting up environment variables..."
    if [ ! -f ".env" ]; then
        cp .env.example .env
        print_status "Created .env file from example"
        print_warning "Please edit .env file with your API keys"
    else
        print_warning ".env file already exists, skipping creation"
    fi
    
    print_status "Setup completed successfully!"
    print_warning "Next steps:"
    echo "1. Edit the .env file with your API keys"
    echo "2. Start the application with 'python app.py'"
}

# Run main setup
main 