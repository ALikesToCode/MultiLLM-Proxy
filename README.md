# MultiLLM Proxy

A robust API proxy service that provides unified access to multiple LLM (Large Language Model) providers including OpenAI, Cerebras, X.AI, and Google AI. This service simplifies the integration and management of multiple AI model providers through a single interface.

## Features

- 🔄 Unified proxy interface for multiple LLM providers
- 🔑 Secure API key management
- 🚦 Real-time status monitoring
- 📝 Interactive API documentation
- 🔌 Easy-to-use REST endpoints
- 🛡️ Error handling and rate limiting
- 🎯 Dynamic configuration
- 📊 Beautiful dashboard interface

## Supported Providers

- OpenAI
- Cerebras
- X.AI
- Google AI Platform

## Prerequisites

- Python 3.8+
- Flask
- Google Cloud SDK (for Google AI Platform)
- Valid API keys for the providers you want to use

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/multillm-proxy.git
    cd multillm-proxy
    ```

2. Create a virtual environment and activate it:
    ```bash
    python -m venv venv
    source venv/bin/activate # On Windows: venv\Scripts\activate
    ```

3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Copy the example environment file and update it with your credentials:
    ```bash
    cp .env.example .env
    ```

5. Update the `.env` file with your API keys and other configurations:
    ```env
    OPENAI_API_KEY=your-openai-api-key
    CEREBRAS_API_KEY=your-cerebras-api-key
    XAI_API_KEY=your-xai-api-key
    GOOGLE_APPLICATION_CREDENTIALS=path-to-your-credentials.json
    SERVER_HOST=localhost
    SERVER_PORT=1400
    ```

## Usage

1. Start the application:
    ```bash
    python app.py
    ```

2. Access the application in your browser:
    ```
    http://localhost:1400
    ```

3. Example API requests:
    ```bash
    curl -X POST "http://localhost:1400/openai/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model": "gpt-3.5-turbo","messages": [{"role": "user","content": "Hello!"}]}'
    ```

    ```bash
    curl -X POST "http://localhost:1400/cerebras/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model": "llama3.1-70b","messages": [{"role": "user","content": "Hello!"}]}'
    ```

    ```bash
    curl -X POST "http://localhost:1400/xai/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model": "xai-1.0","messages": [{"role": "user","content": "Hello!"}]}'
    ```

    ```bash
    curl -X POST "http://localhost:1400/googleai/predict" \
    -H "Content-Type: application/json" \
    -d '{
    "instances": [{
    "prompt": "What is the capital of France?"
    }]
    }'
    ```

## Development

1. Set the environment to development:
    ```bash
    export FLASK_ENV=development
    ```

2. Run the application:
    ```bash
    python app.py
    ```

3. Run tests:
    ```bash
    pytest
    ```

4. Lint and format the code:
    ```bash
    flake8 .
    black .
    ```

## Deployment

1. Build the Docker image:
    ```bash
    docker build -t multillm-proxy .
    ```

2. Run the Docker container:
    ```bash
    docker run -p 1400:1400 multillm-proxy
    ```

3. Deploy with Gunicorn:
    ```bash
    gunicorn -w 4 -b 0.0.0.0:1400 app:app
    ```

## Contributing

1. Create a new branch for your feature:
    ```bash
    git checkout -b feature/amazing-feature
    ```

2. Commit your changes:
    ```bash
    git commit -m 'Add amazing feature'
    ```

3. Push to the branch:
    ```bash
    git push origin feature/amazing-feature
    ```

## Project Structure
