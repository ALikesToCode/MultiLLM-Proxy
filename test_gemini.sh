#!/bin/bash

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Testing Gemini API Integration with Streaming ===${NC}"

# Get the admin API key from .env
ADMIN_API_KEY=$(grep -o 'ADMIN_API_KEY=.*' .env | cut -d = -f 2)

if [ -z "$ADMIN_API_KEY" ]; then
    echo -e "${RED}Error: ADMIN_API_KEY not found in .env${NC}"
    exit 1
fi

# Test OpenAI-compatible endpoint
echo -e "\n${YELLOW}Testing OpenAI-compatible endpoint (/chat/completions)${NC}"
echo -e "${GREEN}curl -X POST \"http://localhost:1400/gemini/chat/completions\" \
    -H \"Content-Type: application/json\" \
    -H \"Authorization: Bearer $ADMIN_API_KEY\" \
    -d '{\"model\": \"gemini-2.0-flash\", \"messages\": [{\"role\": \"user\", \"content\": \"Write a short poem about code\"}], \"stream\": true}'${NC}"

curl -X POST "http://localhost:1400/gemini/chat/completions" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_API_KEY" \
    -d '{"model": "gemini-2.0-flash", "messages": [{"role": "user", "content": "Write a short poem about code"}], "stream": true}'

echo -e "\n\n${YELLOW}Testing direct Gemini API endpoint${NC}"
echo -e "${GREEN}curl -X POST \"http://localhost:1400/gemini/v1beta/models/gemini-2.0-flash:generateContent\" \
    -H \"Content-Type: application/json\" \
    -H \"Authorization: Bearer $ADMIN_API_KEY\" \
    -d '{\"contents\": [{\"parts\": [{\"text\": \"Write a short poem about AI\"}]}], \"stream\": true}'${NC}"

curl -X POST "http://localhost:1400/gemini/v1beta/models/gemini-2.0-flash:generateContent" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_API_KEY" \
    -d '{"contents": [{"parts": [{"text": "Write a short poem about AI"}]}], "stream": true}'

echo -e "\n\n${BLUE}=== Tests completed ===${NC}" 