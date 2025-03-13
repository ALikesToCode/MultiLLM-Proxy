#!/bin/bash

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Load the admin API key from .env file
ADMIN_API_KEY=$(grep -oP 'ADMIN_API_KEY=\K.+' .env)

if [ -z "$ADMIN_API_KEY" ]; then
  echo -e "${RED}Error: Could not find ADMIN_API_KEY in .env file${NC}"
  exit 1
fi

echo -e "${BLUE}${BOLD}=== Testing OpenRouter Integration ===${NC}"

echo -e "\n${YELLOW}Testing OpenRouter models list...${NC}"
curl -s -X GET "http://localhost:1400/openrouter/models" \
  -H "Authorization: Bearer $ADMIN_API_KEY" | jq

echo -e "\n${YELLOW}Testing OpenRouter with GPT-4o...${NC}"
curl -s -X POST "http://localhost:1400/openrouter/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -d '{
    "model": "openai/gpt-4o", 
    "messages": [
      {"role": "user", "content": "What is the meaning of life? (Keep your answer very short)"}
    ]
  }' | jq

echo -e "\n${YELLOW}Testing OpenRouter with Claude-3-Sonnet (streaming mode)...${NC}"
echo -e "${GREEN}Response will stream below:${NC}"
curl -N -X POST "http://localhost:1400/openrouter/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -d '{
    "model": "anthropic/claude-3-sonnet", 
    "messages": [
      {"role": "user", "content": "Explain the concept of REST APIs in 2-3 sentences."}
    ],
    "stream": true
  }'

echo -e "\n\n${BLUE}${BOLD}=== Test Complete ===${NC}"
echo -e "\nIf you see meaningful responses above, your OpenRouter integration is working correctly!"
echo -e "If you're seeing errors, please check ${YELLOW}docs/openrouter_setup.md${NC} for troubleshooting tips." 