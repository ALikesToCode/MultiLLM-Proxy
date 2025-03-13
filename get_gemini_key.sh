#!/bin/bash

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BLUE}${BOLD}=== MultiLLM-Proxy: Gemini API Key Setup Guide ===${NC}"
echo -e "\nThis script will help you set up a Gemini API key for use with MultiLLM-Proxy."
echo -e "\n${YELLOW}Step 1:${NC} Go to ${GREEN}https://aistudio.google.com${NC} in your web browser"
echo -e "${YELLOW}Step 2:${NC} Sign in with your Google account"
echo -e "${YELLOW}Step 3:${NC} Click on \"Get API key\" in the left-hand menu"
echo -e "${YELLOW}Step 4:${NC} Create a new API key (it will start with \"AIza...\")"
echo -e "${YELLOW}Step 5:${NC} Copy your API key"

read -p "$(echo -e "\n${BOLD}Would you like to add your Gemini API key to .env file now?${NC} (y/n): ")" choice

if [[ "$choice" =~ ^[Yy]$ ]]; then
    read -p "$(echo -e "Enter your Gemini API key: ")" gemini_key
    
    if [[ ! "$gemini_key" =~ ^AIza ]]; then
        echo -e "\n${RED}Error: The key you entered doesn't start with 'AIza'.${NC}"
        echo -e "Gemini API keys should start with 'AIza'. Please check your key and try again."
        exit 1
    fi
    
    # Check if .env file exists
    if [ ! -f ".env" ]; then
        echo -e "\n${RED}Error: .env file not found${NC}"
        exit 1
    fi
    
    # Update the .env file
    if grep -q "GEMINI_API_KEY=" .env; then
        # Replace existing key
        sed -i "s|GEMINI_API_KEY=.*|GEMINI_API_KEY=$gemini_key|" .env
    else
        # Add new key
        echo "GEMINI_API_KEY=$gemini_key" >> .env
    fi
    
    # Also update GEMMA_API_KEY to use the same key
    if grep -q "GEMMA_API_KEY=" .env; then
        # Replace existing key
        sed -i "s|GEMMA_API_KEY=.*|GEMMA_API_KEY=$gemini_key|" .env
    else
        # Add new key
        echo "GEMMA_API_KEY=$gemini_key" >> .env
    fi
    
    echo -e "\n${GREEN}Success!${NC} Your Gemini API key has been added to the .env file."
    echo -e "\nYou can now test your Gemini API setup with: ${YELLOW}./test_gemini.sh${NC}"
    echo -e "Or read more about Gemini usage in ${YELLOW}docs/gemini_setup.md${NC}"
else
    echo -e "\nYou can manually add your Gemini API key to the .env file:"
    echo -e "${YELLOW}GEMINI_API_KEY=your_key_here${NC}"
    echo -e "${YELLOW}GEMMA_API_KEY=your_key_here${NC} (same key as above)"
    echo -e "\nSee ${YELLOW}docs/gemini_setup.md${NC} for more information."
fi

echo -e "\n${BLUE}${BOLD}=== Setup Guide Complete ===${NC}" 