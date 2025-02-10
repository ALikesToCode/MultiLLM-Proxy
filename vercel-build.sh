#!/bin/bash

# Install system dependencies for CairoSVG
apt-get update && apt-get install -y \
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    shared-mime-info

# Install Python dependencies
pip install -r requirements.txt

# Generate favicons
python scripts/generate_favicons.py

# Create necessary directories
mkdir -p static/css
mkdir -p static/js
mkdir -p static/img

# Set permissions
chmod -R 755 static 