#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Create necessary directories
mkdir -p static/css
mkdir -p static/js
mkdir -p static/img

# Generate a simple default favicon if the script fails
python - << EOF
from PIL import Image, ImageDraw
img = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)
draw.ellipse([4, 4, 28, 28], fill='#4F46E5')
img.save('static/favicon.ico', format='ICO')
EOF

# Set permissions
chmod -R 755 static 