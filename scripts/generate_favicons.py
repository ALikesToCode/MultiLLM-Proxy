import os
import cairosvg
from PIL import Image

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def generate_favicons():
    # Ensure static directory exists
    static_dir = os.path.join(os.path.dirname(__file__), '..', 'static')
    ensure_dir(static_dir)
    
    # Read the SVG content
    svg_path = os.path.join(static_dir, 'favicon.svg')
    
    # Generate PNG versions
    sizes = {
        'favicon-16x16.png': 16,
        'favicon-32x32.png': 32,
        'favicon-192x192.png': 192,
        'favicon-512x512.png': 512,
        'apple-touch-icon.png': 180
    }
    
    for filename, size in sizes.items():
        output_path = os.path.join(static_dir, filename)
        cairosvg.svg2png(
            url=svg_path,
            write_to=output_path,
            output_width=size,
            output_height=size
        )
    
    # Create ICO file
    ico_path = os.path.join(static_dir, 'favicon.ico')
    img = Image.open(os.path.join(static_dir, 'favicon-32x32.png'))
    img.save(ico_path)
    
    # Create web manifest
    manifest = {
        "name": "MultiLLM Proxy",
        "short_name": "MultiLLM",
        "icons": [
            {
                "src": "/static/favicon-192x192.png",
                "sizes": "192x192",
                "type": "image/png"
            },
            {
                "src": "/static/favicon-512x512.png",
                "sizes": "512x512",
                "type": "image/png"
            }
        ],
        "theme_color": "#4F46E5",
        "background_color": "#ffffff",
        "display": "standalone"
    }
    
    import json
    with open(os.path.join(static_dir, 'site.webmanifest'), 'w') as f:
        json.dump(manifest, f, indent=2)

if __name__ == '__main__':
    generate_favicons() 