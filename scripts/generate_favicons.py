import os
import cairosvg
from PIL import Image
import logging

logger = logging.getLogger(__name__)

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def generate_favicons():
    # Add error handling and logging
    try:
        static_dir = os.path.join(os.path.dirname(__file__), '..', 'static')
        ensure_dir(static_dir)
        
        # Check if source SVG exists
        svg_path = os.path.join(static_dir, 'favicon.svg')
        if not os.path.exists(svg_path):
            logger.error(f"Source favicon.svg not found at {svg_path}")
            # Generate a default favicon if SVG is missing
            generate_default_favicon()
            return
            
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
    except Exception as e:
        logger.error(f"Error generating favicons: {str(e)}")
        # Generate a default favicon on error
        generate_default_favicon()

def generate_default_favicon():
    """Generate a simple default favicon if the SVG source is missing"""
    from PIL import Image
    static_dir = os.path.join(os.path.dirname(__file__), '..', 'static')
    ensure_dir(static_dir)
    
    # Create a 32x32 black square as default favicon
    img = Image.new('RGB', (32, 32), color='black')
    img.save(os.path.join(static_dir, 'favicon.ico'))

if __name__ == '__main__':
    generate_favicons() 