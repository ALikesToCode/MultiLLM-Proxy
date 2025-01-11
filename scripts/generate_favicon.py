from PIL import Image, ImageDraw

def create_favicon():
    # Create a new image with a transparent background
    img = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw a simple icon (a filled circle)
    draw.ellipse([4, 4, 28, 28], fill='#4F46E5')
    
    # Save as ICO
    img.save('static/favicon.ico', format='ICO')

if __name__ == '__main__':
    create_favicon() 