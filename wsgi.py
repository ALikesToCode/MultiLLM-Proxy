from app import create_app

app = create_app()

# This is needed for Vercel
def handler(request, context):
    return app(request, context)

if __name__ == '__main__':
    app.run() 