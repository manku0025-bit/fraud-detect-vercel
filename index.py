from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Hello from Vercel!"

# Vercel needs this:
def handler(request, context):
    return app(request, context)
