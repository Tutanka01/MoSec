# BENCHMARK CASE: True Positive — Flask XSS via unescaped query parameter
# CWE-79 | Source: request.args.get | Sink: Response HTML body
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # Unescaped user input directly interpolated into HTML — XSS
    html = f"<h1>Hello, {name}!</h1>"
    return make_response(html, 200, {"Content-Type": "text/html"})
