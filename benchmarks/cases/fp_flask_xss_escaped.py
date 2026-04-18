# BENCHMARK CASE: False Positive — XSS mitigated by html.escape
# CWE-79 | Source: request.args.get | html.escape sanitizer | Sink: make_response
import html
from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # html.escape properly neutralises XSS payloads
    safe_name = html.escape(name)
    response_body = f"<h1>Hello, {safe_name}!</h1>"
    return make_response(response_body, 200, {"Content-Type": "text/html"})
