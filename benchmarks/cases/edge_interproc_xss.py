# BENCHMARK CASE: Edge — Inter-procedural XSS (source and sink in different functions)
# CWE-79 | Source: request.args.get (in helper) | Sink: make_response (in main route)
# This tests whether the pipeline can follow data flow across function call boundaries.
from flask import Flask, request, make_response

app = Flask(__name__)


def get_user_name() -> str:
    """Returns unsanitized user name from query parameter."""
    return request.args.get("name", "world")


@app.route("/greet")
def greet():
    # name comes from a helper function — inter-procedural taint flow
    name = get_user_name()
    html = f"<h1>Hello, {name}!</h1>"
    return make_response(html, 200, {"Content-Type": "text/html"})
