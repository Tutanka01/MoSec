# BENCHMARK CASE: True Positive — Path traversal via open()
# CWE-22 | Source: request.args.get | Sink: open()
from flask import Flask, request

app = Flask(__name__)
BASE_DIR = "/var/app/files"

@app.route("/read")
def read_file():
    filename = request.args.get("filename")
    # No path sanitization — directory traversal possible
    with open(f"{BASE_DIR}/{filename}") as f:
        contents = f.read()
    return contents
