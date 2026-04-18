# BENCHMARK CASE: True Positive — Command injection via os.system
# CWE-78 | Source: request.args.get | Sink: os.system
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # Unsanitized host parameter passed directly to shell — command injection
    exit_code = os.system(f"ping -c 1 {host}")
    return f"ping returned {exit_code}"
