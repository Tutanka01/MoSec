# BENCHMARK CASE: False Positive — Command injection mitigated by shlex.quote
# CWE-78 | Source: request.args.get | shlex.quote sanitizer | Sink: subprocess.run
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # shlex.quote properly escapes shell metacharacters
    safe_host = shlex.quote(host)
    result = subprocess.run(
        f"ping -c 1 {safe_host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout
