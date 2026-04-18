# BENCHMARK CASE: Edge — Sanitizer exists but is bypassed via alternate code path
# CWE-89 | Source: request.args.get | Sink: cursor.execute
# The sanitize function is defined but not always called — conditional bypass.
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def sanitize_id(value: str) -> str:
    """Attempt to sanitize — but only called on certain paths."""
    return value.replace("'", "''")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    if user_id and user_id.isdigit():
        # Safe path: input is numeric, no injection possible
        safe_id = sanitize_id(user_id)
        query = f"SELECT * FROM users WHERE id = '{safe_id}'"
    else:
        # UNSAFE path: non-numeric input bypasses sanitization entirely
        query = "SELECT * FROM users WHERE username = '" + user_id + "'"

    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)
