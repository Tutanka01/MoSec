# BENCHMARK CASE: False Positive — SQL injection mitigated by parameterized query
# CWE-89 | Source: request.args.get | Parameterized query sanitizer | Sink: cursor.execute
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Parameterized query — user input never concatenated into SQL
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)
