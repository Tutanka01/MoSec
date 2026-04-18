# BENCHMARK CASE: True Positive — SQL injection via string concatenation
# CWE-89 | Source: request.args.get | Sink: cursor.execute
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # String concatenation directly into SQL query — injection
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)
