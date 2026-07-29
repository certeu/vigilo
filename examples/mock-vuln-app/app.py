"""Mock vulnerable Flask app — a deliberate target for smoke-testing Vigilo.

It plants a small, clear set of TRUE positives (SQLi, command injection, SSRF,
weak password hashing) alongside deliberate NOISE that a good pipeline should
NOT headline (a debug route gated off by default; a dev-only secret). The point
is to exercise both detection recall and the false-positive-reduction path
(reachability / conditional-gating / severity de-inflation).

Do NOT deploy this. It is intentionally insecure.
"""

import hashlib
import os
import sqlite3
import subprocess

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# NOISE: off-by-default debug flag. A finding on the /debug route below should be
# demoted to conditional/hardening (reachability mitigated_by_deployment) unless
# DEBUG_MODE is actually enabled — not reported as a live critical.
DEBUG_MODE = os.environ.get("DEBUG_MODE", "false").lower() == "true"


def _db():
    return sqlite3.connect("app.db")


@app.route("/user")
def get_user():
    # TRUE POSITIVE — SQL injection: user input concatenated into the query.
    username = request.args.get("username", "")
    conn = _db()
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE username = '%s'" % username)
    rows = cur.fetchall()
    return jsonify(rows)


@app.route("/ping")
def ping():
    # TRUE POSITIVE — command injection: user input into a shell command.
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/fetch")
def fetch():
    # TRUE POSITIVE — SSRF: server fetches a user-controlled URL with no allowlist.
    url = request.args.get("url", "")
    resp = requests.get(url, timeout=5)
    return resp.text


def hash_password(password: str) -> str:
    # TRUE POSITIVE — weak hashing: MD5, unsalted, for password storage.
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/debug")
def debug_info():
    # NOISE / conditional: only reachable when DEBUG_MODE is on (default off).
    # A good pipeline reports this as conditional / hardening, not a live critical.
    if not DEBUG_MODE:
        return ("Not found", 404)
    return jsonify(dict(os.environ))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
