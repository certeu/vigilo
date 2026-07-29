"""Intentionally vulnerable demo API (for Vigilo pipeline demonstration only).

DO NOT deploy. Contains deliberate vulnerabilities so a scan produces findings.
"""
import os
import sqlite3
import subprocess

from fastapi import FastAPI, Request

app = FastAPI()

# VULN: hardcoded secret / weak crypto key
API_SECRET = "s3cr3t-hardcoded-key-do-not-use"


@app.get("/users")
def get_user(username: str):
    # VULN: SQL injection — user input concatenated into the query
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return {"rows": cur.fetchall()}


@app.get("/ping")
def ping(host: str):
    # VULN: OS command injection
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return {"out": out.decode()}


@app.get("/fetch")
def fetch(url: str):
    # VULN: SSRF — server fetches an arbitrary user-supplied URL
    import urllib.request

    return {"body": urllib.request.urlopen(url).read()[:200]}


@app.post("/eval")
async def run_eval(request: Request):
    # VULN: remote code execution via eval of request body
    body = (await request.body()).decode()
    return {"result": eval(body)}  # noqa: S307


@app.get("/debug")
def debug():
    # VULN: sensitive info exposure
    return {"env": dict(os.environ), "secret": API_SECRET}
