"""Tiny intentionally-flawed app for executor smoke testing."""
import sqlite3
import subprocess


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    # SQL injection: user_id interpolated directly into the query.
    return conn.execute("SELECT * FROM users WHERE id = '%s'" % user_id).fetchall()


def run_ping(host):
    # Command injection: host passed to a shell.
    return subprocess.check_output("ping -c1 " + host, shell=True)
