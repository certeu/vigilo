"""python -m tests.greybox_web.fixtures.ledgerline_api [--port 18642]"""
import argparse

from tests.greybox_web.fixtures.ledgerline_api import serve

p = argparse.ArgumentParser(description="Ledgerline billing API (synthetic Vigilo target)")
p.add_argument("--port", type=int, default=18642)
p.add_argument("--host", default="127.0.0.1")
a = p.parse_args()
_, url = serve(a.port, a.host)
print(f"Ledgerline API listening on {url}", flush=True)
import threading  # noqa: E402
threading.Event().wait()
