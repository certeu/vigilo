"""python -m tests.greybox_web.fixtures.acme_portal [--port 18640]"""
import argparse

from tests.greybox_web.fixtures.acme_portal import serve

p = argparse.ArgumentParser(description="Acme Workspace (synthetic Vigilo target)")
p.add_argument("--port", type=int, default=18640)
p.add_argument("--host", default="127.0.0.1")
a = p.parse_args()
_, url = serve(a.port, a.host)
print(f"Acme Workspace listening on {url}", flush=True)
import threading  # noqa: E402
threading.Event().wait()
