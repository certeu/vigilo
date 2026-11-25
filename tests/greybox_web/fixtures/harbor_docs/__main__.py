"""python -m tests.greybox_web.fixtures.harbor_docs [--port 18643]"""
import argparse

from tests.greybox_web.fixtures.harbor_docs import serve

p = argparse.ArgumentParser(description="Harbor Docs (synthetic Vigilo target)")
p.add_argument("--port", type=int, default=18643)
p.add_argument("--host", default="127.0.0.1")
a = p.parse_args()
_, url = serve(a.port, a.host)
print(f"Harbor Docs listening on {url}", flush=True)
import threading  # noqa: E402
threading.Event().wait()
