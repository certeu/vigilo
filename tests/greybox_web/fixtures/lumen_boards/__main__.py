"""python -m tests.greybox_web.fixtures.lumen_boards [--port 18641]"""
import argparse

from tests.greybox_web.fixtures.lumen_boards import serve

p = argparse.ArgumentParser(description="Lumen Boards (synthetic Vigilo target)")
p.add_argument("--port", type=int, default=18641)
p.add_argument("--host", default="127.0.0.1")
a = p.parse_args()
_, url = serve(a.port, a.host)
print(f"Lumen Boards listening on {url}", flush=True)
import threading  # noqa: E402
threading.Event().wait()
