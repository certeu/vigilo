"""python -m tests.greybox_web.fixtures.fjord_intranet [--port 18645]"""
import argparse

from tests.greybox_web.fixtures.fjord_intranet import serve

p = argparse.ArgumentParser(description="Fjord Intranet (synthetic Vigilo target, clean control)")
p.add_argument("--port", type=int, default=18645)
p.add_argument("--host", default="127.0.0.1")
a = p.parse_args()
_, url = serve(a.port, a.host)
print(f"Fjord Intranet listening on {url}", flush=True)
import threading

threading.Event().wait()
