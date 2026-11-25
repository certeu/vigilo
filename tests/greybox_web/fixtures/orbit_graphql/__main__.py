import argparse
import threading

from tests.greybox_web.fixtures.orbit_graphql import serve

parser = argparse.ArgumentParser(description="Orbit GraphQL synthetic Vigilo target")
parser.add_argument("--port", type=int, default=18646)
parser.add_argument("--host", default="127.0.0.1")
args = parser.parse_args()
_, url = serve(args.port, args.host)
print(f"Orbit GraphQL listening on {url}", flush=True)
threading.Event().wait()
