"""Template for tool.compose: extract API route literals from fetched code.

Capabilities: ["recorded"] (reads responses the run already fetched).
args: {"contains": "<substring of the bundle URLs to read>"}
Adapt the patterns to the bundle you are looking at; keep it short.
"""
import re

PATTERNS = [
    re.compile(r"""["'`](/api/[A-Za-z0-9_\-/{}:.]+)["'`]"""),
    re.compile(r"""path\s*:\s*["'`](/[A-Za-z0-9_\-/{}:.]+)["'`]"""),
    re.compile(r"""(?:fetch|get|post|put|patch|delete)\(\s*["'`]([^"'`]{2,120})["'`]"""),
]


def analyse(ctx):
    rows = ctx.broker.recorded(contains=ctx.args.get("contains") or ".js", limit=20)
    found = {}
    for row in rows:
        body = row.get("body") or ""
        for rx in PATTERNS:
            for m in rx.finditer(body):
                path = m.group(1)
                if path.startswith("/") and len(path) < 150:
                    found.setdefault(path, row["url"])
    return {"summary": f"{len(found)} route literal(s) in {len(rows)} script(s)",
            "observations": [{"key": "routes:" + p, "facts": {"path": p, "source": u}}
                             for p, u in sorted(found.items())[:40]]}
