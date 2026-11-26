"""T4: engine modules never import raw network/shell primitives.

Tools may only reach the network through ``ctx.http`` (the guarded client); no
httpx, socket, subprocess or urllib.request anywhere in the engine package
except in ``netguard.py`` itself, the single guarded network path.
"""
from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
PKG = ROOT / "src" / "greybox_web"

FORBIDDEN = {"httpx", "socket", "subprocess", "urllib.request"}
ALLOWED_IN = {"netguard.py"}          # the single guarded network path


def _bad_imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text())
    bad: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if a.name in FORBIDDEN or top in FORBIDDEN:
                    bad.add(a.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            mod = node.module or ""
            if mod in FORBIDDEN or mod.split(".")[0] in FORBIDDEN:
                bad.add(mod)
            if any(a.name.startswith("create_subprocess") for a in node.names):
                bad.add("subprocess")
    return bad


def test_tools_never_import_network_or_shell():
    for path in sorted((PKG / "tools").glob("*.py")):
        assert not _bad_imports(path), f"{path.name}: {_bad_imports(path)}"


def test_engine_modules_only_via_netguard():
    offenders = {path.name: _bad_imports(path)
                 for path in sorted(PKG.glob("*.py"))
                 if path.name not in ALLOWED_IN and path.name != "__init__.py"
                 and _bad_imports(path)}
    assert not offenders, offenders


# Raw primitives reached through asyncio (no import to catch): a raw socket only in
# the raw-protocol guard, a child process only in the sandbox launcher.
RAW_CALLS = {"open_connection": {"netcap.py"}, "create_connection": {"netcap.py"},
             "open_unix_connection": set(), "start_server": set(),
             "create_subprocess_exec": {"sandbox.py"},
             "create_subprocess_shell": set()}


def _raw_calls(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text())
    return {n.attr for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr in RAW_CALLS}


def test_raw_sockets_and_processes_only_in_their_guard_modules():
    offenders = {}
    for path in sorted(PKG.rglob("*.py")):
        bad = {c for c in _raw_calls(path) if path.name not in RAW_CALLS[c]}
        if bad:
            offenders[str(path.relative_to(PKG))] = bad
    assert not offenders, offenders
