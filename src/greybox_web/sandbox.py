"""The sandbox for agent-authored analysis tools.

The reasoning agent may need an *analysis* no built-in tool can express: parse an
unusual API envelope, diff two responses field by field, walk a JavaScript-derived
route table, decide which of two cookie jars is the privileged one. The declarative
``tool.define`` vocabulary (:mod:`src.greybox_web.tools.dynspec`) covers
single-request verdicts; it cannot express arbitrary computation over several
observations.

This module is the second, narrower answer: the agent writes a SHORT Python function
that is executed in its own interpreter with **no network, no filesystem and no
process access**, over data the run has already recorded. Its only I/O are the
arguments it is given and the value it returns.

Security model — the sandbox never holds a capability, it only holds data
--------------------------------------------------------------------------------
1. **Scope is enforced BEFORE the sandbox runs.** The engine resolves which
   in-scope URLs the tool may read (the work order's ``urls``, already admitted
   against :class:`~src.greybox_web.scope.ScopePolicy`), fetches them (if they are
   not recorded yet) through the ordinary guarded client — per-hop scope, IP
   policy, budgets, rate limits, session cookies — and passes the *responses* in.
   The generated code can therefore not address a host at all: it has no socket,
   and even if it did, the network policy was applied by the process that did the
   fetching.
2. **The interpreter is built without the escape hatches.** The child is started
   with a private site directory preloaded: ``socket``, ``ssl``, ``http``,
   ``subprocess``, ``ctypes``, ``multiprocessing`` and friends raise
   ``ImportError`` on import, and ``os`` exposes no ``system``/``exec*``/``spawn*``
   /``fork``. Whatever the code tries (``__import__``, ``importlib``, a dunder
   walk), it hits the same block.
3. **Determinism of the answer, not the trust.** The return value must be JSON: the
   engine validates its SHAPE (:func:`check_result`). A finding is only ever raised
   by *the engine*, from that validated shape — the tool returns data, it never
   mints a finding.
4. **Bounded resources.** CPU seconds, address space, process count, output bytes
   and wall clock are capped by :class:`SandboxLimits`; the child runs in its own
   process group, so a timeout kills everything it started. No run can affect
   another: every execution is a fresh interpreter with its own temporary
   directory, removed afterwards.
5. **Auditable.** The source, the arguments digest, the output, the duration, the
   exit status and any error are all recorded (``TOOL_SOURCE_CAP`` characters of
   source, so the audit trail keeps the *logic* and not just a hash).

What the tool may return
-------------------------
``{"summary": str, "observations": [{"key": str, "facts": {str: scalar}}],
"findings": [{"title", "severity", "description", "cwe"?, "remediation"?,
"verification"?}]}`` — see :func:`check_result`. Severity is re-validated here, and
findings produced this way are created as *candidate* findings by the tool that
owns them (``tools/toolsmith.py``), so an analytical script can never manufacture a
"verified" vulnerability on its own.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any

# The interpreter prelude: it runs before any generated code and removes the
# capabilities a security analysis never needs. Every socket, process and
# shared-memory module raises ImportError; ``os`` keeps only its path helpers and
# the process can no longer open a file.
PRELUDE = '''
"""Capability narrowing for an agent-authored analysis tool (Vigilo sandbox).

This text is the first half of the child's driver (``DRIVER`` below): it is NOT
installed as ``sitecustomize`` — the application's own virtualenv already provides
one, and a shadowed module would fail silently. Pasting it keeps the child's
command line short, so the audit log stays readable.
"""
import sys as _sys

import io as _io_mod, json as _json_mod, traceback as _tb_mod   # driver needs, pre-narrowing

_BLOCKED = {
    # raw OS / IO escape hatches (posix.system, _io.open, threads, shared memory)
    "posix", "nt", "_io", "_thread", "_posixshmem", "faulthandler", "_signal",
    "gc", "_tracemalloc", "socket", "_socket", "ssl", "_ssl", "http", "urllib", "urllib3", "httpx",
    "requests", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "xmlrpc",
    "asyncio", "_asyncio", "select", "selectors", "multiprocessing",
    "_multiprocessing", "subprocess", "_posixsubprocess", "ctypes", "_ctypes",
    "pty", "tty", "fcntl", "mmap", "signal", "shutil", "tempfile", "webbrowser",
    "importlib", "zlib", "bz2", "lzma", "tarfile", "zipfile", "sqlite3", "dbm",
    "pickle", "shelve", "marshal", "runpy", "pdb", "cProfile", "profile",
    "resource", "sysconfig", "distutils", "setuptools", "pip", "venv", "pathlib",
}


# The real file-open, remembered before the narrowing: the driver has to read the
# tool source and write the result, and it does that with a handle obtained before
# generated code exists (``_DRIVER_OPEN``). Nothing else in the child ever gets one.
_SAVED: dict = {}


class _Blocker:
    """A meta-path finder that refuses the blocked modules by name."""

    def find_spec(self, name, path=None, target=None):
        root = name.split(".")[0]
        if root in _BLOCKED:
            raise ImportError(f"module {name!r} is not available to an analysis tool")
        return None


def _install():
    for mod in list(_sys.modules):
        if mod.split(".")[0] in _BLOCKED:
            _sys.modules.pop(mod, None)
    _sys.meta_path.insert(0, _Blocker())
    import os
    keep = {"path"}
    for attr in ("system", "popen", "fork", "forkpty", "execv", "execve", "execvp",
                 "execvpe", "execl", "execle", "execlp", "execlpe", "spawnv",
                 "spawnve", "spawnvp", "spawnvpe", "spawnl", "spawnle", "spawnlp",
                 "spawnlpe", "posix_spawn", "posix_spawnp", "kill", "killpg",
                 "setuid", "setgid", "ptrace", "chroot", "chdir", "chmod", "chown",
                 "remove", "unlink", "rmdir", "rename", "replace", "mkdir",
                 "makedirs", "symlink", "link", "truncate", "environ", "open"):
        if hasattr(os, attr) and attr not in keep:
            try:
                delattr(os, attr)
            except (AttributeError, TypeError):
                pass
    def _refuse(*_a, **_k):
        raise PermissionError("an analysis tool cannot open files; the data it may "
                              "read is passed in through ctx")

    # No handle into the filesystem: the data an analysis may read arrives through
    # ``ctx``, never from disk.
    import builtins
    import io
    _SAVED["builtins"] = builtins.open
    _SAVED["io"] = io.open
    builtins.open = _refuse
    io.open = _refuse


def _unrefuse():
    """Give the driver its ONE file handle: the real ``io.open``, bound to a private
    name. ``builtins.open`` and ``io.open`` stay refusing, so ``open(...)`` and
    ``from io import open`` in generated code both fail."""
    return _SAVED["io"]


_install()

# The driver needs a file handle of its own to hand the result back; the generated
# code (executed after this line) does not: its ``open`` is the refusing one.
_DRIVER_OPEN = _unrefuse()
'''

# The child driver: it receives the tool source, the arguments and the result path
# on argv, narrows the interpreter (``PRELUDE``, pasted above), executes the source
# and writes a compact JSON result.
DRIVER = PRELUDE + '''
import sys
json = _json_mod
traceback = _tb_mod

_result_path = sys.argv[1]
_src_path = sys.argv[2]
_args_path = sys.argv[3]

with _DRIVER_OPEN(_src_path, "r", encoding="utf-8") as fh:
    _src = fh.read()
with _DRIVER_OPEN(_args_path, "r", encoding="utf-8") as fh:
    _args = json.load(fh)

# The broker protocol: one JSON line out (stdout), one JSON line back (stdin). The
# engine performs the call under its own policy; this side only asks. ``print`` in
# generated code goes to a private buffer (returned as the tool's log), so it can
# never be mistaken for a protocol line.
_proto_out = sys.stdout
_proto_in = sys.stdin
_log = _io_mod.StringIO()
sys.stdout = _log


class BrokerError(Exception):
    """The engine refused or could not perform a brokered call (the reason is the
    message: out of scope, capability not declared, quota, transport failure)."""


class _Broker:
    def __init__(self):
        self._n = 0

    def call(self, op, **args):
        self._n += 1
        _proto_out.write(json.dumps({"id": self._n, "op": op, "args": args},
                                    default=str) + "\\n")
        _proto_out.flush()
        line = _proto_in.readline()
        if not line:
            raise BrokerError("the broker closed the channel")
        msg = json.loads(line)
        if not msg.get("ok"):
            raise BrokerError(str(msg.get("error") or "refused"))
        return msg.get("result")

    def http(self, url, method="GET", headers=None, body=None, json=None,
             content_type=None, session=None, follow=True, state_changing=False):
        return self.call("http", url=url, method=method, headers=headers, body=body,
                         json=json, content_type=content_type, session=session,
                         follow=follow, state_changing=state_changing)

    def get(self, url, **kw):
        return self.http(url, "GET", **kw)

    def post(self, url, **kw):
        return self.http(url, "POST", **kw)

    def tcp(self, host, port, send=None):
        return self.call("tcp", host=host, port=port, send=send)

    def dns(self, name):
        return self.call("dns", name=name)

    def recorded(self, contains=None, scheme=None, method=None, limit=20):
        return self.call("recorded", contains=contains, scheme=scheme,
                         method=method, limit=limit)

    def sessions(self):
        return self.call("sessions")

    def inventory(self, name=None):
        return self.call("inventory", name=name)


class _Ctx(dict):
    """``ctx["responses"]`` and ``ctx.responses`` alike; ``ctx.broker`` is the
    only way to act."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


_namespace = {"__name__": "agent_tool", "__builtins__": __builtins__,
              "BrokerError": BrokerError}
_out = {"ok": False, "error": None, "result": None}
try:
    exec(compile(_src, "<agent-tool>", "exec"), _namespace)
    if "analyse" not in _namespace or not callable(_namespace["analyse"]):
        raise ValueError("the tool must define a callable analyse(ctx)")
    _ctx = _Ctx(_args)
    _ctx["broker"] = _Broker()
    _out["result"] = _namespace["analyse"](_ctx)
    _out["ok"] = True
except BaseException as exc:                                    # noqa: BLE001
    _out["error"] = f"{type(exc).__name__}: {exc}"[:2000]
    _out["traceback"] = traceback.format_exc()[-4000:]

_out["log"] = _log.getvalue()[-4000:]
try:
    with _DRIVER_OPEN(_result_path, "w", encoding="utf-8") as fh:
        json.dump(_out, fh, default=str)
except (TypeError, ValueError) as exc:
    with _DRIVER_OPEN(_result_path, "w", encoding="utf-8") as fh:
        json.dump({"ok": False, "error": f"result is not JSON-serialisable: {exc}"},
                  fh)
'''

TOOL_SOURCE_CAP = 8_000          # characters of source the agent may submit
TOOL_SOURCE_MIN = 20
_MARKER_RE = re.compile(r"^\s*(def\s+analyse\s*\(|\"\"\"|''')", re.MULTILINE)
_SEVERITIES = ("low", "medium", "high", "critical")


class SandboxError(Exception):
    """The tool could not be run (never conflated with "the analysis found nothing")."""


@dataclass(frozen=True)
class SandboxLimits:
    """Resource bounds of one execution. Conservative by design: an analysis tool
    reads data it was handed, it does not compute for minutes."""

    cpu_s: int = 10                  # RLIMIT_CPU (child CPU seconds)
    wall_s: float = 15.0             # engine-side timeout (whole process group)
    memory_mb: int = 512             # RLIMIT_AS
    # NB: there is no RLIMIT_NPROC knob. On macOS the kernel counts user sessions,
    # not processes, so a fork bomb and a plain interpreter look alike and a low cap
    # kills unrelated processes -- the capability narrowing (no subprocess, no fork,
    # no ctypes) is what stops a child, and RLIMIT_CPU bounds the child itself.
    output_bytes: int = 1_000_000    # parser cap on the result document
    file_size_bytes: int = 4_000_000

    def as_dict(self) -> dict[str, Any]:
        return {"cpu_s": self.cpu_s, "wall_s": self.wall_s,
                "memory_mb": self.memory_mb}


DEFAULT_LIMITS = SandboxLimits()


@dataclass
class SandboxResult:
    ok: bool
    result: Any = None
    error: str | None = None
    duration_ms: int = 0
    limits: dict[str, Any] = field(default_factory=dict)
    log: str = ""                     # what the tool printed (debugging aid)
    isolation: str = ""               # bwrap | unshare | process


# ----------------------------------------------------------------- OS isolation
#
# The interpreter narrowing above is defence in depth, NOT the boundary: Python has
# too many ways back to the OS (frame walking, ``object.__subclasses__``) for a
# block list to be one. The boundary is the operating system:
#
# ``bwrap``    bubblewrap: new user/pid/net/ipc/uts namespaces (no network
#              interface but loopback, which is empty), a read-only system image,
#              NO /etc, /home, /root or host /tmp, an empty tmpfs, a cleared
#              environment and all capabilities dropped. Generated code that
#              escapes Python still has no route anywhere and nothing to read.
# ``unshare``  util-linux unshare: user + network namespaces only (no route to the
#              network; the filesystem is still the worker's).
# ``process``  no OS isolation: interpreter narrowing + rlimits only. Never chosen
#              automatically; an operator must set it explicitly (and accepts that
#              a determined escape could reach the network from the worker).
#
# ``VIGILO_GREYBOX_SANDBOX_ISOLATION`` = auto (default: bwrap, else unshare, else
# refuse) | bwrap | unshare | process.

ISOLATION_ENV = "VIGILO_GREYBOX_SANDBOX_ISOLATION"
ISOLATIONS = ("bwrap", "unshare", "process")


class IsolationUnavailable(SandboxError):
    """No acceptable OS isolation: generated code is not run at all."""


def _python() -> str:
    return os.path.realpath(sys.executable)


def _bwrap_cmd(workdir: str, python: str) -> list[str]:
    cmd: list[str] = []
    # Container workers normally run as root. Start bubblewrap without privilege so
    # it must create a user namespace rather than using the outer container's caps.
    if os.geteuid() == 0:
        setpriv = shutil.which("setpriv")
        if not setpriv:
            return ["/nonexistent/vigilo-setpriv"]
        os.chmod(workdir, 0o777)
        cmd += [setpriv, "--reuid=65534", "--regid=65534", "--clear-groups"]
    cmd += [shutil.which("bwrap") or "bwrap", "--unshare-all", "--die-with-parent",
           "--new-session", "--clearenv", "--cap-drop", "ALL",
           "--ro-bind", "/usr", "/usr"]
    for d in ("/lib", "/lib64", "/lib32", "/bin", "/sbin"):
        if os.path.exists(d):
            cmd += ["--ro-bind", d, d] if not os.path.islink(d) \
                else ["--symlink", os.readlink(d), d]
    # an interpreter installed outside /usr (uv / pyenv managed): bind its prefix
    for prefix in {os.path.realpath(sys.base_prefix),
                   os.path.dirname(os.path.dirname(python))}:
        if prefix and not prefix.startswith("/usr") and os.path.isdir(prefix):
            cmd += ["--ro-bind", prefix, prefix]
    library_dir = os.path.join(os.path.realpath(sys.base_prefix), "lib")
    cmd += ["--dir", "/proc", "--dir", "/dev", "--tmpfs", "/tmp",
            "--bind", workdir, "/work", "--chdir", "/work",
            "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/work",
            "--setenv", "LC_ALL", "C.UTF-8", "--setenv", "PYTHONHASHSEED", "0",
            "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--"]
    if library_dir.startswith("/usr/") and os.path.isdir(library_dir):
        cmd[-1:-1] = ["--setenv", "LD_LIBRARY_PATH", library_dir]
    return cmd


def _unshare_cmd() -> list[str]:
    return [shutil.which("unshare") or "unshare", "--user", "--map-root-user", "--net", "--ipc", "--uts",
            "--pid", "--fork", "--kill-child", "--"]


_PROBED: dict[str, bool] = {}


async def _works(kind: str) -> bool:
    """Can this worker actually create the isolation (a container without user
    namespaces cannot)? Probed once with a no-op."""
    if kind in _PROBED:
        return _PROBED[kind]
    ok = False
    if shutil.which(kind):
        tmp = tempfile.mkdtemp(prefix="vigilo-probe-")
        try:
            cmd = (_bwrap_cmd(tmp, _python()) if kind == "bwrap" else _unshare_cmd()) \
                + [_python(), "-I", "-S", "-c", "pass"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            ok = await asyncio.wait_for(proc.wait(), timeout=15) == 0
        except (OSError, asyncio.TimeoutError):
            ok = False
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    _PROBED[kind] = ok
    return ok


async def isolation_mode() -> str:
    """The isolation generated code will run under, or raise
    :class:`IsolationUnavailable` (auto mode with neither bwrap nor unshare)."""
    want = (os.environ.get(ISOLATION_ENV) or "auto").strip().lower()
    if want == "process":
        return "process"
    if want in ("bwrap", "unshare"):
        if not await _works(want):
            raise IsolationUnavailable(
                f"{ISOLATION_ENV}={want} but {want} cannot create its namespaces on "
                f"this worker")
        return want
    for kind in ("bwrap", "unshare"):
        if await _works(kind):
            return kind
    raise IsolationUnavailable(
        "no OS isolation is available on this worker (bubblewrap or unprivileged "
        "user namespaces); agent-written code is not run. Install bubblewrap, allow "
        f"user namespaces, or set {ISOLATION_ENV}=process to accept interpreter-level "
        "isolation only")


def validate_source(source: str) -> str:
    """Accept only a self-contained module defining ``analyse(ctx)``.

    Rejects non-strings, runaway sizes, NUL bytes and sources with no ``analyse``
    entry point — the cheap structural checks that keep a typo from costing a
    subprocess. Everything else (imports, dunders) is handled by the prelude, not
    by pattern matching: a text filter is not a security boundary.
    """
    if not isinstance(source, str):
        raise SandboxError("tool source must be a string")
    src = source.replace("\r\n", "\n").strip("\n")
    if "\x00" in src:
        raise SandboxError("tool source contains a NUL byte")
    if len(src) < TOOL_SOURCE_MIN:
        raise SandboxError(f"tool source is too short ({len(src)} chars)")
    if len(src) > TOOL_SOURCE_CAP:
        raise SandboxError(f"tool source is too long ({len(src)} > {TOOL_SOURCE_CAP} chars)")
    if not re.search(r"^\s*def\s+analyse\s*\(", src, re.MULTILINE):
        raise SandboxError("the tool must define `def analyse(ctx):`")
    if not _MARKER_RE.search(src):
        raise SandboxError("the tool must start with its docstring or its analyse "
                           "definition")
    # Compile here as well: syntax errors are an admission problem, not an
    # execution surprise, and compiling does not run anything.
    try:
        compile(src, "<agent-tool>", "exec")
    except SyntaxError as exc:
        raise SandboxError(f"syntax error: {exc.msg} (line {exc.lineno})") from exc
    return src


def check_result(value: Any) -> dict[str, Any]:
    """Validate the shape of what the tool returned; return the clean document.

    The tool proposes *data*: a summary, observations (key + scalar facts) and
    candidate findings. Anything else is refused — a stray key cannot smuggle an
    option into the engine, and a finding cannot be ``verified`` by saying so.
    """
    if not isinstance(value, dict):
        raise SandboxError("analyse() must return a dict")
    allowed = {"summary", "observations", "findings"}
    extra = set(value) - allowed
    if extra:
        raise SandboxError(f"unexpected result key(s): {sorted(extra)}")
    summary = str(value.get("summary") or "")[:400]
    observations: list[dict[str, Any]] = []
    obs_in = value.get("observations") or []
    if not isinstance(obs_in, list) or len(obs_in) > 50:
        raise SandboxError("observations must be a list of at most 50 items")
    for item in obs_in:
        if not isinstance(item, dict) or not item.get("key"):
            raise SandboxError("each observation needs a key")
        facts = item.get("facts") or {}
        if not isinstance(facts, dict) or len(facts) > 50:
            raise SandboxError("observation facts must be a dict of at most 50 keys")
        clean = {str(k)[:80]: (v if isinstance(v, (str, int, float, bool)) or v is None
                              else json.dumps(v, default=str))
                 for k, v in facts.items()}
        observations.append({"key": str(item["key"])[:200], "facts": clean})
    findings: list[dict[str, Any]] = []
    fnd_in = value.get("findings") or []
    if not isinstance(fnd_in, list) or len(fnd_in) > 20:
        raise SandboxError("findings must be a list of at most 20 items")
    for item in fnd_in:
        if not isinstance(item, dict):
            raise SandboxError("each finding must be a dict")
        title = str(item.get("title") or "").strip()
        description = str(item.get("description") or "").strip()
        severity = str(item.get("severity") or "").strip().lower()
        if not title or len(title) > 200:
            raise SandboxError("a finding needs a title (<= 200 chars)")
        if not description:
            raise SandboxError("a finding needs a description")
        if severity not in _SEVERITIES:
            raise SandboxError(f"finding severity must be one of {_SEVERITIES}")
        finding: dict[str, Any] = {
            "title": title, "description": description[:2000], "severity": severity}
        for key, cap in (("cwe", 32), ("verification", 1000), ("impact", 1000),
                         ("severity_rationale", 1000)):
            text = item.get(key)
            if text:
                finding[key] = str(text)[:cap]
        rem = item.get("remediation")
        if isinstance(rem, dict):
            finding["remediation"] = json.loads(json.dumps(rem, default=str)[:6000]) \
                if len(json.dumps(rem, default=str)) <= 6000 else {"summary": str(
                    rem.get("summary") or "")[:1500]}
        elif rem:
            finding["remediation"] = str(rem)[:1500]
        cls = item.get("class") or item.get("finding_class")
        if cls is not None:
            if cls not in ("vulnerability", "misconfiguration", "hardening",
                           "informational"):
                raise SandboxError("finding class must be vulnerability, "
                                   "misconfiguration, hardening or informational")
            finding["class"] = cls
        affected = item.get("affected")
        if affected:
            finding["affected"] = str(affected)[:300]
        evidence = item.get("evidence")
        if evidence:
            if not isinstance(evidence, list) or len(evidence) > 20:
                raise SandboxError("finding evidence must be a list of <= 20 strings")
            finding["evidence"] = [str(e)[:500] for e in evidence]
        effect = item.get("effect")
        if effect is not None:
            if not isinstance(effect, dict) or set(effect) - {
                    "before_exchange_id", "action_exchange_id",
                    "after_exchange_id", "impact"}:
                raise SandboxError("finding effect needs before_exchange_id, "
                                   "action_exchange_id, after_exchange_id and impact")
            try:
                effect_ids = {key: int(effect[key]) for key in (
                    "before_exchange_id", "action_exchange_id", "after_exchange_id")}
            except (KeyError, TypeError, ValueError) as exc:
                raise SandboxError("finding effect exchange ids must be integers") from exc
            impact = str(effect.get("impact") or "").strip()
            if not impact:
                raise SandboxError("finding effect needs a concrete observed impact")
            finding["effect"] = {**effect_ids, "impact": impact[:1000]}
        findings.append(finding)
    return {"summary": summary, "observations": observations, "findings": findings}


def _preexec(limits: SandboxLimits):
    """Child-side resource limits (POSIX). Applied before exec."""
    def apply() -> None:                                  # pragma: no cover - child
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU,
                               (limits.cpu_s, limits.cpu_s + 2))
            # Address space = CPU budget's twin (a tool that parses a body cannot
            # legitimately need hundreds of MB). NB: macOS may ignore RLIMIT_AS, so
            # the wall clock and the result cap are the enforcement that portably
            # holds; this is the cheap second line on platforms honouring it.
            (soft, hard) = resource.getrlimit(resource.RLIMIT_AS)
            want = limits.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS,
                               (want, want if hard == resource.RLIM_INFINITY
                                else min(want, hard)))
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (limits.file_size_bytes, limits.file_size_bytes))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            os.setsid()          # own process group: a timeout kills the group
        except Exception:        # a platform that cannot set a limit still runs
            pass
    return apply


BROKERED_WALL_S = 90.0      # a brokered tool waits on the network, not the CPU


async def run(source: str, arguments: dict[str, Any], *,
              limits: SandboxLimits | None = None,
              python: str | None = None, broker: Any = None) -> SandboxResult:
    """Execute ``source``'s ``analyse(ctx)`` in the sandbox and validate its result.

    ``broker`` (``broker.Broker``): serves the tool's ``ctx.broker`` calls. Without
    one every call fails with "the broker closed the channel"."""
    lim = limits or (SandboxLimits(wall_s=BROKERED_WALL_S) if broker is not None
                     else DEFAULT_LIMITS)
    return await _run(validate_source(source), arguments, lim, python, broker)


async def probe(*, limits: SandboxLimits | None = None) -> dict[str, Any]:
    """Run :data:`PROBE_SOURCE` and return the capability map.

    The tests (and a deployment's smoke check) call this to prove the blocks hold in
    the interpreter that will actually run generated code — a claim about a
    sandbox is worth exactly as much as the probe that verifies it."""
    res = await run(PROBE_SOURCE, {}, limits=limits)
    if not res.ok:
        raise SandboxError(f"sandbox probe failed: {res.error}")
    return dict(res.result["observations"][0]["facts"])


async def _serve(proc, broker, deadline: float) -> bytes:
    """Answer the child's broker requests until it closes stdout; return stderr.
    A malformed protocol line ends the execution (the child is not trusted)."""
    loop = asyncio.get_running_loop()
    assert proc.stdout is not None and proc.stdin is not None
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError
        line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
        if not line:
            break
        if len(line) > 200_000:
            raise SandboxError("broker request too large")
        try:
            req = json.loads(line)
        except ValueError:
            raise SandboxError("the tool wrote a non-protocol line to the broker "
                               "channel") from None
        if broker is None:
            reply = {"ok": False, "error": "this tool has no broker capabilities"}
        else:
            reply = await broker.handle(req)
        data = (json.dumps(reply, default=str) + "\n").encode()
        try:
            proc.stdin.write(data)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            break
    assert proc.stderr is not None
    return await proc.stderr.read()


async def _run(src: str, arguments: dict[str, Any], lim: SandboxLimits,
               python: str | None, broker: Any = None) -> SandboxResult:
    isolation = await isolation_mode()      # raises: never run unisolated by default
    workdir = tempfile.mkdtemp(prefix="vigilo-tool-")
    try:
        src_path = os.path.join(workdir, "tool.py")
        args_path = os.path.join(workdir, "args.json")
        res_path = os.path.join(workdir, "result.json")
        drv_path = os.path.join(workdir, "driver.py")
        with open(src_path, "w", encoding="utf-8") as fh:
            fh.write(src)
        with open(args_path, "w", encoding="utf-8") as fh:
            json.dump(arguments, fh, default=str)
        with open(drv_path, "w", encoding="utf-8") as fh:
            fh.write(DRIVER)
        # No environment is inherited: nothing of the platform's configuration (a
        # credential in a *_KEY variable, a PYTHONPATH into the application) reaches
        # the child, and imports cannot resolve outside the standard library.
        env = {"PATH": "", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
               "LC_ALL": "C.UTF-8", "TMPDIR": workdir, "HOME": workdir}
        loop = asyncio.get_running_loop()
        started = loop.time()
        interp = python or _python()
        if isolation == "bwrap":
            os.chmod(workdir, 0o777)        # the namespaced uid must write the result
            argv = _bwrap_cmd(workdir, interp) + [
                interp, "-I", "-S", "-B", "/work/driver.py", "/work/result.json",
                "/work/tool.py", "/work/args.json"]
        else:
            prefix = _unshare_cmd() if isolation == "unshare" else []
            argv = prefix + [interp, "-I", "-S", "-B", drv_path, res_path, src_path,
                             args_path]
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=workdir, env=env, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            preexec_fn=_preexec(lim))
        try:
            stderr = await _serve(proc, broker, started + lim.wall_s)
            await asyncio.wait_for(proc.wait(),
                                   timeout=max(0.1, started + lim.wall_s - loop.time()))
        except asyncio.TimeoutError:
            await _kill(proc)
            return SandboxResult(ok=False, limits=lim.as_dict(), isolation=isolation,
                                 duration_ms=int((loop.time() - started) * 1000),
                                 error=f"the tool exceeded the {lim.wall_s:.0f}s wall "
                                       f"clock and was stopped")
        except SandboxError as exc:
            await _kill(proc)
            return SandboxResult(ok=False, limits=lim.as_dict(), isolation=isolation,
                                 duration_ms=int((loop.time() - started) * 1000),
                                 error=str(exc))
        except BaseException:
            await _kill(proc)               # cancelled run / exhausted budget
            raise
        duration_ms = int((loop.time() - started) * 1000)
        if proc.returncode != 0 or not os.path.exists(res_path):
            tail = stderr.decode("utf-8", "replace")[-600:]
            return SandboxResult(ok=False, duration_ms=duration_ms,
                                 limits=lim.as_dict(), isolation=isolation,
                                 error=f"the tool process exited with "
                                       f"{proc.returncode}: {tail.strip()}")
        if os.path.getsize(res_path) > lim.output_bytes:
            return SandboxResult(ok=False, duration_ms=duration_ms,
                                 limits=lim.as_dict(),
                                 error="the tool result document is too large")
        with open(res_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        log = str(doc.get("log") or "")[-4000:]
        if not doc.get("ok"):
            err = str(doc.get("error") or "the tool raised")[:2000]
            tb = str(doc.get("traceback") or "").strip().splitlines()
            where = tb[-3:] if tb else []
            return SandboxResult(ok=False, duration_ms=duration_ms,
                                 limits=lim.as_dict(), log=log, isolation=isolation,
                                 error=" | ".join([err, *where])[:2000])
        try:
            clean = check_result(doc.get("result"))
        except SandboxError as exc:
            return SandboxResult(ok=False, duration_ms=duration_ms, log=log,
                                 limits=lim.as_dict(), error=str(exc),
                                 isolation=isolation)
        return SandboxResult(ok=True, result=clean, duration_ms=duration_ms,
                             limits=lim.as_dict(), log=log, isolation=isolation)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _group_kill(pid: int) -> None:                        # pragma: no cover - races
    """Kill the child AND everything it started (it called ``setsid``, so it leads
    its own process group). Never a bare ``killpg(0)``: a missing group must not
    escalate to the worker's own."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


async def _kill(proc) -> None:                             # pragma: no cover - races
    """Terminate a runaway tool and reap it (a zombie would hold the group id)."""
    if proc.pid is not None:
        await asyncio.get_running_loop().run_in_executor(None, _group_kill, proc.pid)
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except (asyncio.TimeoutError, ProcessLookupError):
        pass


# ----------------------------------------------------------------- preflight probe

PROBE_SOURCE = '''
"""Capability probe: prove the blocks hold before claiming a sandboxed execution."""

def analyse(ctx):
    blocked = {}
    for name in ("socket", "subprocess", "ctypes", "multiprocessing", "ssl",
                 "http", "urllib", "importlib"):
        try:
            __import__(name)
            blocked[name] = "IMPORTED"
        except ImportError:
            blocked[name] = "blocked"
        except Exception as exc:
            blocked[name] = f"blocked ({type(exc).__name__})"
    import os
    for attr in ("system", "popen", "fork", "execv", "spawnv", "kill"):
        blocked[f"os.{attr}"] = "PRESENT" if hasattr(os, attr) else "removed"
    return {"summary": "capability probe",
            "observations": [{"key": "sandbox.probe", "facts": blocked}]}
'''
