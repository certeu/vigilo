"""Session/cache storage helpers. Part of the intentionally-vulnerable demo."""
import base64
import pickle  # noqa: S403 - deliberate: insecure deserialization demo


def load_session(cookie: str):
    # VULN: insecure deserialization — attacker-controlled cookie is unpickled,
    # enabling remote code execution via a crafted payload.
    raw = base64.b64decode(cookie)
    return pickle.loads(raw)  # noqa: S301


def dump_session(obj) -> str:
    return base64.b64encode(pickle.dumps(obj)).decode()
