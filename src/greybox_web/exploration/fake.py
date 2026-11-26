"""The deterministic fake exploration model (dev mode, E2E, tests).

A stand-in for the real model that speaks the same JSON contract (``schema.py``)
and is *reactive*: it reads the knowledge JSON the real model would read and
decides from what it sees. It is stateless (everything it needs — what was already
asked of the target, what is pending — is in the knowledge), and nothing about any
specific application is hardcoded: two applications that look different produce
different plans through the same function.

What it does, in the order a tester would:

1. bootstrap: nothing known yet -> fetch the root, robots.txt and the sitemap;
2. follow what discovery found: crawl the frontier in batches;
3. test what the mapping found: every discovered parameter (reflection, error
   indicators, redirect targets when the name says so), login forms under an
   auth-testing scope (default credentials), endpoints that showed error or debug
   signatures, plus the checks that fit each surface (per service, per
   cookie-setting endpoint, per API surface) and passive re-examination of leaked
   internals and third-party origins; a request-header echo ("header_reflect_hint")
   composes a dynamic instrument for it (batch E: tool.define, declarative spec)
   and uses it at once;
4. open hypotheses for the interesting surfaces (API authorization, session
   handling, stored user content, input handling, default credentials,
   request-header reflection) and act on them;
5. fill the knowledge's coverage gaps (surface×check-class combinations with no
   completed outcome — including a defined-but-unused dynamic instrument) before
   anyone may call the assessment adequate;
6. judge the assessment adequate only when no gap remains, no frontier URL is
   unfetched, nothing is in flight and no action can be proposed;
7. acknowledge every operator message (one short reply per message id).

Only advertised tools and URLs taken from the knowledge itself are proposed, so
every proposal is in scope by construction. Candidate-finding verification is not
its job: the platform schedules it.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from src.greybox_web.exploration.knowledge import extract_knowledge

MAX_ACTIONS = 8                  # the contract's per-reply cap
CRAWL_BATCH = 10
PARAM_BATCH = 6                  # parameters proposed per reply; more next cycle

SERVICE_CHECKS = ("headers.security", "headers.disclosure", "cookies.flags",
                  "cors.policy", "exposure.files", "exposure.dirlisting")

# Parameter names that commonly carry a redirect target (redirect.open's fit).
REDIRECT_PARAM_NAMES = {"url", "next", "to", "redirect", "return", "goto",
                        "dest", "target", "continue", "callback", "u", "link"}


def _endpoints(k: dict) -> list[dict]:
    try:
        eps = (k.get("assets") or {}).get("endpoints") or []
        return [e for e in eps if isinstance(e, dict)]
    except AttributeError:
        return []


def _services(k: dict) -> list[str]:
    try:
        return sorted(str(s.get("url")) for s in
                      (k.get("assets") or {}).get("services") or []
                      if isinstance(s, dict) and s.get("url"))
    except AttributeError:
        return []


_MESSAGE_ID = re.compile(r"^- id=(m\d+) .*?action=(\w+)", re.MULTILINE)


def operator_message_ids(user: str) -> list[tuple[str, str]]:
    """``(id, action)`` of the OPERATOR MESSAGES section of an explorer prompt."""
    head = user.find("## OPERATOR MESSAGES")
    if head < 0:
        return []
    end = user.find("\n## ", head + 1)
    return _MESSAGE_ID.findall(user[head:end if end > 0 else None])


def _replies(user: str) -> list[dict]:
    """One short acknowledgement per operator message (the contract makes a reply
    mandatory); what the platform applied is already in the message line."""
    out = []
    for mid, action in operator_message_ids(user):
        what = ("I will keep it in mind while planning the next steps"
                if action == "note" else
                f"the platform applied the {action.replace('_', ' ')}; I will plan "
                "around it")
        out.append({"id": mid, "reply": f"Noted: {what}."})
    return out


def _reply(reasoning: str, hypotheses: list[dict], actions: list[dict],
           todolist: list[dict], assessment: str = "incomplete",
           replies: list[dict] | None = None) -> str:
    return json.dumps({
        "reasoning": reasoning,
        "assessment": assessment,
        "todolist": todolist,
        "hypotheses": hypotheses,
        "actions": actions[:MAX_ACTIONS],
        "replies": replies or [],
    })


def _h(url: str) -> str:
    return hashlib.sha1(url.encode()).hexdigest()[:10]


_ENVELOPE_SOURCE = """\
\"\"\"Report a meta block that names the database engine.\"\"\"
import json


def analyse(ctx):
    for resp in ctx['responses']:
        try:
            doc = json.loads(resp.get('body') or '')
        except ValueError:
            continue
        if not isinstance(doc, dict):
            continue
        meta = doc.get('meta')
        if not isinstance(meta, dict) or not meta.get('engine'):
            continue
        detail = json.dumps(meta, sort_keys=True)[:300]
        return {
            'summary': 'the envelope meta names ' + str(meta['engine']),
            'observations': [{'key': 'envelope.meta',
                              'facts': {'engine': str(meta['engine']),
                                        'keys': sorted(meta)[:10]}}],
            'findings': [{
                'title': 'API envelope discloses the database engine',
                'severity': 'low',
                'cwe': 'CWE-200',
                'description': ('The JSON envelope carries a meta block naming the '
                                'database engine, which helps an attacker target '
                                'known CVEs.'),
                'evidence': [detail],
                'remediation': 'Remove the meta block from production responses.',
            }],
        }
    return {'summary': 'no developer metadata in the envelope',
            'observations': [{'key': 'envelope.clean',
                              'facts': {'inputs': len(ctx['responses'])}}]}
"""


def _envelope_spec(url: str) -> dict:
    """The composition request for the envelope analyser (Phase 3).

    The SOURCE is what the agent would write: a short function over the responses
    the engine fetched. It never sees a socket — the engine read ``url`` through
    the guarded client and handed the body in."""
    return {
        "id": "envelope-meta",
        "title": "Developer metadata in the API envelope",
        "purpose": ("No built-in check reads the shape of a JSON response; deciding "
                    "whether the envelope's meta block names the database engine "
                    "needs an analyser over the body"),
        "inputs": [{"url": url, "method": "GET"}],
        "source": _ENVELOPE_SOURCE,
    }


def _seen_work(k: dict) -> tuple[set[tuple[str, str]], set[str], set[str]]:
    """What was already asked: ({(tool, url)}, crawled seed URLs, busy tools)."""
    work = k.get("work") or {}
    seen: set[tuple[str, str]] = set()
    crawled: set[str] = set()
    busy_tools: set[str] = set()
    for line in work.get("history") or []:
        text = str(line)
        if text.endswith("]") and " [" in text:
            text = text.rsplit(" [", 1)[0]
        tool, _, url = text.partition(" ")
        seen.add((tool, url.strip()))
        if tool == "discovery.crawl":
            crawled.update(url.split())
    for w in (work.get("pending") or []) + (work.get("running") or []):
        tool, url = str(w.get("tool")), str(w.get("url") or "")
        seen.add((tool, url))
        busy_tools.add(tool)
        if tool == "discovery.crawl":
            crawled.update(url.split())
    return seen, crawled, busy_tools


def heuristic_responder(system: str, user: str) -> str:
    k = extract_knowledge(user)
    base = (k.get("run") or {}).get("base_url") or ""
    eps = sorted(_endpoints(k), key=lambda e: str(e.get("url") or ""))
    services = _services(k)
    frontier = sorted(str(u) for u in (k.get("frontier") or []) if u)
    tools = {str(t) for t in (k.get("tools") or [])}
    coverage = k.get("coverage") or {}
    allow_auth = bool((k.get("run") or {}).get("allow_auth_testing"))
    open_leads = ((k.get("hypotheses") or {}).get("open") or [])
    work = k.get("work") or {}
    seen, crawled, busy_tools = _seen_work(k)
    in_flight = bool(work.get("pending") or work.get("running"))

    def todo(tool: str, url: str) -> bool:
        return tool in tools and (tool, url) not in seen

    hypotheses: list[dict] = []
    actions: list[dict] = []
    todos: list[dict] = []

    def act(tool: str, params: dict, reason: str, priority: int, variant: str,
            hyp: str | None = None) -> bool:
        """Add one action and mark it asked-of. Returns False (and adds nothing)
        when the reply is already full: the next cycle proposes it instead, so a
        truncated reply never silently drops work."""
        if len(actions) >= MAX_ACTIONS:
            return False
        actions.append({"tool": tool, "params": params, "reason": reason,
                        "priority": priority, "variant": variant,
                        **({"hypothesis": hyp} if hyp else {})})
        key = str(params.get("url") or params.get("needle") or "")
        if params.get("param") is not None:
            # the knowledge's parameter-aware target form (url|location:param)
            key = f"{key}|{params.get('location') or 'query'}:{params['param']}"
        if params.get("account") is not None:
            key = f"{key}|acct:{params['account']}"   # one login per account
        seen.add((tool, key))                   # not twice in one reply
        return True

    # 0) Bootstrap: nothing is known and nothing has been asked yet.
    if base and not eps and not services and not seen and not in_flight:
        for tool, prio, why in (
                ("discovery.fetch_root", 10,
                 ("start by fetching the target root to confirm it is reachable "
                  "and to see what it links to")),
                ("discovery.robots", 20,
                 "robots.txt lists the paths the application itself advertises"),
                ("discovery.sitemap", 21,
                 "sitemap.xml lists URLs the application wants indexed")):
            if tool in tools:
                act(tool, {"url": base}, why, prio, "start")
        todos.append({"step": "Fetch the root, robots.txt and the sitemap",
                      "status": "in_progress"})
        todos.append({"step": "Crawl what the first pages link to",
                      "status": "pending"})
        return _reply(
            "Nothing is known about the target yet. I start by looking at it: the "
            "root page, robots.txt and the sitemap show where the application "
            "advertises its surface; what they link to decides where I go next.",
            [], actions, todos, replies=_replies(user))

    # 1) An API-looking surface: authorization boundaries are the interesting
    #    property of APIs (collection endpoints, object references, roles).
    api_eps = [e for e in eps if e.get("api") or str(e.get("path", "")).startswith("/api")]
    if api_eps and "discovery.crawl" in tools and "discovery.crawl" not in busy_tools:
        seeds = sorted({u for u in frontier if "/api" in u} - crawled)[:3]
        if seeds and not any(a.get("variant") == "api-surface" for a in actions):
            hypotheses.append({
                "id": "h1", "label": "API authorization boundaries untested",
                "hypothesis": ("The application exposes an API surface "
                               f"({api_eps[0].get('path', '')}); object-level "
                               "authorization between roles is the classic weakness "
                               "of such surfaces and has not been examined."),
                "signals": {"surface": "api", "endpoints": len(api_eps)}})
            act("discovery.crawl",
                {"url": base or seeds[0], "seeds": seeds,
                 "max_pages": len(seeds)},
                "map the API surface: fetch its collection endpoints so object "
                "references and role boundaries become observable",
                25, f"api-surface-{_h(' '.join(seeds))}", "h1")
            todos.append({"step": "Examine the API surface for authorization "
                                  "boundaries between roles", "status": "in_progress"})

    # 2) A login form: session and authentication handling.
    logins = [e for e in eps if e.get("login_form")]
    if logins and todo("cookies.flags", str(logins[0].get("url") or base)):
        login = logins[0]
        hypotheses.append({
            "id": "h2", "label": "Session handling around the login flow",
            "hypothesis": ("The login flow issues session credentials; their "
                           "attributes (flags, scope, lifetime) are observable "
                           "through the authenticated surface.")})
        act("cookies.flags", {"url": str(login.get("url") or base)},
            "the login endpoint authenticates users; examine the session cookies "
            "it sets", 30, "login-session", "h2")
        todos.append({"step": "Examine session credentials issued by the login flow",
                      "status": "pending"})

    # 2b) Provided accounts ("hardcore by default"): become each user the operator
    #     named, so the application can be explored from inside — as that user.
    accounts = [a for a in (k.get("run") or {}).get("accounts") or []
                if a.get("label")]
    live_sessions = {str(s.get("label")) for s in
                     (k.get("run") or {}).get("sessions") or []}
    if allow_auth and accounts and logins:
        lf = logins[0].get("login_form") or {}
        lf_url = str(logins[0].get("url") or base)
        for acct in accounts:
            label = str(acct.get("label"))
            if label in live_sessions:
                continue               # already logged in as this account
            if todo("auth.login", f"{lf_url}|acct:{label}") and act(
                    "auth.login",
                    {"url": lf_url, "account": label,
                     "user_field": lf.get("user_field") or "user",
                     "password_field": lf.get("password_field") or "password",
                     "method": lf.get("method") or "POST"},
                    f"log in as {label} ({acct.get('user')}) to explore the "
                    "application as this user", 28, f"login-{label}"):
                todos.append({"step": f"Log in as {label} and explore as this user",
                              "status": "in_progress"})

    # 2c) Object-level access: with an identity of one's own, ask for objects that
    #     belong to somebody else — or with no login at all — and watch the answer.
    if allow_auth and live_sessions and "authz.object" in tools:
        from src.greybox_web.tools.authz import looks_like_object
        for e in eps:
            url = str(e.get("url") or "")
            if (looks_like_object(str(e.get("path") or url))
                    and todo("authz.object", url)):
                act("authz.object", {"url": url},
                    "fetch this object under every identity the run has "
                    "(anonymous and each logged-in account): shared access is the "
                    "object-level authorization weakness", 40, f"authz-{_h(url)}")
                todos.append({"step": "Test object-level access on discovered "
                                      "objects", "status": "in_progress"})

    # 3) Upload/document-looking surfaces: exposure of stored content. Surfaces
    #    that ACCEPT content (uploads) imply a storage directory worth listing;
    #    read-only document listings rank below them.
    write_hints = ("upload", "media", "attachment")
    doc_hints = ("document", "doc", "file")

    def _storage_rank(e: dict) -> int:
        p = str(e.get("path", "")).lower()
        if any(w in p for w in write_hints):
            return 0
        if any(w in p for w in doc_hints):
            return 1
        return 9

    up_eps = sorted((e for e in eps if _storage_rank(e) < 9),
                    key=lambda e: (_storage_rank(e), str(e.get("url") or "")))
    if up_eps:
        up = up_eps[0]
        path = str(up.get("path") or "")
        directory = path.rsplit("/", 1)[0] or "/"
        p = urlsplit(str(up.get("url") or base))
        url = f"{p.scheme or 'http'}://{p.netloc}{directory}"
        if todo("exposure.dirlisting", url):
            hypotheses.append({
                "id": "h3", "label": "Stored user content may be listable",
                "hypothesis": ("The application stores user content under "
                               f"{directory}; a directory index there would expose "
                               "other users' files.")})
            act("exposure.dirlisting", {"url": url},
                "user content is stored under this path; check whether the storage "
                "directory is listable", 30, "stored-content", "h3")
            todos.append({"step": "Check whether stored user content is listable",
                          "status": "pending"})

    # 3b) Discovered parameters: every one deserves the injection checks (and
    #     redirect.open when its name says "redirect target"). Login-form fields
    #     are the authentication surface — only auth.default_creds (scope-gated,
    #     rule 3c) may touch them — so the parameter rules leave them alone.
    login_urls = {str(e.get("url") or "") for e in eps if e.get("login_form")}
    param_handled = 0
    for p in (k.get("assets") or {}).get("parameters") or []:
        if not isinstance(p, dict) or param_handled >= PARAM_BATCH:
            continue          # first few per reply; the loop asks again next cycle
        name = str(p.get("name") or "")
        loc = str(p.get("location") or "query")
        endpoint = str(p.get("endpoint") or "")
        if not name or not endpoint or endpoint in login_urls:
            continue
        key = f"{endpoint}|{loc}:{name}"
        if todo("injection.reflection", key) and act(
                "injection.reflection", {"url": endpoint, "param": name,
                                         "location": loc},
                f"test the {name} parameter for unencoded reflection", 40,
                f"injr-{_h(endpoint)}-{name}", "h4"):
            param_handled += 1
        if todo("injection.errors", key) and act(
                "injection.errors", {"url": endpoint, "param": name,
                                     "location": loc},
                f"test the {name} parameter for error-based injection indicators",
                42, f"inje-{_h(endpoint)}-{name}", "h4"):
            param_handled += 1
        if (name.lower() in REDIRECT_PARAM_NAMES
                and todo("redirect.open", key) and act(
                    "redirect.open", {"url": endpoint, "param": name,
                                      "location": loc},
                    f"{name} looks like a redirect target; check whether it accepts "
                    "an arbitrary host", 38, f"openr-{_h(endpoint)}-{name}", "h4")):
            param_handled += 1
    if param_handled:
        hypotheses.append({
            "id": "h4", "label": "Input handling of discovered parameters",
            "hypothesis": ("Discovered parameters reach application logic; "
                           "unencoded reflection, error-based indicators and "
                           "unchecked redirect targets are the classic weaknesses "
                           "of input handling, and each parameter deserves its "
                           "outcome."),
            "signals": {"parameters": param_handled}})
        todos.append({"step": "Test every discovered parameter (reflection, error "
                              "indicators, redirect targets)", "status": "in_progress"})

    # 3c) A login form under an auth-testing scope: the default-credentials check.
    if allow_auth and "auth.default_creds" in tools:
        logins = [e for e in eps if e.get("login_form") and str(e.get("url") or "")]
        if logins:
            hypotheses.append({
                "id": "h5",
                "label": "Default credentials on the login form may work",
                "hypothesis": ("The login form may still accept a well-known "
                               "default username/password pair; the fixed pairs "
                               "of the default-credentials check settle it, "
                               "against an invalid baseline."),
                "signals": {"login_forms": len(logins)}})
            for e in logins:
                url = str(e.get("url") or "")
                lf = e.get("login_form") or {}
                if todo("auth.default_creds", url) and act(
                        "auth.default_creds",
                        {"url": url,
                         "user_field": lf.get("user_field") or "user",
                         "password_field": lf.get("password_field") or "password",
                         "method": lf.get("method") or "POST"},
                        "the login form may accept well-known default credentials; "
                        "try the fixed pairs", 30, f"defcreds-{_h(url)}", "h5"):
                    todos.append({"step": "Test the login form for default "
                                          "credentials", "status": "in_progress"})

    # 3d) Endpoints that showed an error/debug signature while crawled: the
    #     disclosure check re-examines them.
    for e in eps:
        url = str(e.get("url") or "")
        if e.get("error_signature") and url and todo("info.errors", url):
            act("info.errors", {"url": url},
                "this endpoint showed an error or debug signature while crawled; "
                "re-examine it for stack-trace disclosure", 45, f"info-{_h(url)}")

    # 3e) A request-header echo no fixed tool can test (batch E): an endpoint that
    #     echoed the discovery marker header ("header_reflect_hint" on the
    #     knowledge entry). injection.* address query/form parameters only — the
    #     instrument is missing, so COMPOSE one (tool.define, declarative) and use
    #     it at once. A spec id that already exists is never redefined; a defined
    #     instrument with no completed use is a coverage gap (rule 6b).
    if "tool.define" in tools:
        hinted = [e for e in eps
                  if e.get("header_reflect_hint") and str(e.get("url") or "")]
        if hinted:
            e = hinted[0]
            hint_url = str(e.get("url"))
            hint_name = str(e.get("header_reflect_hint"))
            define_key = "define:dyn.header-reflection"
            if ("tool.define", define_key) not in seen:
                spec = {
                    "id": "dyn.header-reflection",
                    "kind": "check",
                    "title": "Unencoded reflection of a request header "
                             "(potential XSS)",
                    "description": ("Sends the inert canary in a request header the "
                                    "endpoint was seen to echo and reports a "
                                    "response that carries it back unencoded."),
                    "param_keys": ["url", "header"],
                    "request": {"method": "GET",
                                "inject": [{"into": "header", "key": hint_name,
                                            "location": "header",
                                            "transform": "canary"}],
                                "follow": True},
                    "baseline": False,
                    "verdict": {"mode": "any",
                                "predicates": [{"type": "reflection_of",
                                                "of": "canary"}]},
                    "finding": {
                        "title": (f"Unencoded reflection of request header "
                                  f"{hint_name} (potential XSS)"),
                        "description": (f"The {hint_name} request header of "
                                        f"{hint_url} is echoed into the HTML "
                                        "without encoding: the inert canary Vigilo "
                                        "sent, including its raw <, >, \" and ' "
                                        "characters, appears verbatim in the "
                                        "response. Whoever controls the header "
                                        "controls markup and script in the page."),
                        "severity": "medium", "confidence": "high",
                        "cwe": "CWE-79",
                        "hint": ("Encode untrusted header values by output "
                                "context (element body, attribute, JavaScript, "
                                "URL); a reflection that still carries raw <, >, "
                                "\" or ' characters is exploitable.")}}
                hypotheses.append({
                    "id": "h6",
                    "label": "Request-header reflection untested by the fixed tools",
                    "hypothesis": ("The endpoint echoes a request header value into "
                                   "its HTML; an unencoded reflection there is "
                                   "script-injectable. The fixed tools cannot send "
                                   "request headers, so a dynamic instrument "
                                   "tests it."),
                    "signals": {"header": hint_name, "endpoint": hint_url}})
                if act("tool.define", {"spec": spec},
                       f"no fixed tool injects into request headers, but "
                       f"{hint_url} echoes the {hint_name} header: compose a "
                       "dynamic header-reflection instrument and use it here",
                       26, "define-header-reflection", "h6"):
                    # act() keyed the definition by its absent url; the knowledge
                    # records it as define:<spec id> — same key from now on
                    seen.discard(("tool.define", ""))
                    seen.add(("tool.define", define_key))
                if ("dyn.header-reflection", hint_url) not in seen:
                    act("dyn.header-reflection", {"url": hint_url,
                                                  "header": hint_name},
                        f"the header-echo instrument on {hint_url}: send the canary "
                        f"in {hint_name} and read the reflection back", 27,
                        f"dynrefl-{_h(hint_url)}", "h6")
                todos.append({"step": "Test the echoed request header with a "
                                      "dynamic instrument", "status": "in_progress"})

    # 3f) A developer-facing JSON envelope (Phase 3): headers.*/cookies.*/exposure.*
    #     read the wire and well-known paths, never a data SHAPE. The need is an
    #     ANALYSIS ("read the envelope, decide whether its meta block names the
    #     stack"), so the agent writes the analyser and runs it in the sandbox --
    #     validated before registration, no network of its own.
    if "tool.compose" in tools:
        enveloped = [e for e in eps
                     if (e.get("json_envelope") or {}).get("meta_versions")
                     and str(e.get("url") or "")]
        if enveloped:
            e = enveloped[0]
            env_url = str(e.get("url"))
            # one composition per run is enough: the analyser is generic over the
            # responses it is handed, and admission refuses a duplicate id anyway
            composed_already = any(t == "tool.compose" for t, _ in seen)
            compose_key = "define:tool.envelope-meta"
            if not composed_already and ("tool.compose", compose_key) not in seen:
                hypotheses.append({
                    "id": "h7",
                    "label": "Developer metadata in the JSON envelope",
                    "hypothesis": ("The API's envelope carries a meta block naming "
                                   "the database engine and versions; no built-in "
                                   "check reads response data shape, so an "
                                   "agent-authored analyser decides it."),
                    "signals": {"endpoint": env_url,
                                "meta_keys": (e.get("json_envelope") or {})
                                .get("meta_keys", [])}})
                if act("tool.compose",
                       {"spec": _envelope_spec(env_url)},
                       f"{env_url} answers with a developer meta block "
                       f"({', '.join((e.get('json_envelope') or {}).get('meta_keys', []))})"
                       f" — no built-in check reads a JSON envelope, so write an "
                       f"analyser for it and run it in the sandbox",
                       26, "compose-envelope-meta", "h7"):
                    seen.discard(("tool.compose", ""))
                    seen.add(("tool.compose", compose_key))
                if ("tool.envelope-meta", env_url) not in seen:
                    act("tool.envelope-meta", {"url": env_url},
                        f"run the composed analyser on {env_url}: read the JSON "
                        f"envelope's meta block and report what it names", 27,
                        f"compose-use-{_h(env_url)}", "h7")
                todos.append({"step": "Analyse the API envelope with a composed "
                                      "tool", "status": "in_progress"})

    # 4) Checks that fit what was discovered.
    for svc in services:
        root = svc.rstrip("/") + "/"
        for tool in SERVICE_CHECKS:
            if todo(tool, root):
                act(tool, {"url": root, "service": svc},
                    f"baseline posture of the service {svc}", 50,
                    f"svc-{_h(root)}")
    for e in eps:
        url = str(e.get("url") or "")
        if not url:
            continue
        if e.get("sets_cookies") and todo("cookies.flags", url):
            act("cookies.flags", {"url": url, "endpoint": url},
                "this endpoint sets cookies; examine their attributes", 50,
                f"cookies-{_h(url)}")
        if e.get("api") and todo("cors.policy", url):
            act("cors.policy", {"url": url, "endpoint": url},
                "an API-looking endpoint: examine its cross-origin policy", 50,
                f"cors-{_h(url)}")
        for leak in (e.get("leaks") or [])[:2]:
            if todo("netview.reexamine", str(leak)):
                act("netview.reexamine", {"kind": "leak", "needle": str(leak)},
                    f"{leak} leaked in a response; do other recorded responses "
                    "disclose more internals?", 60, f"leak-{_h(str(leak))}")
        for host in (e.get("third_party") or [])[:2]:
            if todo("netview.reexamine", str(host)):
                act("netview.reexamine", {"kind": "origin", "needle": str(host)},
                    f"the page loads content from {host}; which other recorded "
                    "pages depend on it?", 60, f"origin-{_h(str(host))}")

    # 4b) A page whose behaviour lives in its own code: read the code. A bundle is
    #     an INPUT for extraction, not surface to crawl — the endpoints it names
    #     become surface, and only then can they be tested.
    if ("discovery.scripts" in tools and base
            and ("discovery.scripts", base) not in seen and not in_flight
            and coverage.get("pages_fetched")):
        act("discovery.scripts", {"url": base},
            "the application is rendered by script: read its own JavaScript and "
            "JSON to learn the routes and API calls it makes, then test them", 12,
            f"scripts-{_h(base)}")

    # 5) Advance the frontier: understand the rest of the application.
    remaining_pages = int(coverage.get("max_pages") or 0) - int(
        coverage.get("pages_fetched") or 0)
    todo_frontier = [u for u in frontier if u not in crawled]
    if (todo_frontier and "discovery.crawl" in tools
            and "discovery.crawl" not in busy_tools and remaining_pages > 0
            and not any(a["tool"] == "discovery.crawl" for a in actions)):
        seeds = todo_frontier[:min(CRAWL_BATCH, remaining_pages)]
        act("discovery.crawl",
            {"url": base or seeds[0], "seeds": seeds,
             "max_pages": len(seeds)},
            "advance the crawl frontier to understand the rest of the application",
            15, f"frontier-{_h(' '.join(seeds))}")
        todos.append({"step": "Advance the crawl frontier", "status": "in_progress"})

    # 6) The coverage ledger's gaps: fill surface×check-class combinations
    #    with no completed outcome before the assessment may be judged adequate.
    #    Everything proposed comes from the knowledge (gap entries name endpoints,
    #    parameters and service roots the run discovered).
    gaps = k.get("gaps") or {}
    ep_by_url = {str(e.get("url") or ""): e for e in eps}
    for g in (gaps.get("parameters") or [])[:PARAM_BATCH]:
        endpoint = str(g.get("endpoint") or "")
        name = str(g.get("name") or "")
        loc = str(g.get("location") or "query")
        key = f"{endpoint}|{loc}:{name}"
        variants = {"injection.reflection": f"injr-{_h(endpoint)}-{name}",
                    "injection.errors": f"inje-{_h(endpoint)}-{name}",
                    "redirect.open": f"openr-{_h(endpoint)}-{name}"}
        for tool in g.get("missing") or []:
            if variants.get(tool) and todo(tool, key):
                act(tool, {"url": endpoint, "param": name, "location": loc},
                    f"fill the coverage gap: {tool} has no completed outcome for "
                    f"the {name} parameter yet", 55, variants[tool])
    for g in (gaps.get("endpoints") or [])[:4]:
        url = str(g.get("url") or "")
        for tool in g.get("missing") or []:
            if tool == "info.errors" and todo("info.errors", url):
                act("info.errors", {"url": url},
                    "fill the coverage gap: the error-disclosure check has no "
                    "completed outcome for this endpoint yet", 55, f"info-{_h(url)}")
            elif (tool == "auth.default_creds" and allow_auth
                  and todo("auth.default_creds", url)):
                lf = (ep_by_url.get(url) or {}).get("login_form") or {}
                act("auth.default_creds",
                    {"url": url, "user_field": lf.get("user_field") or "user",
                     "password_field": lf.get("password_field") or "password",
                     "method": lf.get("method") or "POST"},
                    "fill the coverage gap: the default-credentials check has no "
                    "completed outcome for this login form yet", 55,
                    f"defcreds-{_h(url)}")
            elif tool == "authz.object" and allow_auth and todo("authz.object", url):
                act("authz.object", {"url": url},
                    "fill the coverage gap: this object has no completed "
                    "object-access outcome across the run's identities yet", 55,
                    f"authz-{_h(url)}")
    for g in (gaps.get("services") or [])[:4]:
        root = str(g.get("url") or "")
        for tool in g.get("missing") or []:
            if todo(tool, root):
                act(tool, {"url": root, "service": root.rstrip("/")},
                    f"fill the coverage gap: {tool} has no completed outcome for "
                    "the service root yet", 55, f"svc-{_h(root)}")

    # 6b) A defined dynamic instrument with no completed use (batch E): a
    #     coverage gap like any other. Propose one use where it fits — an
    #     endpoint whose recorded header echo matches its declared params, else
    #     the first endpoint.
    for g in (gaps.get("dynamic") or [])[:4]:
        tid = str(g.get("id") or "")
        keys = {str(p) for p in (g.get("param_keys") or [])}
        if not tid or tid not in tools:
            continue
        fit = [e for e in eps if e.get("header_reflect_hint")] \
            if "header" in keys else []
        target = next((e for e in (fit or eps) if str(e.get("url") or "")), None)
        if target is None:
            continue
        url = str(target.get("url"))
        params = {"url": url}
        if "header" in keys and target.get("header_reflect_hint"):
            params["header"] = str(target["header_reflect_hint"])
        if (tid, url) not in seen:
            act(tid, params,
                f"fill the coverage gap: the defined instrument {tid} has no "
                "completed use yet", 55, f"use-{_h(tid)}")

    # 7) Adequacy: only when nothing can be proposed, nothing is in flight, no
    #    gap remains and no crawlable page is left.
    fetched = int(coverage.get("pages_fetched") or 0)
    max_pages = int(coverage.get("max_pages") or 0)
    gaps_left = sum(len(gaps.get(s) or []) for s in
                    ("parameters", "endpoints", "services", "dynamic"))
    crawlable = bool(frontier) and max_pages - fetched > 0
    assessment = ("incomplete" if (actions or in_flight or gaps_left or crawlable)
                  else "adequate")
    reasoning = (f"Knowledge shows {len(eps)} endpoint(s), {len(frontier)} frontier "
                 f"URL(s), {fetched}/{max_pages} pages fetched, "
                 f"{len(open_leads)} open hypotheses, {gaps_left} unfilled coverage "
                 f"gap(s). ")
    if hypotheses:
        reasoning += ("Feature-specific directions found: "
                      + ", ".join(h["label"] for h in hypotheses) + ".")
    elif actions:
        reasoning += ("No feature-specific direction; extending coverage of what "
                      "is known.")
    elif in_flight:
        reasoning += "Waiting for the work in flight before deciding what is next."
    elif gaps_left:
        reasoning += (f"The coverage ledger still lists {gaps_left} unfilled "
                      "surface×class gap(s); the assessment is incomplete.")
    else:
        reasoning += "Nothing left to advance: the assessment is adequate."
    return _reply(reasoning, hypotheses, actions, todos, assessment,
                  replies=_replies(user))
