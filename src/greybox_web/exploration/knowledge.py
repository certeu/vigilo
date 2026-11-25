"""The run's knowledge as the exploration model sees it.

Built from the database — the same tables the UI reads — plus a few live values only
the supervisor holds (budget, frontier). Everything target-derived is redacted and
capped; the builder is read-only and never touches the network. The result is a plain
JSON-able dict: the exploration prompt embeds it as data, the fake model and the
behavioural acceptance test react to it, and ``fingerprint`` gives the explorer its
quiet-mode signal (nothing changed -> no model call).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.greybox_web.tools.authz import looks_like_object

from src.greybox_web import tools as tool_registry
from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxFinding,
    GreyboxGraphNode,
    GreyboxRun,
    GreyboxTarget,
    GreyboxWorkOrder,
)
from src.greybox_web import redaction
from src.greybox_web.assetclass import classify_path, is_static_like, static_prefix
from src.greybox_web.scope import ScopePolicy

_JSON_BLOCK = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


def extract_knowledge(user: str) -> dict:
    """The first fenced JSON block of an explorer prompt (the knowledge context).
    Shared by the fake model and tests; production code does not depend on fake.py."""
    m = _JSON_BLOCK.search(user)
    if not m:
        return {}
    try:
        return json.loads(m.group(1))
    except ValueError:
        return {}

# Caps: generous enough to describe a real application, small enough to stay a cheap
# prompt. When the byte budget is exceeded the largest volatile sections are dropped
# first (see _fit).
CAP_ENDPOINTS = 60
CAP_PARAMS = 40
CAP_OBSERVATIONS = 30
CAP_FINDINGS = 30
CAP_OPEN_LEADS = 20
CAP_SETTLED_LEADS = 15
CAP_OPERATIONS = 40
CAP_INVESTIGATIONS = 20
CAP_WORK_PENDING = 20
CAP_WORK_RUNNING = 5
CAP_WORK_RECENT = 15
CAP_WORK_HISTORY = 120
CAP_FRONTIER = 20
CAP_DELTA = 20
CAP_RESULTS = 6
CAP_RESULT_OBS = 12
CAP_FACT_CHARS = 1500
BYTE_BUDGET = 30_000
COMPACT_BYTE_BUDGET = 8_000        # the retry after a truncated reply

# Static assets (bundles, stylesheets, images, fonts, source maps) say nothing about
# the application's behaviour but a modern front-end serves hundreds of them: they are
# summarised as counts by prefix instead of listed one by one. The classifier is the
# one the Network map / Traffic views use (``assetclass``).
CAP_STATIC_PREFIXES = 10


def is_static_asset(url_or_path: str, content_type: str | None = None) -> bool:
    return is_static_like(classify_path(url_or_path, content_type))


def summarise_static(urls: list[str]) -> dict[str, Any]:
    """Counts of static assets by folding prefix and by file type."""
    by_prefix: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for u in urls:
        pre = static_prefix(u)
        by_prefix[pre] = by_prefix.get(pre, 0) + 1
        leaf = (urlsplit(u).path or u).rsplit("/", 1)[-1]
        ext = leaf.rsplit(".", 1)[-1].lower() if "." in leaf else "other"
        by_type[ext] = by_type.get(ext, 0) + 1
    top = sorted(by_prefix.items(), key=lambda kv: (-kv[1], kv[0]))
    return {"count": len(urls),
            "by_prefix": dict(top[:CAP_STATIC_PREFIXES]),
            "by_type": dict(sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))[:8]),
            "note": "static assets are summarised, not listed"}


@dataclass
class KnowledgeInputs:
    """Live values the supervisor/explorer provide; everything else comes from the DB."""

    budget: dict[str, Any] = field(default_factory=dict)     # requests/duration used
    frontier: list[str] = field(default_factory=list)        # unfetched in-scope URLs
    coverage: dict[str, int] = field(default_factory=dict)   # pages fetched / max
    agent: dict[str, Any] = field(default_factory=dict)      # model calls/tokens left
    accounts: list[dict[str, Any]] = field(default_factory=list)   # login accounts
    sessions: list[dict[str, Any]] = field(default_factory=list)   # live identities
    delta: list[dict[str, Any]] = field(default_factory=list)  # events since last call
    todolist: list[dict[str, Any]] = field(default_factory=list)
    # Run-defined dynamic tools (batch E): {id, title, kind, param_keys} — never the
    # spec (the executor holds it; every use is a proposal through admission).
    dynamic_tools: list[dict[str, Any]] = field(default_factory=list)


# Extensions a frontier entry may have and still be work: a JSON/JS *document* can
# name endpoints or carry data; a stylesheet, image, font or source map cannot.
_HASHED_BUNDLE = re.compile(r"/[0-9a-f]{6,}[.\-]|[.\-][0-9a-f]{8,}\.m?js$|"
                            r"(?:^|/)(?:chunks?|_next|_nuxt|static/js|assets/js)/")
_WORK_SUFFIXES = (".json", ".js", ".mjs", ".graphql", ".gql", ".xml", ".txt", ".yaml",
                  ".yml", ".wsdl", ".har")


def is_work_url(url: str) -> bool:
    """Is this URL something a *tester* would examine by hand?

    Build output is not: hashed chunk names carry no meaning and their URLs are not
    surface. A field assessment's frontier put 20 hashed Next.js chunks in front of two real
    pages, so the agent never saw the pages (defect F3). A page, an interface, a form
    action or a JSON document is work; so is a *hand-written* script (``/static/app.js``,
    ``/main.js``), which names routes; a hashed bundle is not.
    """
    path = (urlsplit(url).path or url).lower().split("?")[0]
    if _HASHED_BUNDLE.search(path):
        return False                     # build output: not surface, not readable
    if path.endswith(_WORK_SUFFIXES):
        return True                      # a document: may name endpoints or carry data
    return not is_static_asset(url)


def frontier_view(frontier: Any, cap: int = CAP_FRONTIER) -> list[str]:
    """The frontier as the agent sees it: work first, then the cap.

    Ordering, not truncation order, decides what the agent can see: interfaces and
    documents come before build output, so a wall of ``/_next/static/chunks/*`` can
    never occupy every slot (defect F3). Pure, and used by both the knowledge
    snapshot and the supervisor's live inputs, so the two can never disagree.
    """
    urls = [str(u) for u in (frontier or []) if u]
    work = [u for u in urls if is_work_url(u)]
    rest = [u for u in urls if not is_work_url(u)]
    return [*sorted(set(work)), *sorted(set(rest))][:max(0, cap)]


def _static(a: GreyboxAsset) -> bool:
    return is_static_asset(a.key, (a.data or {}).get("content_type"))


def _clip(text: Any, n: int) -> str:
    s = str(text or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def _endpoint_view(a: GreyboxAsset) -> dict[str, Any]:
    d = a.data or {}
    path = urlsplit(a.key).path
    codes = d.get("status_codes") or []
    content_type = d.get("content_type")
    out: dict[str, Any] = {
        "url": a.key,
        "path": path,
        "tested": bool(a.tested),
        "api": path == "/api" or path.startswith("/api/")
        or (isinstance(content_type, str) and "json" in content_type),
    }
    if codes:
        out["status"] = codes[-1] if isinstance(codes[-1], int) else codes[-1][0]
    if content_type:
        out["content_type"] = _clip(content_type, 60)
    if d.get("title"):
        out["title"] = _clip(d.get("title"), 80)
    if d.get("methods") and "POST" in d["methods"]:
        out["methods"] = d["methods"]
    if d.get("error_signature"):
        out["error_signature"] = _clip(d["error_signature"], 80)
    if d.get("login_form"):
        lf = d["login_form"] or {}
        out["login_form"] = {"method": lf.get("method"),
                             "user_field": lf.get("user_field"),
                             "password_field": lf.get("password_field"),
                             "fields": sorted((lf.get("fields") or {}).keys())[:10]}
    if d.get("sets_cookies"):
        out["sets_cookies"] = True
    if d.get("source"):
        # where the endpoint came from (browser:fetch, script:<bundle>, link):
        # API calls only a browser saw are the surface an HTML crawler misses
        out["source"] = [str(x)[:60] for x in d["source"]][:3]
    if d.get("header_reflect_hint"):
        # a request-header echo discovery's marker spotted (batch E): only a
        # dynamic instrument can test a header reflection — the hint is what the
        # model composes one from
        out["header_reflect_hint"] = _clip(d["header_reflect_hint"], 60)
    # Developer-facing JSON envelope signals (Phase 3): a data SHAPE no built-in
    # check reads -- the model composes an analyser for it
    if d.get("developer_meta") or d.get("inventory_key"):
        out["json_envelope"] = {k: d[k] for k in
                                ("developer_meta", "meta_keys", "meta_versions",
                                 "inventory_key")
                                if d.get(k)}
    leaks = [str(h.get("v")) for h in (d.get("leaks") or []) if isinstance(h, dict)
             and h.get("v")][:3]
    if leaks:
        out["leaks"] = leaks
    third = [str(e.get("h")) for e in (d.get("third_party") or []) if isinstance(e, dict)
             and e.get("h")][:3]
    if third:
        out["third_party"] = third
    return out


def _target(w: GreyboxWorkOrder) -> str:
    """The URL a work order acts on (for the model's no-repeat view). A parameter
    probe carries its parameter — ``url|location:name`` — so two probes of the same
    endpoint through different parameters are different work."""
    p = w.params if isinstance(w.params, dict) else {}
    u = p.get("url") or p.get("endpoint") or ""
    seeds = p.get("seeds")
    if w.tool in ("tool.define", "tool.compose"):
        # one instrument per spec id is different work, not a repeat: the id is the
        # target (a redefinition of the same id is admission's duplicate rejection)
        sid = p.get("spec") if isinstance(p.get("spec"), dict) else {}
        return _clip(f"define:{sid.get('id') or ''}", 200)
    if w.tool == "auth.login" and p.get("account"):
        # one login per account is different work, not a repeat
        return _clip(f"{u}|acct:{p['account']}", 200)
    if w.tool == "discovery.crawl" and isinstance(seeds, list) and seeds:
        return _clip(" ".join(str(x) for x in seeds[:3]), 200)
    if p.get("host") and p.get("port"):
        # a network action: the service it addressed (and the hello it sent)
        return _clip(f"tcp://{p['host']}:{p['port']}"
                     + (f"|probe:{p['probe']}" if p.get("probe") else ""), 200)
    if w.tool == "net.sweep":
        return _clip("sweep:" + ",".join(str(x) for x in (p.get("targets") or ["*"]))
                     + "/" + ",".join(str(x) for x in (p.get("ports") or ["*"])), 200)
    if w.tool == "net.resolve":
        return _clip(f"dns:{p.get('name')}", 200)
    extra = ""
    if p.get("session"):
        extra += f"|as:{p['session']}"           # same URL, another identity
    if isinstance(p.get("args"), dict) and p["args"]:
        extra += "|args:" + json.dumps(p["args"], sort_keys=True, default=str)[:80]
    if extra:
        return _clip((u or "") + extra, 200)
    if u and p.get("param") is not None:
        u = f"{u}|{p.get('location') or 'query'}:{p['param']}"
    return _clip(u, 200)


def _param_view(a: GreyboxAsset, parent_key: str | None) -> dict[str, Any]:
    # key format: "<endpoint>#<location>:<name>" (see graph.param_key)
    tail = a.key.split("#", 1)[1] if "#" in a.key else ""
    location, _, name = tail.partition(":")
    return {"name": name or a.label, "location": location or "query",
            "endpoint": parent_key or (a.key.split("#", 1)[0] or "")}


# The coverage ledger: check classes whose natural target is a
# service root, and the parameter check classes. Both sets are intersected with
# the run's selected checks before a gap is listed.
SERVICE_ROOT_CHECKS = ("headers.security", "headers.disclosure", "cookies.flags",
                       "cors.policy", "exposure.files", "exposure.dirlisting")
PARAM_CHECKS = ("injection.reflection", "injection.errors")
GAPS_NOTE = ("a surface with no entry for a class is UNEXAMINED, not clean; failed "
             "or skipped checks stay gaps")


def _is_redirect_param(name: str) -> bool:
    """Parameter names that commonly carry a redirect target. The canonical set
    lives with the fake model (``fake.REDIRECT_PARAM_NAMES``); the lazy import keeps
    the module load order simple (fake imports this module)."""
    from src.greybox_web.exploration.fake import REDIRECT_PARAM_NAMES
    return str(name or "").lower() in REDIRECT_PARAM_NAMES


def _gaps(selected: set[str], allow_auth: bool, has_identities: bool,
          work: list[GreyboxWorkOrder],
          endpoints: list[GreyboxAsset], params: list[GreyboxAsset],
          services: list[GreyboxAsset]) -> tuple[dict[str, Any], int]:
    """Surface × check-class combinations with no completed outcome, from the work
    orders themselves (never from the capped history strings). Only ``done`` counts
    as an outcome — a failed or skipped check is unexamined, never clean (the
    coverage invariant). Returns ``(gaps section, parameter assets fully tested)``.

    A login form's fields are the authentication surface: ``auth.default_creds`` is
    their check class (when the scope allows it), so they are not listed as
    parameter gaps for the injection classes."""
    param_done: set[tuple[str, str, str, str]] = set()   # (tool, url, location, name)
    url_done: set[tuple[str, str]] = set()               # (tool, url)
    for w in work:
        if w.status != "done":
            continue                    # failed/skipped: still a gap
        p = w.params if isinstance(w.params, dict) else {}
        u = str(p.get("url") or p.get("endpoint") or "")
        if not u:
            continue
        url_done.add((w.tool, u))
        if p.get("param") is not None:
            param_done.add((w.tool, u, str(p.get("location") or "query"),
                            str(p.get("param"))))

    ep_data = {a.key: (a.data or {}) for a in endpoints}
    parents = {a.id: a.key for a in endpoints}

    gaps_params: list[dict[str, Any]] = []
    tested = 0
    for a in params:
        endpoint = parents.get(a.parent_id) or a.key.split("#", 1)[0]
        view = _param_view(a, endpoint)
        name, loc = view["name"], view["location"]
        if (ep_data.get(endpoint) or {}).get("login_form"):
            continue                    # the authentication surface, not a param gap
        applicable = [t for t in PARAM_CHECKS if t in selected]
        if _is_redirect_param(name) and "redirect.open" in selected:
            applicable.append("redirect.open")
        if not applicable:
            continue
        missing = [t for t in applicable
                   if (t, endpoint, loc, name) not in param_done]
        if missing:
            if len(gaps_params) < 12:
                gaps_params.append({"endpoint": endpoint, "name": name,
                                    "location": loc, "missing": missing})
        else:
            tested += 1

    gaps_endpoints: list[dict[str, Any]] = []
    for a in endpoints:
        d = a.data or {}
        missing = []
        if ("info.errors" in selected and d.get("error_signature")
                and ("info.errors", a.key) not in url_done):
            missing.append("info.errors")
        if (allow_auth and "auth.default_creds" in selected and d.get("login_form")
                and ("auth.default_creds", a.key) not in url_done):
            missing.append("auth.default_creds")
        if (allow_auth and "authz.object" in selected and has_identities
                and looks_like_object(a.key)
                and ("authz.object", a.key) not in url_done):
            missing.append("authz.object")
        if missing and len(gaps_endpoints) < 8:
            gaps_endpoints.append({"url": a.key, "missing": missing})

    gaps_services: list[dict[str, Any]] = []
    for a in services:
        root = a.key.rstrip("/") + "/"     # the URL the service checks act on
        missing = [t for t in SERVICE_ROOT_CHECKS if t in selected
                   and (t, root) not in url_done and (t, a.key) not in url_done]
        entry: dict[str, Any] = {"url": root}
        # A CORS policy matters where credentialed API responses are served: a
        # service with an API is only covered by a CORS check ON an API endpoint
        # (the HTML page often sends no CORS headers at all).
        api_eps = [e.key for e in endpoints if e.key.startswith(root)
                   and _endpoint_view(e)["api"] and e.key.rstrip("/") != root.rstrip("/")]
        if "cors.policy" in selected and api_eps and not any(
                ("cors.policy", u) in url_done for u in api_eps):
            if "cors.policy" not in missing:
                missing.append("cors.policy")
            entry["cors_on"] = api_eps[0]
        if missing and len(gaps_services) < 4:
            gaps_services.append({**entry, "missing": missing})

    return {"parameters": gaps_params, "endpoints": gaps_endpoints,
            "services": gaps_services, "note": GAPS_NOTE}, tested


async def build(session: AsyncSession, run_id: uuid.UUID,
                inputs: KnowledgeInputs | None = None, *,
                budget: int = BYTE_BUDGET) -> dict[str, Any]:
    """One knowledge snapshot for the run. Read-only, redacted, capped."""
    inp = inputs or KnowledgeInputs()
    run = await session.get(GreyboxRun, run_id)
    if run is None:
        return {}
    target = await session.get(GreyboxTarget, run.target_id)
    scope = ScopePolicy.from_dict(run.scope)

    assets = (await session.scalars(
        select(GreyboxAsset).where(GreyboxAsset.run_id == run_id)
        .order_by(GreyboxAsset.kind, GreyboxAsset.key))).all()
    parents = {a.id: a.key for a in assets}
    all_endpoints = [a for a in assets if a.kind == "endpoint" and a.in_scope]
    static_urls = [a.key for a in all_endpoints if _static(a)]
    endpoints = [a for a in all_endpoints if not _static(a)]
    params = [a for a in assets if a.kind == "parameter" and a.in_scope]
    services = [a for a in assets if a.kind == "service" and a.in_scope]

    observations = (await session.scalars(
        select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run_id,
            GreyboxGraphNode.kind == "observation",
            ~GreyboxGraphNode.key.startswith("skill."))
        .order_by(GreyboxGraphNode.created_at.desc())
        .limit(CAP_OBSERVATIONS))).all()
    leads = (await session.scalars(
        select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run_id, GreyboxGraphNode.kind == "lead")
        .order_by(GreyboxGraphNode.created_at.desc()))).all()
    findings = (await session.scalars(
        select(GreyboxFinding).where(GreyboxFinding.run_id == run_id)
        .order_by(GreyboxFinding.created_at.desc())
        .limit(CAP_FINDINGS))).all()
    operation_nodes = (await session.scalars(
        select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run_id,
            GreyboxGraphNode.kind == "observation",
            GreyboxGraphNode.key.startswith("api.operation|"))
        .order_by(GreyboxGraphNode.key))).all()
    invocation_nodes = (await session.scalars(
        select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run_id,
            GreyboxGraphNode.kind == "observation",
            GreyboxGraphNode.key.startswith("api.invocation|"))
        .order_by(GreyboxGraphNode.created_at.desc()))).all()
    work = (await session.scalars(
        select(GreyboxWorkOrder).where(GreyboxWorkOrder.run_id == run_id)
        .order_by(GreyboxWorkOrder.created_at.desc()))).all()

    open_leads, settled_leads = [], []
    for n in leads:
        view = {"label": _clip(n.label, 120),
                "hypothesis": _clip((n.data or {}).get("hypothesis"), 300),
                "type": (n.data or {}).get("type") or "lead"}
        if n.status in ("open", "investigating"):
            if len(open_leads) < CAP_OPEN_LEADS:
                open_leads.append(view)
        elif len(settled_leads) < CAP_SETTLED_LEADS:
            settled_leads.append({**view, "status": n.status,
                                  "outcome": n.outcome})

    pending = [{"tool": w.tool, "title": _clip(w.title, 100), "url": _target(w)}
               for w in sorted(work, key=lambda w: (w.priority, w.created_at))
               if w.status == "pending"][:CAP_WORK_PENDING]
    running = [{"tool": w.tool, "title": _clip(w.title, 100), "url": _target(w)}
               for w in work if w.status == "running"][:CAP_WORK_RUNNING]
    # Everything already asked of the target (tool + url + outcome), compact: the
    # model must not repeat itself, and the recent list is too short to show that.
    history = [f"{w.tool} {_target(w)} [{w.status}]".replace("  ", " ")
               for w in sorted(work, key=lambda w: w.created_at)
               if w.status in ("done", "failed", "skipped")][-CAP_WORK_HISTORY:]
    recent_work = [{"tool": w.tool, "status": w.status, "url": _target(w),
                    "summary": _clip(w.result_summary or w.error, 140)}
                   for w in sorted((w for w in work
                                    if w.status in ("done", "failed", "skipped")),
                                   key=lambda w: (w.finished_at is None,
                                                  w.finished_at), reverse=True)
                   [:CAP_WORK_RECENT]]

    # The agent must be able to READ what its last actions produced — not a
    # 140-character line — to interpret evidence and to fix a generated tool that
    # failed (its error text is the only way to iterate). Bounded: the last
    # CAP_RESULTS finished work orders, with the observations they recorded.
    finished = sorted((w for w in work if w.status in ("done", "failed")),
                      key=lambda w: (w.finished_at is None, w.finished_at),
                      reverse=True)[:CAP_RESULTS]
    wo_obs: dict[Any, list] = {}
    if finished:
        rows = (await session.scalars(
            select(GreyboxGraphNode).where(
                GreyboxGraphNode.run_id == run_id,
                GreyboxGraphNode.kind == "observation",
                GreyboxGraphNode.work_order_id.in_([w.id for w in finished])))).all()
        for n in rows:
            wo_obs.setdefault(n.work_order_id, []).append(n)
    results = []
    for w in finished:
        obs = wo_obs.get(w.id, [])[:CAP_RESULT_OBS]
        results.append({
            "tool": w.tool, "status": w.status, "target": _target(w),
            "summary": _clip(w.result_summary, 500),
            **({"error": _clip(w.error, 900)} if w.error else {}),
            **({"observations": [{"key": _clip(n.key, 80),
                                  "label": _clip(n.label, 160),
                                  "facts": _cap_facts((n.data or {}).get("facts"))}
                                 for n in obs]} if obs else {}),
        })

    from src.greybox_web.tools.routes import examined_surface
    surf = examined_surface(all_endpoints)
    tcov = surf["template_coverage"]
    from src.greybox_web import modes as _modes
    from src.greybox_web import progress as _progress
    from src.greybox_web import skillbook
    skills_view: dict[str, Any] = {}
    if skillbook.enabled():
        facts = await skillbook.run_facts(session, run_id, scope,
                                          identities=1 + len(inp.sessions or []))
        loaded = skillbook.state_from(facts)
        usable = [x.name for x in skillbook.available(
            scope.mode, _modes.for_scope(scope).allowed)]
        skills_view = {
            "loaded": [{"name": x["name"], "current_phase": x["phase"],
                        "phases": x["phases"],
                        "criteria": [{k: v for k, v in c.items() if k != "text"}
                                     | {"text": _clip(c["text"], 90)}
                                     for c in x["criteria"]]} for x in loaded],
            "not_loaded": [n for n in usable if n not in facts.loaded],
            "parts_read": skillbook.recent_parts(facts),
        }
    progress_view = _progress.summary(await _progress.ledger(session, run_id))
    # Security relationship model (secmodel_store.view): who the identities are,
    # which interfaces each one was granted/refused, what the agent declared
    # (entities, relations, expectations) and the correlation signals. Derived
    # from the recorded exchanges on every snapshot: it cannot go stale.
    from src.greybox_web import secmodel_store
    model_view = await secmodel_store.view(session, run_id)
    security_model = {
        "identities": model_view["identities"],
        "interfaces": model_view["interfaces"][:25],
        "entities": [{"key": e["key"], **({"attributes": e["attributes"]}
                                          if e["attributes"] else {})}
                     for e in model_view["entities"][:30]],
        "relations": [f"{r['src']} {r['rel']} {r['dst']} ({r['basis']})"
                      for r in model_view["relations"][:30]],
        "expectations": [{k: v for k, v in e.items()
                          if k in ("subject", "operation", "resource", "expected",
                                   "basis", "evidence")}
                         for e in model_view["expectations"][:20]],
        "signals": model_view["signals"][:8],
        "unresolved": model_view["unresolved"][:10],
        "counts": model_view["counts"],
    }

    delta = [{"kind": d.get("kind"), "summary": _clip(d.get("summary"), 140)}
             for d in (inp.delta or [])[:CAP_DELTA]]

    # The tools the model may propose: registered, run-selected (checks), passive
    # follow-ups; active probes only when the target opted in (admission enforces
    # this anyway — the list is honest, not a gate).
    registered = set(_registered_ids())
    selected = set(run.checks or [])
    from src.greybox_web import modes
    caps = modes.for_scope(scope)
    unusable = _unusable_capabilities()
    available = sorted(
        tid for tid in registered
        if not tid.startswith("verify.")
        and (tool_registry.get(tid).kind != "check" or tid in selected)
        and (tid not in _active_probe_ids() or tid in scope.active_probes)
        and caps.allows(modes.effective(tool_registry.get(tid).capability))
        and modes.effective(tool_registry.get(tid).capability) not in unusable)
    # Run-defined instruments (batch E) exist from their admission on: they join
    # the honest tool list, and their id/title/param keys get their own section —
    # the spec itself never reaches the model (it holds validated literals only,
    # but the executor owns it; every use is a proposal through the same admission).
    dyn_tools = [d for d in (inp.dynamic_tools or [])
                 if isinstance(d, dict) and d.get("id")][:20]
    available = sorted(set(available) | {str(d["id"]) for d in dyn_tools})

    pages_fetched = int(inp.coverage.get("pages_fetched") or 0)
    max_pages = int(inp.coverage.get("max_pages") or
                    (run.limits or {}).get("max_pages", 200))

    # The coverage ledger: computed from the work orders and the
    # assets themselves, never from the capped history strings.
    gaps, params_tested = _gaps(selected, scope.allow_auth_testing,
                                bool(inp.sessions), work,
                                endpoints, params, services)
    # A defined instrument with no completed use yet is unexamined surface, not
    # noise: an unused dynamic tool is a coverage gap (batch E). Only a ``done``
    # use counts — a failed or skipped one stays a gap.
    dyn_done = {w.tool for w in work if w.status == "done"}
    gaps["dynamic"] = [
        {"id": str(d["id"]), "title": _clip(d.get("title"), 120),
         "param_keys": [str(x) for x in (d.get("param_keys") or [])][:10]}
        for d in dyn_tools if str(d["id"]) not in dyn_done][:8]
    checks_pending = sum(1 for w in work
                         if w.status == "pending" and w.tool in selected)

    from src.greybox_web import correlation
    canonical_issue_views = await correlation.candidate_issue_summaries(session, run_id)
    from src.greybox_web.investigation import (discover_operations, investigation_from_lead,
                                               investigations_from_operations)
    discovered_operations = discover_operations(
        [({**(endpoint.data or {}), "url": endpoint.key}) for endpoint in endpoints]
        + [node.data.get("facts", {}) for node in operation_nodes],
        model_view["interfaces"])
    discovered_operations.sort(key=lambda operation: (not bool(operation.permissions),
                                                      not bool(operation.state_effects),
                                                      operation.id))
    operation_views = [operation.as_dict() for operation in discovered_operations][:CAP_OPERATIONS]
    operations_by_id = {operation.id: operation for operation in discovered_operations}
    configured_identities = [item.get("label") for item in inp.sessions if item.get("label")]
    calls_left = inp.agent.get("calls_left")
    model_budget_exhausted = ((isinstance(calls_left, int) and calls_left <= 0)
                              or run.end_reason in ("budget_time", "budget_requests",
                                                    "budget_model_calls", "budget_tokens"))
    structured_leads = [lead for lead in leads
                        if isinstance((lead.data or {}).get("signals"), dict)
                        and isinstance((lead.data or {})["signals"].get("investigation"), dict)]
    investigation_views = [investigation_from_lead(
        lead.key, lead.status, lead.outcome, lead.data or {},
        available_tools=(w.tool for w in work if w.parent_node_id == lead.id),
        configured_identities=configured_identities,
        operation_record=operations_by_id.get(
            ((lead.data or {}).get("signals") or {}).get("investigation", {}).get("operation_id")
            or (((lead.data or {}).get("signals") or {}).get("investigation", {}).get("operation") or {}).get("id")),
        execution_capabilities=available,
        work_orders=({"tool": w.tool, "status": w.status}
                     for w in work if w.parent_node_id == lead.id),
        budget_exhausted=model_budget_exhausted).as_dict() for lead in structured_leads]
    explicit_operation_ids = {item.get("operation_id") for item in investigation_views}
    investigation_views.extend(investigation.as_dict() for investigation in
        investigations_from_operations(
            (operation for operation in discovered_operations
             if operation.id not in explicit_operation_ids),
            available_identities=(item.get("label") for item in inp.sessions),
            execution_capabilities=available,
            budget_exhausted=model_budget_exhausted))
    investigation_views = [_attribute_operation_invocations(item, invocation_nodes)
                            for item in investigation_views]
    investigation_views.sort(key=lambda item: (
        {"in_progress": 0, "verification_pending": 1, "awaiting_evidence": 2,
         "ready": 3, "hypothesis_established": 4, "not_attempted": 5}.get(
             item.get("progress_state"), 6),
        not bool((item.get("planned_verification") or {}).get("operation", {}).get("state_effects")),
        len(item.get("missing_prerequisites") or []), item["remaining_steps"], item["key"]))
    investigation_counts = {state: sum(1 for item in investigation_views
                                        if item.get("progress_state") == state)
                            for state in ("discovered", "hypothesis_established", "ready",
                                          "in_progress", "awaiting_evidence",
                                          "verification_pending", "confirmed", "rejected",
                                          "inconclusive", "blocked", "not_attempted",
                                          "budget_exhausted")}

    k: dict[str, Any] = {
        "run": {
            "base_url": run.base_url,
            "objective": _clip((target.description if target else None)
                               or f"Assess {run.base_url} within the authorised scope",
                               600),
            "scope": _clip("; ".join(scope.summary()[:6]), 300),
            # What kind of target this is and what the run may do with it: the
            # agent chooses capabilities from this, never assumes HTTP/browser.
            "mode": scope.mode,
            "mode_description": modes.describe(scope.mode),
            "capabilities": caps.as_list(),
            **({"network": {"targets": list(scope.network.targets)[:32],
                            "ports": list(scope.network.ports)[:64],
                            "protocols": list(scope.network.protocols)}}
               if scope.network else {}),
            "state_changing_allowed": scope.state_changing,
            "resource_lifecycle": scope.resource_lifecycle,
            "allow_auth_testing": bool((run.scope or {}).get("allow_auth_testing")),
            "credentials_available": run.credential_id is not None or bool(run.account_ids),
            "accounts": inp.accounts,       # {label, user} — never secrets
            "sessions": inp.sessions,       # {label, cookies: names} — live identities
        },
        "budget": {
            "requests_used": int(inp.budget.get("requests_used") or 0),
            "requests_max": int(inp.budget.get("requests_max") or 0),
            "duration_s": int(inp.budget.get("duration_s") or 0),
            "duration_max_s": int((run.limits or {}).get("max_duration_s", 900)),
        },
        "agent": dict(inp.agent or {}),
        "coverage": {
            "pages_fetched": pages_fetched,
            "max_pages": max_pages,
            "endpoints_discovered": len(all_endpoints),
            # the verdict's own definition (routes.examined_surface): the agent
            # sees exactly which API endpoints the coverage check counts as open
            "endpoints_examined": surf["tested"],
            "api_endpoints": surf["api"],
            "api_untested": surf["api_untested"][:15],
            "parameters": len(params),
            "parameters_tested": params_tested,
            "checks_pending": checks_pending,
            "frontier": len(inp.frontier or []),
        },
        "frontier": frontier_view(inp.frontier),
        "assets": {
            "services": [{"url": s.key} for s in services[:10]],
            "endpoints": [_template_view(_endpoint_view(e), tcov)
                          for e in endpoints[:CAP_ENDPOINTS]],
            "static": summarise_static(static_urls),
            "parameters": [_param_view(p, parents.get(p.parent_id))
                           for p in params[:CAP_PARAMS]],
        },
        "observations": [{"key": _clip(n.key, 80), "label": _clip(n.label, 120),
                          "facts": (n.data or {}).get("facts") or {}}
                         for n in observations],
        "hypotheses": {"open": open_leads, "settled": settled_leads},
        "operations": operation_views,
        "investigations": {"active": investigation_views[:CAP_INVESTIGATIONS],
                           "counts": investigation_counts},
        "canonical_issues": canonical_issue_views[:12],
        "findings": [{"id": str(f.id), "canonical_issue_id": str(f.canonical_issue_id) if f.canonical_issue_id else None,
                      "check": f.check_id, "title": _clip(f.title, 120),
                      "severity": f.severity, "status": f.status, "class": f.finding_class,
                      "url": _clip((f.location or {}).get("url"), 200),
                      "evidence_refs": [f"exchange:{item['exchange_id']}" for item in (f.evidence or []) if item.get("exchange_id")][:8] or [f"finding:{f.id}"]}
                     for f in findings],
        "work": {"pending": pending, "running": running, "recent": recent_work,
                 "history": history},
        "results": results,
        # Methodology (skillbook.py): loaded skills with their phase gates and
        # definition-of-done criteria (engine-evaluated against this run's
        # evidence), and the skills not loaded yet. The playbooks themselves are
        # shown in a TRUSTED prompt section, not in this untrusted block.
        "skills": skills_view,
        "security_model": security_model,
        # Anti-loop (progress.py): what recent actions actually taught the run.
        "progress": progress_view,
        "gaps": gaps,
        # Operator messages (hints) are NOT part of this untrusted, target-derived
        # block: the explorer renders them in a separate trusted section
        # (``exploration/messages.py``).
        "todolist": list(inp.todolist or []),
        "tools": available,
        "dynamic_tools": dyn_tools,
        "delta": delta,
    }
    return redaction.structured(_fit(k, budget))


def _template_view(view: dict[str, Any], tcov: dict[str, dict]) -> dict[str, Any]:
    """A templated endpoint (`/api/notes/{id}` from code) is examined through its
    concrete instances: say so, so the agent tests an instance instead of trying to
    "test" the placeholder."""
    c = tcov.get(view["url"])
    if c is None:
        return view
    return {**view, "template": True, "instances": c["instances"],
            "instances_tested": c["tested"], "tested": c["tested"] > 0}


def _attribute_operation_invocations(investigation: dict[str, Any],
                                     invocations: list[GreyboxGraphNode]) -> dict[str, Any]:
    """Advance from exact persisted execution evidence, without judging impact."""
    operation_ref = investigation.get("operation_id")
    relevant = []
    for node in invocations:
        facts = (node.data or {}).get("facts") or {}
        direct_ref = str(facts.get("investigation_ref") or "")
        if (facts.get("operation_ref") != operation_ref
                or (direct_ref and direct_ref != investigation.get("key"))
                or not isinstance(facts.get("status"), int)
                or not facts.get("identity")):
            continue
        relevant.append({
            "evidence": node.key,
            "identity": str(facts["identity"])[:160],
            "status": facts["status"],
            "ok": bool(facts.get("ok")),
            "state_changing": bool(facts.get("state_changing")),
            **({"expected_effect": str(facts["expected_effect"])[:300]}
               if facts.get("expected_effect") else {}),
        })
    if not relevant or investigation.get("progress_state") in {
            "confirmed", "rejected", "inconclusive", "blocked", "budget_exhausted"}:
        return investigation

    progress = dict(investigation.get("progress") or {})
    progress["operation_invocations"] = relevant[:20]
    work = dict(progress.get("work_orders") or {})
    work["done"] = max(int(work.get("done") or 0), len(relevant))
    progress["work_orders"] = work
    planned_steps = list((investigation.get("planned_verification") or {}).get("steps") or [])
    completed = list(progress.get("completed_steps") or [])
    if any(item["state_changing"] for item in relevant):
        for step in planned_steps[:2]:
            if step not in completed:
                completed.append(step)
        progress["state"] = "verification_pending"
    else:
        progress["state"] = "awaiting_evidence"
        if len({item["identity"] for item in relevant}) >= 2 and planned_steps:
            completed.append(planned_steps[0])
            progress["state"] = "verification_pending"
    progress["completed_steps"] = completed
    evidence = list(dict.fromkeys([*(investigation.get("evidence") or []),
                                   *(item["evidence"] for item in relevant)]))
    if progress["state"] == "verification_pending":
        next_actions = [{"kind": "independent_verification",
                         "required_evidence": investigation.get("required_observations") or []}]
    else:
        observed_identities = {item["identity"] for item in relevant}
        next_actions = [({**action, "identity_options": [identity for identity in
                         action.get("identity_options") or []
                         if identity not in observed_identities]}
                        if action.get("kind") == "invoke_operation" else action)
                        for action in investigation.get("possible_next_actions") or []]
    return {**investigation, "progress": progress, "current_progress": progress,
            "status": progress["state"], "progress_state": progress["state"],
            "remaining_steps": max(0, len(planned_steps) - len(completed)),
            "evidence": evidence, "possible_next_actions": next_actions}


def _cap_facts(facts: Any) -> Any:
    """Observation facts for the results section: kept whole when small, else a
    JSON prefix (the agent sees the shape and the start, never megabytes)."""
    if not facts:
        return {}
    text = json.dumps(facts, default=str)
    if len(text) <= CAP_FACT_CHARS:
        return facts
    return {"_truncated": True, "json_prefix": text[:CAP_FACT_CHARS]}


def _unusable_capabilities() -> set[str]:
    """Capabilities the policy allows but this worker cannot provide (an honest tool
    list: the browser is not offered when Playwright is not installed)."""
    from src.greybox_web import modes
    from src.greybox_web.tools import browser
    return set() if browser.available() else {modes.BROWSER}


def _registered_ids() -> list[str]:
    """Registered tool ids without instantiating anything heavy."""
    from src.greybox_web.tools import _registry          # same package
    return list(_registry().keys())


def _active_probe_ids() -> set[str]:
    from src.greybox_web.scope import ACTIVE_PROBE_TOOLS
    return set(ACTIVE_PROBE_TOOLS)


def size(k: dict[str, Any]) -> int:
    return len(json.dumps(k, default=str, separators=(",", ":")).encode())


def _cut(path: tuple[str, ...], n: int):
    def fn(k: dict[str, Any]) -> None:
        d: Any = k
        for p in path[:-1]:
            d = d.get(p) if isinstance(d, dict) else None
            if d is None:
                return
        leaf = path[-1]
        if isinstance(d, dict) and isinstance(d.get(leaf), list):
            d[leaf] = d[leaf][-n:] if leaf == "history" else d[leaf][:n]
    return fn


# Trimming stages, least valuable first; applied one by one until the snapshot fits.
_STAGES = (
    _cut(("delta",), 8), _cut(("observations",), 10),
    _cut(("assets", "parameters"), 20), _cut(("hypotheses", "settled"), 5),
    _cut(("work", "recent"), 8), _cut(("work", "history"), 50),
    _cut(("assets", "endpoints"), 30), _cut(("gaps", "parameters"), 6),
    _cut(("gaps", "endpoints"), 4), _cut(("observations",), 5),
    _cut(("work", "pending"), 10), _cut(("work", "history"), 20),
    _cut(("assets", "endpoints"), 15), _cut(("assets", "parameters"), 8),
    _cut(("frontier",), 8), _cut(("work", "recent"), 3), _cut(("results",), 3),
    _cut(("hypotheses", "open"), 8), _cut(("findings",), 12),
    _cut(("delta",), 3), _cut(("work", "history"), 8), _cut(("observations",), 0),
    _cut(("assets", "endpoints"), 8), _cut(("findings",), 6), _cut(("results",), 1),
    _cut(("progress", "unproductive"), 2), _cut(("progress", "failing"), 2),
    _cut(("operations",), 10), _cut(("investigations", "active"), 10),
    _cut(("operations",), 5),
    _cut(("security_model", "interfaces"), 12), _cut(("security_model", "relations"), 12),
    _cut(("security_model", "entities"), 12), _cut(("security_model", "unresolved"), 5),
)


def _fit(k: dict[str, Any], budget: int = BYTE_BUDGET) -> dict[str, Any]:
    """Stay inside the byte budget by trimming the most volatile sections first."""
    for stage in _STAGES:
        if size(k) <= budget:
            return k
        stage(k)
    return k


def compact(k: dict[str, Any], budget: int = COMPACT_BYTE_BUDGET) -> dict[str, Any]:
    """A much smaller copy of a snapshot (the retry after a truncated reply)."""
    import copy
    return _fit(copy.deepcopy(k), budget)


def fingerprint(k: dict[str, Any], message_ids: Any = ()) -> str:
    """A quiet-mode fingerprint over everything the model could react to: unchanged
    knowledge (while work is in flight, or at an idle moment) means a call would see
    exactly what the last call saw. ``message_ids`` are the operator messages (hint
    ids) the call would carry: keyed by id, so a new message always changes it."""
    work = k.get("work") or {}
    cov = k.get("coverage") or {}
    canon = {
        "endpoints": sorted(f"{e['url']}:{e['tested']}" for e in
                            (k.get("assets") or {}).get("endpoints") or []),
        "open_leads": sorted(h.get("label") for h in
                             (k.get("hypotheses") or {}).get("open") or []),
        "investigations": sorted(f"{i.get('key')}:{i.get('status')}:{i.get('remaining_steps')}"
                                 for i in (k.get("investigations") or {}).get("active") or []),
        "findings": sorted(f"{f.get('check')}:{f.get('status')}" for f in
                           k.get("findings") or []),
        "frontier": sorted(k.get("frontier") or []),
        "pending": sorted(f"{w.get('tool')}:{w.get('title')}" for w in
                          work.get("pending") or []),
        "running": sorted(w.get("tool") for w in work.get("running") or []),
        "recent": sorted(f"{w.get('tool')}:{w.get('status')}"
                         f":{str(w.get('summary'))[:60]}" for w in
                         work.get("recent") or []),
        "coverage": {n: cov.get(n) for n in ("pages_fetched", "endpoints_examined")},
        # the coverage ledger: a newly fillable gap must wake the quiet-mode check
        # (dynamic instruments included: a defined-but-unused tool, or its first
        # completed use, changes what the next call would see)
        "gaps": sorted(
            f"{g.get('endpoint') or g.get('url')}|{g.get('name') or ''}|{t}"
            for section in ("parameters", "endpoints", "services")
            for g in (k.get("gaps") or {}).get(section) or []
            for t in g.get("missing") or [])[:40],
        "dynamic_unused": sorted(str(g.get("id")) for g in
                                  (k.get("gaps") or {}).get("dynamic") or []),
        "dynamic_tools": sorted(str(d.get("id")) for d in
                                 k.get("dynamic_tools") or []),
        "messages": sorted(str(i) for i in message_ids or ()),
        # admission refusals the model has not seen yet: it must be able to react
        "refused": sum(1 for d in k.get("delta") or []
                       if str(d.get("summary") or "").startswith("rejected:")),
        # The todolist is the MODEL's own state (it wrote the latest one), not new
        # external knowledge: excluded so a repeat wake with nothing else changed is
        # correctly quiet rather than a redundant call.
    }
    return hashlib.sha256(json.dumps(canon, sort_keys=True, default=str)
                          .encode()).hexdigest()
