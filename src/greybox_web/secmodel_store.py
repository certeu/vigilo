"""Persistence and queries for the security relationship model (``secmodel``).

Nothing new is stored on the side:

* **entities** the agent declares are assets (kinds = ``secmodel.ENTITY_KINDS``,
  key ``<kind>:<name>``) and **relations** are asset edges, in the run's existing
  asset graph; each relation's basis and evidence are kept in the source asset's
  ``data.relations``;
* **expectations** are observation nodes (``model.expect|…``), like skill claims,
  so they survive a resumed run;
* **observations** are never copied: they are derived on demand from the recorded
  exchanges, whose ids are the evidence references.

Evidence references are resolved, not trusted: ``exchange:<id>`` must be an
exchange of this run; any other reference must name an observation key, an asset
key, a finding title or a work-order target of the run. An expectation that
claims a documented/observed basis with no resolvable evidence is stored with
basis ``stated`` — an assumption, shown as such.
"""
from __future__ import annotations

import json
import uuid
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import secmodel as sm
from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxAssetEdge,
    GreyboxFinding,
    GreyboxGraphNode,
    GreyboxHttpExchange,
)

EXPECT_PREFIX = "model.expect|"
CAP_EXCHANGES = 6000
CAP_BODIES = 400
CAP_BODY_CHARS = 200_000
CAP_VIEW_INTERFACES = 40
CAP_VIEW_SIGNALS = 12
NON_COMPARABLE = {"browser-session"}


# ------------------------------------------------------------------ evidence


async def resolve_evidence(session: AsyncSession, run_id: uuid.UUID,
                           refs: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """(resolved, unresolved) references for this run."""
    if not refs:
        return [], []
    ok, bad = [], []
    xids = {r: r.split(":", 1)[1] for r in refs if r.startswith("exchange:")}
    found: set[int] = set()
    nums = [int(v) for v in xids.values() if v.isdigit()]
    if nums:
        found = set((await session.scalars(select(GreyboxHttpExchange.id).where(
            GreyboxHttpExchange.run_id == run_id,
            GreyboxHttpExchange.id.in_(nums)))).all())
    others = [r for r in refs if r not in xids]
    corpus: list[str] = []
    if others:
        corpus += list((await session.scalars(select(GreyboxGraphNode.key).where(
            GreyboxGraphNode.run_id == run_id))).all())
        corpus += list((await session.scalars(select(GreyboxAsset.key).where(
            GreyboxAsset.run_id == run_id))).all())
        corpus += list((await session.scalars(select(GreyboxFinding.title).where(
            GreyboxFinding.run_id == run_id))).all())
        # a URL or path cited as evidence: a request the run actually recorded
        corpus += list((await session.scalars(
            select(GreyboxHttpExchange.url).where(
                GreyboxHttpExchange.run_id == run_id,
                GreyboxHttpExchange.status_code.is_not(None))
            .distinct().limit(CAP_EXCHANGES))).all())
    for r in refs:
        if r in xids:
            (ok if xids[r].isdigit() and int(xids[r]) in found else bad).append(r)
        elif len(r) >= 6 and any(c == r or r in c for c in corpus):
            ok.append(r)
        else:
            bad.append(r)
    return ok, bad


# ------------------------------------------------------------------ writes


async def apply(session: AsyncSession, gtx, decl: sm.Declarations) -> dict[str, Any]:
    """Store one reply's validated declarations. Returns counts and notes."""
    notes = list(decl.notes)
    assets: dict[str, GreyboxAsset] = {}

    async def entity(ref: sm.EntityRef, attrs: dict | None = None) -> GreyboxAsset:
        if ref.key in assets and not attrs:
            return assets[ref.key]
        a = await gtx.asset(ref.kind, ref.key, f"{ref.kind} {ref.name}", in_scope=True,
                            data={"model": True, "name": ref.name,
                                  **({"attributes": attrs} if attrs else {})})
        assets[ref.key] = a
        return a

    for ref, attrs in decl.entities:
        await entity(ref, attrs)
    for rel in decl.relations:
        src, dst = await entity(rel.src), await entity(rel.dst)
        ok, bad = await resolve_evidence(session, gtx.run_id, rel.evidence)
        basis = rel.basis if ok or rel.basis == "stated" else "stated"
        if basis != rel.basis:
            notes.append(f"{rel.src.key} {rel.rel} {rel.dst.key}: no resolvable "
                         f"evidence, kept as an assumption (stated)")
        await gtx.asset_edge(src, dst, rel.rel)
        await gtx.asset(src.kind, src.key, src.label, in_scope=True, data={
            "relations": [{"rel": rel.rel, "dst": rel.dst.key, "basis": basis,
                           "evidence": ok[:4], "unresolved": bad[:4]}]})
    for e in decl.expectations:
        ok, bad = await resolve_evidence(session, gtx.run_id, e.evidence)
        basis = e.basis if ok or e.basis == "stated" else "stated"
        if basis != e.basis:
            notes.append(f"expectation {e.subject.key} {e.operation} {e.resource.key}:"
                         f" no resolvable evidence for basis {e.basis!r}, kept as "
                         "stated")
        await entity(e.subject)
        await entity(e.resource)
        key = f"{EXPECT_PREFIX}{e.subject.key}|{e.operation}|{e.resource.key}"[:300]
        facts = {"subject": e.subject.key, "operation": e.operation,
                 "resource": e.resource.key, "expected": e.expected,
                 "basis": basis, "claimed_basis": e.basis, "evidence": ok[:6],
                 "unresolved": bad[:6], "note": e.note}
        node = await gtx.get_node("observation", key)
        if node is None:
            await gtx.node("observation", key,
                           f"expected {e.expected}: {e.subject.name} {e.operation} "
                           f"{e.resource.name} ({basis})", "recorded",
                           data={"facts": facts})
        else:
            node.data = {**(node.data or {}), "facts": facts}
    return {"entities": len(decl.entities), "relations": len(decl.relations),
            "expectations": len(decl.expectations), "notes": notes[:12]}


# ------------------------------------------------------------------ reads


async def declared(session: AsyncSession, run_id: uuid.UUID) -> dict[str, Any]:
    """Entities, relations and expectations declared so far."""
    rows = (await session.scalars(select(GreyboxAsset).where(
        GreyboxAsset.run_id == run_id,
        GreyboxAsset.kind.in_(sm.ENTITY_KINDS)))).all()
    by_id = {a.id: a for a in rows}
    edges = (await session.scalars(select(GreyboxAssetEdge).where(
        GreyboxAssetEdge.run_id == run_id,
        GreyboxAssetEdge.src_id.in_(list(by_id) or [uuid.uuid4()])))).all() \
        if by_id else []
    rels = []
    for e in edges:
        s, d = by_id.get(e.src_id), by_id.get(e.dst_id)
        if s is None or d is None:
            continue
        meta = next((r for r in (s.data or {}).get("relations") or []
                     if r.get("rel") == e.rel and r.get("dst") == d.key), {})
        rels.append({"src": s.key, "rel": e.rel, "dst": d.key,
                     "basis": meta.get("basis", "stated"),
                     "evidence": meta.get("evidence") or []})
    exp_nodes = (await session.scalars(select(GreyboxGraphNode).where(
        GreyboxGraphNode.run_id == run_id, GreyboxGraphNode.kind == "observation",
        GreyboxGraphNode.key.startswith(EXPECT_PREFIX)))).all()
    return {
        "entities": [{"key": a.key, "kind": a.kind,
                      "name": (a.data or {}).get("name") or a.key.split(":", 1)[-1],
                      "attributes": (a.data or {}).get("attributes") or {}}
                     for a in sorted(rows, key=lambda a: a.key)],
        "relations": rels,
        "expectations": [(n.data or {}).get("facts") or {} for n in exp_nodes],
    }


def expectations_from(rows: list[dict]) -> list[sm.Expectation]:
    out = []
    for f in rows:
        try:
            sk, sn = str(f["subject"]).split(":", 1)
            rk, rn = str(f["resource"]).split(":", 1)
            out.append(sm.Expectation(sm.EntityRef(sk, sn), f["operation"],
                                      sm.EntityRef(rk, rn), f["expected"],
                                      f.get("basis") or "stated",
                                      tuple(f.get("evidence") or ())))
        except (KeyError, ValueError, sm.ModelError):
            continue
    return out


async def observations(session: AsyncSession, run_id: uuid.UUID,
                       identities: set[str]) -> list[sm.Observation]:
    """Access observations derived from the run's attributed exchanges."""
    rows = (await session.execute(
        select(GreyboxHttpExchange.id, GreyboxHttpExchange.url,
               GreyboxHttpExchange.method, GreyboxHttpExchange.status_code,
               GreyboxHttpExchange.error, GreyboxHttpExchange.identity,
               GreyboxHttpExchange.tool, GreyboxHttpExchange.blocked,
               GreyboxHttpExchange.content_type, GreyboxHttpExchange.request_body)
        .where(GreyboxHttpExchange.run_id == run_id,
               GreyboxHttpExchange.identity.is_not(None),
               GreyboxHttpExchange.redirect_hop == 0)
        .order_by(GreyboxHttpExchange.id.desc()).limit(CAP_EXCHANGES))).all()
    bodies = (await session.scalars(
        select(GreyboxHttpExchange.response_body)
        .where(GreyboxHttpExchange.run_id == run_id,
               GreyboxHttpExchange.status_code >= 200,
               GreyboxHttpExchange.status_code < 300,
               GreyboxHttpExchange.content_type.like("%json%"))
        .order_by(GreyboxHttpExchange.id.desc()).limit(CAP_BODIES))).all()
    known: set[str] = set()
    for b in bodies:
        known |= sm.ids_in_body((b or "")[:CAP_BODY_CHARS])
    return sm.observe([dict(r._mapping) for r in reversed(rows)], identities, known)


async def identities_seen(session: AsyncSession, run_id: uuid.UUID) -> dict[str, int]:
    from sqlalchemy import func
    rows = (await session.execute(
        select(GreyboxHttpExchange.identity, func.count())
        .where(GreyboxHttpExchange.run_id == run_id,
               GreyboxHttpExchange.identity.is_not(None))
        .group_by(GreyboxHttpExchange.identity))).all()
    return {str(i): int(n) for i, n in rows}


def roles_of(decl: dict[str, Any]) -> dict[str, str]:
    """identity name -> role name, from has_role relations or a role attribute."""
    roles: dict[str, str] = {}
    for e in decl["entities"]:
        if e["kind"] == "identity" and e["attributes"].get("role"):
            roles[e["name"]] = sm.norm(e["attributes"]["role"])
    for r in decl["relations"]:
        if r["rel"] == "has_role":
            roles[r["src"].split(":", 1)[1]] = r["dst"].split(":", 1)[1]
    return roles


async def view(session: AsyncSession, run_id: uuid.UUID) -> dict[str, Any]:
    """The security model as the agent, the coverage verdict and the report see it."""
    seen = await identities_seen(session, run_id)
    comparable = {i for i in seen if i not in NON_COMPARABLE}
    decl = await declared(session, run_id)
    obs = await observations(session, run_id, comparable)
    roles = roles_of(decl)
    signals = sm.correlate(obs, expectations_from(decl["expectations"]), roles)
    matrix = sm.access_matrix(obs)
    reads = {o.interface: o.resource_type for o in obs}
    interfaces = []
    for tpl, per in sorted(matrix.items(), key=lambda kv: -sum(
            sum(c.values()) for c in kv[1].values()))[:CAP_VIEW_INTERFACES]:
        interfaces.append({"interface": tpl, "resource_type": reads.get(tpl),
                           "access": {i: dict(c) for i, c in sorted(per.items())}})
    expected_types = {str(f.get("resource", "")).split(":", 1)[-1]
                      for f in decl["expectations"]}
    unresolved = []
    if len(comparable) >= 2:
        for it in interfaces:
            asked = [i for i in it["access"]]
            if len(asked) < 2:
                unresolved.append({"kind": "single_identity_interface",
                                   "interface": it["interface"],
                                   "detail": f"only {asked[0]} requested it: access "
                                             "for other identities is unknown"})
    for rtype in sorted({o.resource_type for o in obs} - expected_types):
        unresolved.append({"kind": "no_expectation", "resource_type": rtype,
                           "detail": "intended access for this resource type has not "
                                     "been established (observations alone prove "
                                     "nothing)"})
    return {
        "identities": [{"identity": i, "requests": n, "role": roles.get(i)}
                       for i, n in sorted(seen.items())],
        "entities": decl["entities"][:60],
        "relations": decl["relations"][:60],
        "expectations": decl["expectations"][:40],
        "interfaces": interfaces,
        "signals": [s.as_dict() for s in signals[:CAP_VIEW_SIGNALS]],
        "unresolved": unresolved[:20],
        "counts": {"observations": len(obs), "interfaces": len(matrix),
                   "signals": len(signals), "expectations": len(decl["expectations"]),
                   "entities": len(decl["entities"]),
                   "relations": len(decl["relations"])},
    }


def compact(v: dict[str, Any]) -> str:
    return json.dumps(v, separators=(",", ":"), default=str)


# ------------------------------------------------------------------ verification gate

AUTHORISED, EXPECTED_DENY, UNKNOWN = "authorised", "expected_deny", "unknown"


def _mentions(body: str, instance: str) -> bool:
    """The instance appears as a whole JSON value/token, not a substring."""
    import re
    return bool(re.search(r"(?<![A-Za-z0-9_-])" + re.escape(instance)
                          + r"(?![A-Za-z0-9_-])", body or ""))


async def access_gate(session: AsyncSession, run_id: uuid.UUID, url: str,
                      readers: list[str]) -> tuple[str, list[str]]:
    """Is the observed access consistent with the application's own model?

    For each identity that was served the object at ``url``:

    * an established expectation (identity or its role) ``allow``s reading the
      resource type → authorised;
    * the identity's own LIST of that resource type (a list interface of the type,
      or a parent's sub-collection of it) contains the instance → visible to it by
      design → authorised;
    * an expectation ``deny``s it → expected_deny (the finding stands, with its
      basis);
    * otherwise unknown (the finding stands; intended access not established).

    ``authorised`` only when EVERY reader is authorised: one unexplained reader
    keeps the finding."""
    from src.greybox_web import secmodel as sm
    if not readers:
        return UNKNOWN, []
    decl = await declared(session, run_id)
    roles = roles_of(decl)
    obs_known = await observations(session, run_id, set(readers))
    known = {o.instance for o in obs_known if o.instance}
    iface = sm.interface_of(url, known)
    if iface is None or iface.kind != "detail":
        return UNKNOWN, []
    inst = sm.instance_of(url, iface)
    rtype = iface.resource_type
    exps = expectations_from(decl["expectations"])
    reasons: list[str] = []
    verdicts: list[str] = []
    for who in readers:
        w = who.lower()
        subj = {("identity", w)} | ({("role", roles[w])} if w in roles else set())
        mine = [e for e in exps if (e.subject.kind, e.subject.name) in subj
                and e.operation in ("read", "list")
                and ((e.resource.kind == "resource_type" and e.resource.name == rtype)
                     or (e.resource.kind == "resource"
                         and e.resource.name == (inst or "").lower()))]
        if any(e.expected == "deny" for e in mine):
            e = next(e for e in mine if e.expected == "deny")
            verdicts.append(EXPECTED_DENY)
            reasons.append(f"{who}: expected deny ({e.basis}) on {e.resource.key}")
            continue
        if any(e.expected == "allow" for e in mine):
            e = next(e for e in mine if e.expected == "allow")
            verdicts.append(AUTHORISED)
            reasons.append(f"{who}: expected allow ({e.basis}) on {e.resource.key}")
            continue
        via = _membership(decl["relations"], who, url)
        if via:
            verdicts.append(AUTHORISED)
            reasons.append(f"{who}: {via}")
            continue
        listed = await _listed_to(session, run_id, who, rtype, inst, url)
        if listed:
            verdicts.append(AUTHORISED)
            reasons.append(f"{who}: the application lists {rtype} {inst} to this "
                           f"identity ({listed})")
        else:
            verdicts.append(UNKNOWN)
            reasons.append(f"{who}: intended access to {rtype} {inst} not established")
    if EXPECTED_DENY in verdicts:
        return EXPECTED_DENY, reasons
    if verdicts and all(v == AUTHORISED for v in verdicts):
        return AUTHORISED, reasons
    return UNKNOWN, reasons


ESTABLISHING = ("member_of", "owns")


def _membership(relations: list[dict], who: str, url: str) -> str | None:
    """An established (non-assumed) membership or ownership of the identity in a
    resource the URL is under — the instance itself, an enclosing one in the path,
    or an ancestor through established ``belongs_to`` relations (a document that
    belongs to a project the identity is a member of): reading it is what that
    relationship grants. Ids compare case-insensitively (entity names are
    normalised to lower case)."""
    from urllib.parse import urlsplit
    segs = {x.lower() for x in (urlsplit(url).path or "").split("/") if x}
    parents: dict[str, set[str]] = {}
    for r in relations:
        if r["rel"] == "belongs_to" and r.get("basis") != "stated" \
                and r["src"].startswith("resource:") and r["dst"].startswith("resource:"):
            parents.setdefault(r["src"].split(":", 1)[1], set()).add(
                r["dst"].split(":", 1)[1])
    frontier, seen = set(segs), set()
    while frontier:                           # ancestors through belongs_to
        x = frontier.pop()
        if x in seen:
            continue
        seen.add(x)
        frontier |= parents.get(x, set()) - seen
    segs = seen
    for r in relations:
        if r["rel"] in ESTABLISHING and r["src"] == f"identity:{who.lower()}" \
                and r.get("basis") != "stated" and r["dst"].startswith("resource:"):
            inst = r["dst"].split(":", 1)[1]
            if inst in segs:
                return f"{r['rel'].replace('_', ' ')} {inst} ({r['basis']})"
    return None


async def _listed_to(session: AsyncSession, run_id: uuid.UUID, who: str, rtype: str,
                     inst: str | None, url: str) -> str | None:
    """A list interface of ``rtype`` (or a sub-collection named ``rtype``) that
    returned ``inst`` to ``who``; the URL, or None."""
    from src.greybox_web import secmodel as sm
    if not inst:
        return None
    rows = (await session.execute(
        select(GreyboxHttpExchange.url, GreyboxHttpExchange.response_body,
               GreyboxHttpExchange.content_type)
        .where(GreyboxHttpExchange.run_id == run_id,
               GreyboxHttpExchange.identity == who,
               GreyboxHttpExchange.status_code >= 200,
               GreyboxHttpExchange.status_code < 300,
               GreyboxHttpExchange.response_body.contains(inst))
        .limit(200))).all()
    for u, body, content_type in rows:
        if u.split("?", 1)[0] == url.split("?", 1)[0]:
            continue
        it = sm.interface_of(u, {inst})
        if it is None:
            continue
        is_list = (it.kind == "list" and it.resource_type == rtype) or \
            (it.kind == "sub" and it.sub == rtype)
        if is_list and inst not in (u.split("?", 1)[0]) and _mentions(body, inst):
            return u
        path_segments = [x for x in u.split("?", 1)[0].split("/") if x]
        page = sm.interface_of(u, {inst, path_segments[-1]}) if path_segments else None
        if "html" in str(content_type or "").lower() \
                and not urlsplit(u).path.startswith("/api/") \
                and page is not None and page.kind == "detail" \
                and page.resource_type != rtype:
            import re
            section = re.search(r"<(?:h[1-6]|th)[^>]*>\s*" + re.escape(rtype)
                                + r"\s*</(?:h[1-6]|th)>", body or "", re.I)
            link = re.search(r"href=[\"'][^\"']*/" + re.escape(rtype)
                             + r"/" + re.escape(inst) + r"(?:[/?#\"'])", body or "", re.I)
            if section and link:
                return u
    return None


def _template_rx(template: str):
    import re
    return re.compile("^" + re.escape(template).replace(re.escape("{id}"), "[^/]+")
                      + "$")


async def open_signals(session: AsyncSession, run_id: uuid.UUID,
                       v: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Signals nothing has settled yet: no finding on any of their interfaces and
    no ``authz.exposure`` examination of them."""
    v = v or await view(session, run_id)
    if not v["signals"]:
        return []
    paths = [urlsplit_path(u) for u in (await session.scalars(
        select(GreyboxFinding.location).where(GreyboxFinding.run_id == run_id))).all()]
    exam = (await session.scalars(select(GreyboxGraphNode.data).where(
        GreyboxGraphNode.run_id == run_id, GreyboxGraphNode.kind == "observation",
        GreyboxGraphNode.key.startswith("authz.exposure|")))).all()
    examined = [urlsplit_path({"url": (d or {}).get("facts", {}).get("interface")})
                for d in exam] + \
        [urlsplit_path({"url": (d or {}).get("facts", {}).get("control")}) for d in exam]
    out = []
    for s in v["signals"]:
        rxs = [_template_rx(t) for t in s.get("interfaces") or []]
        hit = any(rx.match(p) for rx in rxs for p in paths + examined if p)
        if not hit:
            out.append(s)
    return out


def urlsplit_path(loc: Any) -> str:
    from urllib.parse import urlsplit
    u = (loc or {}).get("url") if isinstance(loc, dict) else loc
    return urlsplit(str(u or "")).path if u else ""
