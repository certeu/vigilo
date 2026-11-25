"""Non-web vertical slice, end to end (acceptance 4, 11, 12).

A network-mode target over a controlled loopback segment (``fixtures/net_lab.py``):
real worker, real database, real sockets through ``netcap.GuardedNet``, real
sandbox — only the reasoning model is scripted. The script *reacts to the
knowledge* the engine gives it (it reads services, banners and results from the
snapshot, never from the fixture), so what is asserted is the platform contract:

* the run is offered network tools and NOT the browser or web checks;
* a sweep inventories host → services from banners; silent services are
  identified only after the agent decides to send identification hellos — a new
  observation (an unidentified service) changes what the agent does next;
* the agent writes its own analyser (patch level from an SSH banner) with the
  ``recorded`` + ``tcp_connect`` capabilities; its attempt to reach an address
  outside the boundary is refused by the broker and audited, and the outside
  listener never sees a connection;
* evidence-backed findings are verified by an independent re-probe and classified
  (vulnerability / misconfiguration / hardening) with remediation and retest steps;
* the report inventories the services without any web assumption.
"""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web.exploration.client import FakeClient
from src.greybox_web.exploration.knowledge import extract_knowledge
from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxEvent,
    GreyboxFinding,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxWorkOrder,
)
from tests.greybox_web.conftest import create_target, h, run_worker_once, start_run
from tests.greybox_web.fixtures import net_lab

LIMITS = {"rate_limit_rps": 50, "max_requests": 200, "request_timeout_s": 5,
          "max_duration_s": 120, "max_pages": 10, "max_concurrency": 4}

SSH_AUDIT = '''
"""Patch level of SSH services from their banners (recorded + one re-read)."""

def _version(banner):
    head = banner.split("-", 2)[-1] if banner.startswith("SSH-") else ""
    if not head.startswith("OpenSSH_"):
        return None
    num = head[len("OpenSSH_"):].split(" ")[0]
    major, _, rest = num.partition(".")
    digits = ""
    for ch in rest:
        if not ch.isdigit():
            break
        digits += ch
    minor = digits or "0"
    return (int(major), int(minor)), num


def analyse(ctx):
    findings, facts = [], {}
    rows = ctx.broker.recorded(scheme="tcp", limit=50)
    for row in rows:
        banner = row.get("body") or ""
        v = _version(banner)
        if not v:
            continue
        hostport = row["url"].split("//", 1)[1]
        live = ctx.broker.tcp(hostport.rsplit(":", 1)[0], int(hostport.rsplit(":", 1)[1]))
        facts[hostport] = {"version": v[1], "confirmed_live": live["banner"][:40]}
        if v[0] < (7, 4):
            findings.append({
                "title": f"Outdated OpenSSH {v[1]} on {hostport}",
                "severity": "medium", "class": "hardening", "cwe": "CWE-1104",
                "affected": "tcp://" + hostport,
                "description": f"The banner announces OpenSSH {v[1]}, a release "
                               "line out of upstream support with published "
                               "vulnerabilities.",
                "evidence": [banner.strip()[:120]],
                "remediation": {"summary": "Upgrade OpenSSH to a supported release.",
                                "steps": ["Apply the distribution's security "
                                          "updates for openssh-server.",
                                          "Restart sshd and confirm the new banner."],
                                "validation": ["The banner reports a supported "
                                               "version (>= 9.x)."]}})
    # the boundary is the broker's, not this code's: try a neighbour on purpose
    try:
        ctx.broker.tcp("127.0.0.2", ctx.args.get("probe_port", 22))
        facts["neighbour"] = "REACHED"
    except BrokerError as exc:
        facts["neighbour"] = "refused: " + str(exc)
    return {"summary": f"{len(facts) - 1} ssh service(s) audited",
            "observations": [{"key": "ssh.patch", "facts": {
                "audit": json.dumps(facts)}}],
            "findings": findings}
'''


def _act(tool, params, reason, variant, hyp=None):
    a = {"tool": tool, "params": params, "reason": reason, "priority": 20,
         "variant": variant}
    if hyp:
        a["hypothesis"] = hyp
    return a


def network_agent(seen: list):
    """A reactive investigator: decisions come from the knowledge snapshot only."""
    def respond(system: str, user: str) -> str:
        k = extract_knowledge(user)
        seen.append((system, k))
        work = k.get("work") or {}
        done = " ".join(work.get("history") or []) + " " + " ".join(
            f"{w['tool']} {w['url']}" for w in (work.get("pending") or [])
            + (work.get("running") or []))
        tools = set(k.get("tools") or [])
        services: dict = {}
        for o in k.get("observations") or []:
            f = o.get("facts") or {}
            if str(o.get("key", "")).startswith("net.service|"):
                services[(f.get("host"), f.get("port"))] = f
        actions, hyps = [], []
        if "net.sweep" not in done:
            actions.append(_act("net.sweep", {}, "inventory the authorised boundary",
                                "sweep"))
        for (host, port), f in sorted(services.items(), key=lambda x: str(x)):
            if f.get("protocol") != "unknown":
                continue
            for probe in ("http_head", "redis_ping"):
                if f"tcp://{host}:{port}|probe:{probe}" in done:
                    continue
                hid = f"h-silent-{port}"
                hyps.append({"id": hid, "label": f"silent service {port}",
                             "hypothesis": f"{host}:{port} answers no banner: "
                                           f"identify it with an inert hello"})
                actions.append(_act("net.probe", {"host": host, "port": port,
                                                  "probe": probe},
                                    "unidentified silent service", f"{port}-{probe}",
                                    hid))
                break
        ssh = [f for f in services.values() if f.get("protocol") == "ssh"
               and f.get("version")]
        if ssh and "define:ssh-patch" not in done:
            hyps.append({"id": "h-ssh", "label": "outdated ssh",
                         "hypothesis": "the SSH banner version may be unsupported"})
            actions.append(_act("tool.compose", {"spec": {
                "id": "ssh-patch", "title": "SSH patch level from banners",
                "purpose": "no built-in tool judges a product's patch level from "
                           "its banner",
                "capabilities": ["recorded", "tcp_connect"], "max_calls": 20,
                "source": "import json\n" + SSH_AUDIT}},
                "need a banner-to-patch-level analyser", "compose", "h-ssh"))
        if "tool.ssh-patch" in tools and "tool.ssh-patch" not in done:
            actions.append(_act("tool.ssh-patch", {"args": {"probe_port": 22}},
                                "run the analyser I wrote", "run", "h-ssh"))
        if not actions:
            return json.dumps({"reasoning": "every service is identified and "
                               "analysed", "assessment": "adequate", "todolist": [],
                               "hypotheses": [], "actions": []})
        return json.dumps({"reasoning": f"{len(services)} services known",
                           "assessment": "incomplete", "todolist": [],
                           "hypotheses": hyps, "actions": actions[:8]})
    return respond


async def _rows(session_maker, run_id, model):
    async with session_maker() as s:
        return list((await s.scalars(select(model).where(model.run_id == run_id)))
                    .all())


async def test_network_segment_is_assessed_end_to_end(
        client, user_token, session_maker, monkeypatch):
    lab = await net_lab.start()
    seen: list = []
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client",
                        lambda *a, **kw: FakeClient(network_agent(seen)))
    ports = [lab.ports[n] for n in ("ssh", "telnet", "redis", "web", "closed")]
    try:
        t = await create_target(
            client, user_token, name="lab-segment",
            base_url=f"http://127.0.0.1:{lab.ports['web']}/",
            assessment_mode="network", model_backend="fake", limits=dict(LIMITS),
            scope={"network": {"targets": ["127.0.0.1"], "ports": ports,
                               "protocols": ["tcp"], "rate_per_s": 20}})
        r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
        assert r.status_code == 201, r.text
        run_id = uuid.UUID(r.json()["id"])
        assert str(await run_worker_once(session_maker)) == str(run_id)
    finally:
        await lab.close()
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "succeeded", body.get("error_summary")

    # --- capabilities follow the target: network tools, never browser/web checks
    system, k0 = seen[0]
    assert "NETWORK SEGMENT" in system and "browser.visit" not in system
    tools = set(k0["tools"])
    assert {"net.sweep", "net.probe", "tool.compose"} <= tools
    assert not {t for t in tools if t.startswith(("browser.", "headers.", "injection."))}
    assert k0["run"]["mode"] == "network" and k0["run"]["network"]["ports"]

    # --- inventory: host -> services, identified by banner or by inert hello
    assets = await _rows(session_maker, run_id, GreyboxAsset)
    host = next(a for a in assets if a.kind == "host" and a.key == "127.0.0.1")
    svcs = {a.key: a for a in assets if a.kind == "service"}
    for name in ("ssh", "telnet", "redis", "web"):
        a = svcs[f"tcp://127.0.0.1:{lab.ports[name]}"]
        assert a.parent_id == host.id and a.tested
    proto = {n: svcs[f"tcp://127.0.0.1:{lab.ports[n]}"].data["protocol"]
             for n in ("ssh", "telnet", "redis", "web")}
    assert proto == {"ssh": "ssh", "telnet": "telnet", "redis": "redis",
                     "web": "http"}, proto
    assert f"tcp://127.0.0.1:{lab.ports['closed']}" not in svcs

    # --- adaptive: the silent services changed the plan (probes + hypotheses)
    wos = await _rows(session_maker, run_id, GreyboxWorkOrder)
    probes = {(w.params["port"], w.params["probe"]) for w in wos if w.tool == "net.probe"}
    assert (lab.ports["redis"], "redis_ping") in probes
    assert (lab.ports["web"], "http_head") in probes
    assert not any(p[0] in (lab.ports["ssh"], lab.ports["telnet"]) for p in probes)

    # --- only inert bytes reached the services; nothing reached outside the scope
    assert all(b in (b"", b"PING\r\n", b"HEAD / HTTP/1.0\r\n\r\n")
               for b in lab.received.get("redis", []) + lab.received.get("web", []))
    assert lab.outside_connections == 0
    traffic = await _rows(session_maker, run_id, GreyboxHttpExchange)
    assert not [x for x in traffic if x.scheme == "http" and not x.blocked]
    refused = [x for x in traffic if x.host == "127.0.0.2"]
    assert refused and all(x.blocked and x.block_reason == "address_not_in_scope"
                           for x in refused)

    # --- the agent wrote a tool, ran it, and its finding was verified by replay
    composed = [e for e in await _rows(session_maker, run_id, GreyboxEvent)
                if e.kind == "tool.defined"]
    assert composed and composed[0].data["capabilities"] == ["recorded",
                                                              "tcp_connect"]
    assert "def analyse" in composed[0].data["source"]
    findings = {f.check_id + "|" + f.title: f
                for f in await _rows(session_maker, run_id, GreyboxFinding)}
    tool_wos = [(w.tool, w.status, w.error, w.result_summary) for w in wos
                if "ssh-patch" in w.tool]
    ssh_f = next((f for k, f in findings.items() if k.startswith("tool.ssh-patch|")),
                 None)
    assert ssh_f is not None, (tool_wos, list(findings))
    assert ssh_f.status == "verified" and ssh_f.finding_class == "hardening"
    assert ssh_f.remediation["validation"]

    # --- evidence-backed, classified, verified network findings
    by_check = {f.check_id: f for f in findings.values()}
    assert by_check["net.unauthenticated"].status == "verified"
    assert by_check["net.unauthenticated"].finding_class == "vulnerability"
    assert by_check["net.cleartext"].finding_class == "misconfiguration"
    assert by_check["net.cleartext"].status == "verified"
    for f in findings.values():
        assert f.remediation and f.remediation.get("summary"), f.title

    # --- the report: inventory and class sections, no web vocabulary required
    rep = (await client.get(f"/greybox/runs/{run_id}/report",
                            headers=h(user_token))).json()["markdown"]
    for phrase in ("## Summary", "## Asset and service inventory",
                   "### Confirmed vulnerabilities", "### Security misconfigurations",
                   "### Hardening recommendations", "## Tools written by the agent",
                   "How to verify the fix", "## Hypotheses investigated",
                   f"tcp://127.0.0.1:{lab.ports['redis']}"):
        assert phrase in rep, phrase
    vulns = rep.split("### Confirmed vulnerabilities", 1)[1].split("\n### ", 1)[0]
    assert "Redis answers commands without authentication" in vulns
    assert "Outdated OpenSSH" not in vulns and "Telnet" not in vulns

    # --- coverage: every service examined
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
    assert run.coverage_verdict["outcome"] in ("completed", "partial"), \
        run.coverage_verdict
    assert "never swept" not in json.dumps(run.coverage_verdict)


async def test_unreachable_anchor_url_does_not_fail_a_network_assessment(
        client, user_token, session_maker, monkeypatch):
    """Regression (Harbor Net baseline run): in network mode the agent may fetch
    the anchor URL; when nothing listens there, the web "nothing answered"
    fast-fail used to fail the whole run although TCP services had answered."""
    lab = await net_lab.start()
    import src.greybox_web.supervisor as sup

    def respond(system: str, user: str) -> str:
        k = extract_knowledge(user)
        done = " ".join((k.get("work") or {}).get("history") or [])
        actions = []
        if "net.sweep" not in done:
            actions.append(_act("net.sweep", {}, "inventory", "sweep"))
        if "discovery.fetch_root" not in done:
            actions.append(_act("discovery.fetch_root", {"url": k["run"]["base_url"]},
                                "look at the anchor", "root"))
        return json.dumps({"reasoning": "r", "assessment": "incomplete"
                           if actions else "adequate", "actions": actions})
    monkeypatch.setattr(sup, "build_client", lambda *a, **kw: FakeClient(respond))
    ports = [lab.ports[n] for n in ("ssh", "redis", "closed")]
    try:
        t = await create_target(
            client, user_token, name="anchorless",
            base_url=f"http://127.0.0.1:{lab.ports['closed']}/",
            assessment_mode="network", model_backend="fake", limits=dict(LIMITS),
            scope={"network": {"targets": ["127.0.0.1"], "ports": ports,
                               "protocols": ["tcp", "http"], "rate_per_s": 20}})
        r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
        run_id = uuid.UUID(r.json()["id"])
        await run_worker_once(session_maker)
    finally:
        await lab.close()
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "succeeded", body.get("error_summary")


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
