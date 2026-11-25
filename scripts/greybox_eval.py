#!/usr/bin/env python3
"""Real-model evaluation of Vigilo against the synthetic fixtures, through the
platform's NORMAL HTTP API (exactly what an operator does in the UI).

    uv run python scripts/greybox_eval.py --fixture harbor_docs \
        --backend codex --model gpt-6-sol [--api http://127.0.0.1:8080] [--repeat 2]
    uv run python scripts/greybox_eval.py --list

Each fixture lives in ``tests/greybox_web/fixtures/<name>/`` with two separate files:

``assessment.json``   the ONLY information given to Vigilo: name, mode, a generic
                      objective, test accounts, the network scope or the artifact
                      directory. It never names a seeded issue.
``ground_truth.json`` what the fixture really contains (seeded conditions, negative
                      controls, scoring regexes). Read by THIS script after the run,
                      to score — it never reaches the platform or the agent.

Per run: start the fixture (unless ``--no-start``), create the login accounts as
vault credentials, create a target of the fixture's mode, start a run with the chosen
model backend, wait, collect run/findings/events/assets/report/knowledge model,
score against the ground truth and write ``summary.json`` / ``summary.md`` under
``~/.cache/vigilo-e2e/eval/<fixture>/<timestamp>/``.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/greybox_web/fixtures"
TERMINAL = {"succeeded", "failed", "cancelled"}


# ---------------------------------------------------------------- fixtures


def fixtures() -> dict[str, Path]:
    return {p.parent.name: p.parent for p in sorted(FIXTURES.glob("*/assessment.json"))}


def load(name: str) -> tuple[dict, dict]:
    d = fixtures().get(name)
    if d is None:
        raise SystemExit(f"unknown fixture {name!r}; known: {', '.join(fixtures())}")
    return (json.loads((d / "assessment.json").read_text()),
            json.loads((d / "ground_truth.json").read_text()))


class Target:
    """Start / stop one fixture in a child process (web) or in-process (network)."""

    def __init__(self, name: str, spec: dict, port: int | None) -> None:
        self.name, self.spec = name, spec
        self.port = port or spec.get("port")
        self.proc: subprocess.Popen | None = None

    @property
    def url(self) -> str:
        if self.spec["mode"] == "web":
            return f"http://127.0.0.1:{self.port}/"
        return self.spec.get("anchor_url") or "http://127.0.0.1/"

    def start(self) -> None:
        mod = f"tests.greybox_web.fixtures.{self.name}"
        args = [sys.executable, "-m", mod]
        if self.spec["mode"] == "web":
            args += ["--port", str(self.port)]
        if self.spec["mode"] == "artifact":
            return                     # nothing listens: the files are uploaded
        self.proc = subprocess.Popen(args, cwd=ROOT, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.ready():
                return
            time.sleep(0.3)
        raise SystemExit(f"fixture {self.name} did not come up")

    def ready(self) -> bool:
        if self.spec["mode"] == "web":
            try:
                return httpx.get(self.url.rstrip("/") + self.spec.get("health_path", "/"),
                                 timeout=2, trust_env=False).status_code < 500
            except httpx.HTTPError:
                return False
        import socket
        net = self.spec["network"]
        host, port = net["targets"][0], net.get("ready_port") or net["ports"][0]
        try:
            socket.create_connection((host, port), timeout=1).close()
            return True
        except OSError:
            return False

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ---------------------------------------------------------------- platform API


def admin_credentials() -> tuple[str, str]:
    env = dict(os.environ)
    if not env.get("VIGILO_FIRST_ADMIN_EMAIL"):
        from dotenv import dotenv_values
        env.update({k: v for k, v in dotenv_values(ROOT / ".env").items() if v})
    return env["VIGILO_FIRST_ADMIN_EMAIL"], env["VIGILO_FIRST_ADMIN_PASSWORD"]


class Api:
    def __init__(self, base: str) -> None:
        self.c = httpx.Client(base_url=base.rstrip("/"), timeout=120, trust_env=False)

    def login(self) -> None:
        user, pw = admin_credentials()
        r = self.c.post("/auth/jwt/login", data={"username": user, "password": pw})
        r.raise_for_status()
        self.c.headers["Authorization"] = "Bearer " + r.json()["access_token"]

    def get(self, path, **kw):
        for attempt in range(20):          # survive an API restart while polling
            try:
                r = self.c.get(path, **kw)
                break
            except httpx.TransportError:
                if attempt == 19:
                    raise
                time.sleep(15)
        r.raise_for_status()
        return r.json()

    def post(self, path, body=None, ok=(200, 201, 202), **kw):
        r = self.c.post(path, json=body, **kw) if body is not None or not kw \
            else self.c.post(path, **kw)
        if r.status_code not in ok:
            raise SystemExit(f"POST {path} -> {r.status_code}: {r.text[:600]}")
        return r.json()


def ensure_accounts(api: Api, fixture: str, accounts: list[dict]) -> list[str]:
    existing = {c["label"]: c["id"] for c in api.get("/credentials")
                if c.get("kind") == "login_account"}
    ids = []
    for acct in accounts:
        label = f"{fixture}-{acct['label']}"
        if label not in existing:
            existing[label] = api.post("/credentials", {
                "kind": "login_account", "label": label,
                "secret": json.dumps({key: acct[key] for key in
                                      ("user", "password", "login_url", "user_field",
                                       "password_field", "method", "body")
                                      if key in acct})})["id"]
        ids.append(existing[label])
    return ids


def wait(api: Api, run_id: str, until: float | None = None) -> dict:
    last = None
    while True:
        run = api.get(f"/greybox/runs/{run_id}")
        line = (f"{run['status']} phase={run.get('phase')} "
                f"requests={run['counters'].get('requests')} "
                f"findings={run['counters'].get('findings_total', '?')}")
        if line != last:
            print(time.strftime("%H:%M:%S"), line, flush=True)
            last = line
        if run["status"] in TERMINAL or (until and time.time() >= until):
            return run
        time.sleep(15)


def all_events(api: Api, run_id: str) -> list[dict]:
    out, after = [], 0
    while True:
        page = api.get(f"/greybox/runs/{run_id}/events",
                       params={"after_seq": after, "limit": 500})
        items = page.get("items") if isinstance(page, dict) else page
        if not items:
            return out
        out += items
        after = items[-1]["seq"]


# ---------------------------------------------------------------- scoring


def _text(f: dict) -> str:
    return " ".join([f.get("title") or "", f.get("description") or "",
                     f.get("check_id") or ""])


def _loc(f: dict) -> str:
    loc = f.get("location") or {}
    return str(loc.get("url") or loc.get("asset") or loc.get("service") or "")


def _match(rule: dict, f: dict, *, named: bool = False) -> bool:
    """Location AND text. ``named``: the location rule may also be satisfied by a
    path the finding's description names (an agent-written analyser may file its
    finding under the URL it was run on)."""
    where = _loc(f) + ((" " + (f.get("description") or "")) if named else "")
    return bool(re.search(rule["location_regex"], where)
                and re.search(rule["text_regex"], _text(f)))


def score(gt: dict, findings: list[dict]) -> dict:
    """Seeded rows, false positives and duplicates for one run.

    * a seeded condition is *found* when a non-rejected finding matches it, and
      *verified* when a matching finding was reproduced by the platform;
    * a finding matching a negative control is a false positive whatever its class;
    * an unmatched finding is a false positive unless its class is one the fixture
      allows (hardening/informational advice is reviewed, not counted);
    * several findings matching the same seeded condition are duplicates."""
    live = [f for f in findings if f.get("status") != "rejected"]
    rows, matched = [], set()
    for s in gt.get("seeded", []):
        hits = [f for f in live if _match(s["match"], f)] or \
            [f for f in live if _match(s["match"], f, named=True)]
        matched |= {f["id"] for f in hits}
        verified = [f for f in hits if f["status"] == "verified"]
        best = (verified or hits or [None])[0]
        status = ("verified" if verified else "found_unverified" if hits else "missed")
        rows.append({
            "id": s["id"], "title": s["title"], "expected_class": s.get("class"),
            "status": status,
            "must_be_verified": bool(s.get("must_be_verified")),
            "ok": status == "verified" or (status == "found_unverified"
                                           and not s.get("must_be_verified")),
            "class_ok": bool(best) and s.get("class") in ("any", None,
                                                          best.get("finding_class")),
            "finding": (f"[{best.get('finding_class')}/{best['status']}/"
                        f"{best.get('severity')}] {best['title']}") if best else None,
            "duplicates": max(0, len(verified) - 1),
        })
    allowed = set((gt.get("fp_policy") or {}).get("unmatched_allowed_classes")
                  or ["informational", "hardening"])
    fps, extra = [], []
    for nc in gt.get("negative_controls", []):
        for f in live:
            if _match(nc["false_positive_if"], f) and f["id"] not in matched:
                fps.append({"control": nc["id"], "finding": f["title"],
                            "class": f.get("finding_class"), "status": f["status"]})
                matched.add(f["id"])
    for f in live:
        if f["id"] in matched:
            continue
        row = {"finding": f["title"], "class": f.get("finding_class"),
               "status": f["status"], "severity": f.get("severity"),
               "location": _loc(f)}
        (extra if f.get("finding_class") in allowed else fps).append(
            {**row, **({} if f.get("finding_class") in allowed
                       else {"control": "unmatched"})})
    found = sum(1 for r in rows if r["status"] != "missed")
    return {"rows": rows, "false_positives": fps, "extra_advice": extra,
            "seeded": len(rows), "found": found,
            "verified": sum(1 for r in rows if r["status"] == "verified"),
            "missed": [r["id"] for r in rows if r["status"] == "missed"],
            "duplicates": sum(r["duplicates"] for r in rows)}


# ---------------------------------------------------------------- metrics


def investigation_metrics(exploration: dict, events: list[dict]) -> dict:
    """Measure workflow follow-through without embedding fixture knowledge."""
    nodes = exploration.get("nodes") or []
    investigations = {}
    for node in nodes:
        signal = ((node.get("data") or {}).get("signals") or {}).get("investigation")
        if node.get("kind") == "lead" and isinstance(signal, dict):
            investigations[str(signal.get("id") or node["id"])] = (node, signal)
    ready = {
        key
        for key, (_node, inv) in investigations.items()
        if inv.get("status")
        in (
            "ready",
            "in_progress",
            "awaiting_evidence",
            "verification_pending",
            "confirmed",
            "rejected",
            "inconclusive",
            "blocked",
        )
        or inv.get("ready_at")
    }
    terminal = {
        key
        for key, (_node, inv) in investigations.items()
        if inv.get("status") in ("confirmed", "rejected", "inconclusive", "blocked")
        or inv.get("final_outcome")
    }
    parent_to_key = {
        str(node["id"]): key for key, (node, _inv) in investigations.items()
    }
    meaningful = []
    repeated_discovery = 0
    for node in (node for node in nodes if node.get("kind") == "work_order"):
        data = node.get("data") or {}
        inv_key = str(
            data.get("investigation_ref") or data.get("investigation_id") or ""
        )
        inv_key = (
            inv_key
            if inv_key in investigations
            else parent_to_key.get(str(node.get("parent_id")), "")
        )
        if not inv_key:
            continue
        tool = str(data.get("tool") or node.get("label") or "")
        if tool.startswith("discovery."):
            repeated_discovery += int(inv_key in ready)
        elif not tool.startswith("skill."):
            meaningful.append((inv_key, node))
    initiated = {key for key, _node in meaningful}
    from datetime import datetime

    latencies = []
    for key, node in meaningful:
        inv = investigations[key][1]
        if inv.get("ready_at") and node.get("created_at"):
            start = datetime.fromisoformat(str(inv["ready_at"]).replace("Z", "+00:00"))
            action = datetime.fromisoformat(
                str(node["created_at"]).replace("Z", "+00:00")
            )
            latencies.append(max(0, round((action - start).total_seconds(), 3)))
    refused = sum(
        1
        for event in events
        if event.get("kind") == "planner.decision"
        and (event.get("data") or {}).get("reason") == "no_new_information"
    )
    return {
        "persisted": len(investigations),
        "ready": len(ready),
        "attempted": len(initiated),
        "completed": len(terminal & initiated),
        "initiation_rate": (
            round(len(initiated & ready) / len(ready), 3) if ready else None
        ),
        "completion_rate": (
            round(len(terminal & initiated) / len(initiated), 3) if initiated else None
        ),
        "time_to_first_meaningful_test_s": min(latencies) if latencies else None,
        "repeated_discovery_without_progress": repeated_discovery + refused,
        "unattempted_ready": sorted(ready - initiated),
    }


def metrics(api: Api, run: dict, events: list[dict], findings: list[dict],
            started: float, exploration: dict | None = None,
            canonical_issues: list[dict] | None = None) -> dict:
    rid = run["id"]
    kinds: dict[str, int] = {}
    tools: dict[str, int] = {}
    for e in events:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        if e["kind"] == "work_order.created":
            t = (e.get("data") or {}).get("tool") or "?"
            tools[t] = tools.get(t, 0) + 1
    llm = [e for e in events if e["kind"] == "llm.response"]
    assets = api.get(f"/greybox/runs/{rid}/graph/assets")
    nodes = assets.get("nodes") or assets.get("assets") or []
    by_kind: dict[str, int] = {}
    for n in nodes:
        by_kind[n.get("kind")] = by_kind.get(n.get("kind"), 0) + 1
    eps = [n for n in nodes if n.get("kind") == "endpoint"]
    hyps = sorted({h for e in llm for h in (e.get("data") or {}).get(
        "hypothesis_labels") or []})
    refused = [e for e in events if e["kind"] == "planner.decision"
               and (e.get("data") or {}).get("reason") in ("no_new_information",
                                                           "repeated_failure")]
    fcount: dict[str, int] = {}
    for f in findings:
        k = f"{f.get('finding_class')}/{f['status']}"
        fcount[k] = fcount.get(k, 0) + 1
    canonical_issues = canonical_issues or []
    return {
        "run_id": rid, "status": run["status"], "end_reason": run.get("end_reason"),
        "model_backend": run.get("model_backend"), "model": run.get("model"),
        "duration_s": round(time.time() - started),
        "model_calls": len(llm),
        "tokens": sum(int((e.get("data") or {}).get("tokens") or 0) for e in llm),
        "requests": run["counters"].get("requests"),
        "assets_by_kind": by_kind,
        "endpoints_discovered": len(eps),
        "endpoint_paths": sorted({urlsplit(n.get("key") or "").path
                                  for n in eps})[:120],
        "hypotheses": hyps,
        "hypotheses_count": len(hyps),
        "skills_loaded": [{"skill": (e.get("data") or {}).get("skill"),
                           "reason": (e.get("data") or {}).get("reason")}
                          for e in events if e["kind"] == "skill.loaded"],
        "criteria_claim_events": kinds.get("skill.criteria", 0),
        "model_updates": kinds.get("model.updated", 0),
        "tools_invoked": dict(sorted(tools.items(), key=lambda x: -x[1])),
        "tools_composed": [(e.get("data") or {}).get("id") for e in events
                           if e["kind"] == "tool.defined"],
        "refused_repeats": len(refused),
        "findings_by_class_status": fcount,
        "verification_outcomes": {k: sum(1 for f in findings if (f.get("verification") or {}).get("result") == k)
                                  for k in ("confirmed", "inconclusive", "not_reproduced", "authorised_by_model")},
        "coverage_verdict": run.get("coverage_verdict"),
        "auth_states": run.get("auth_states"),
        "resumed": kinds.get("run.resumed", 0),
        "investigations": investigation_metrics(exploration or {}, events),
        "canonical_issue_count": len(canonical_issues),
        "canonical_affected_locations": sum(int(x.get("affected_location_count") or 0)
                                            for x in canonical_issues),
    }


# ---------------------------------------------------------------- one run


def create_target(api: Api, name: str, spec: dict, target: Target, a) -> dict:
    accounts = ensure_accounts(api, name, spec.get("accounts") or [])
    body = {"name": f"{name}-{time.strftime('%m%d-%H%M%S')}",
            "base_url": target.url, "description": spec["objective"],
            "account_ids": accounts, "assessment_mode": spec["mode"],
            "model_backend": a.backend, "model": a.model or None,
            "limits": {"max_requests": a.max_requests, "max_duration_s": a.max_duration,
                       "rate_limit_rps": 10, "max_pages": 80, "max_concurrency": 4,
                       "request_timeout_s": 10}}
    if spec.get("scope"):
        body["scope"] = dict(spec["scope"])
    if spec["mode"] == "network":
        body.setdefault("scope", {})["network"] = {k: v for k, v in spec["network"].items()
                                                     if k in ("targets", "ports", "protocols",
                                                              "rate_per_s")}
    if spec.get("activity"):
        body.setdefault("scope", {})["activity"] = spec["activity"]
    t = api.post("/greybox/targets", body)
    if spec["mode"] == "artifact":
        upload_artifact(api, t["id"], FIXTURES / name / spec["artifact_dir"])
    return t


def upload_artifact(api: Api, target_id: str, directory: Path) -> None:
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in sorted(directory.rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                tar.add(p, arcname=str(p.relative_to(directory)))
    r = api.c.post(f"/greybox/targets/{target_id}/artifact",
                   files={"file": ("bundle.tar.gz", buf.getvalue(),
                                   "application/gzip")})
    if r.status_code not in (200, 201):
        raise SystemExit(f"artifact upload -> {r.status_code}: {r.text[:400]}")
    print(f"artifact uploaded: {r.json().get('files')} files", flush=True)


def one_run(api: Api, name: str, spec: dict, gt: dict, target: Target, a,
            out: Path) -> dict:
    if a.attach:
        rid = a.attach            # an existing run (e.g. the driver was interrupted)
    else:
        t = create_target(api, name, spec, target, a)
        run = api.post(f"/greybox/targets/{t['id']}/runs",
                       {"authorization_confirmed": True})
        rid = run["id"]
    print(f"[{name}] run {rid} started (backend {a.backend}, model "
          f"{a.model or 'default'})", flush=True)
    started = time.time()
    run = wait(api, rid)
    events = all_events(api, rid)
    items = api.get(f"/greybox/runs/{rid}/findings")["items"]
    findings = [api.get(f"/greybox/runs/{rid}/findings/{f['id']}") for f in items]
    report = api.get(f"/greybox/runs/{rid}/report")
    exploration = api.get(f"/greybox/runs/{rid}/graph/exploration", params={"limit": 500})
    canonical = api.get(f"/greybox/runs/{rid}/canonical-issues").get("items") or []
    try:
        model = api.get(f"/greybox/runs/{rid}/model")
    except httpx.HTTPError:
        model = None
    sc = score(gt, findings)
    m = metrics(api, run, events, findings, started, exploration, canonical)
    if model is not None:
        m["security_model"] = {
            **(model.get("counts") or {}),
            "identities": [i.get("identity") for i in model.get("identities") or []],
            "expectations_by_basis": _by(model.get("expectations") or [], "basis"),
            "signals": [x.get("summary") for x in model.get("signals") or []][:12],
        }
    rejected_by_model = [f["title"] for f in findings
                         if ((f.get("verification") or {}).get("model") or {})
                         .get("decision") == "authorised"]
    m["rejected_as_authorised_by_model"] = rejected_by_model
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except subprocess.SubprocessError:
        revision = "unknown"
    summary = {"kind": "real-model", "fixture": name, "target": target.url,
               "revision": revision,
               "working_tree_dirty": subprocess.run(
                   ["git", "diff", "--quiet"], cwd=ROOT).returncode != 0,
               "fixture_reset": "process_start" if target.proc is not None
               else "external_reused",
               **sc, **m}
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    (out / "events.json").write_text(json.dumps(events, default=str))
    (out / "exploration.json").write_text(json.dumps(exploration, default=str))
    (out / "canonical-issues.json").write_text(json.dumps(canonical, default=str))
    (out / "findings.json").write_text(json.dumps(findings, indent=2, default=str))
    (out / "report.md").write_text(report.get("markdown") or "")
    if model is not None:
        (out / "model.json").write_text(json.dumps(model, indent=2, default=str))
    (out / "summary.md").write_text(render(summary))
    print(render(summary))
    print(f"results in {out}", flush=True)
    return summary


def _by(rows: list[dict], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        out[str(r.get(key))] = out.get(str(r.get(key)), 0) + 1
    return out


def render(s: dict) -> str:
    md = [f"## {s['fixture']} — run {s['run_id'][:8]} ({s['status']}, "
          f"{(s.get('coverage_verdict') or {}).get('outcome')})", "",
          "| Seeded | Expected class | Result | Status |", "|---|---|---|---|"]
    md += [f"| {r['id']} {r['title']} | {r['expected_class']} | {r['finding'] or '—'} "
           f"| {r['status']}{' (dup ' + str(r['duplicates']) + ')' if r['duplicates'] else ''} |"
           for r in s["rows"]]
    md += ["", f"False positives: {len(s['false_positives'])}"]
    md += [f"- {fp.get('control')}: [{fp.get('class')}/{fp.get('status')}] "
           f"{fp['finding']}" for fp in s["false_positives"]]
    md += ["", f"Advice (hardening/informational, reviewed): {len(s['extra_advice'])}"]
    md += [f"- [{x['class']}/{x['status']}] {x['finding']}" for x in s["extra_advice"]]
    sm_ = s.get("security_model")
    if sm_:
        md += ["", f"Security model: {sm_.get('entities', 0)} entities, "
                   f"{sm_.get('relations', 0)} relations, {sm_.get('expectations', 0)} "
                   f"expectations {sm_.get('expectations_by_basis')}, "
                   f"{sm_.get('interfaces', 0)} interfaces, {sm_.get('signals', 0)} "
                   "signals"]
    if s.get("rejected_as_authorised_by_model"):
        md += ["", "Reproduced but rejected as authorised by the access model: "
                   + "; ".join(s["rejected_as_authorised_by_model"][:8])]
    md += ["", f"calls {s['model_calls']} · tokens {s['tokens']} · requests "
               f"{s['requests']} · {s['duration_s']} s · tools composed "
               f"{len(s['tools_composed'])} · skills "
               f"{[x['skill'] for x in s['skills_loaded']]}"]
    return "\n".join(md) + "\n"


def rescore(d: Path) -> None:
    """Recompute the score of a saved run from its findings (and model), e.g. after
    a ground-truth correction or for runs recorded by an older driver."""
    s = json.loads((d / "summary.json").read_text())
    _, gt = load(s["fixture"])
    findings = json.loads((d / "findings.json").read_text())
    s.update(score(gt, findings))
    if (d / "model.json").exists():
        model = json.loads((d / "model.json").read_text())
        s["security_model"] = {
            **(model.get("counts") or {}),
            "identities": [i.get("identity") for i in model.get("identities") or []],
            "expectations_by_basis": _by(model.get("expectations") or [], "basis"),
            "signals": [x.get("summary") for x in model.get("signals") or []][:12]}
    s["rejected_as_authorised_by_model"] = [
        f["title"] for f in findings
        if ((f.get("verification") or {}).get("model") or {}).get("decision")
        == "authorised"]
    (d / "summary.json").write_text(json.dumps(s, indent=2, default=str))
    (d / "summary.md").write_text(render(s))
    print(render(s))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", action="append", default=[])
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--api", default="http://127.0.0.1:8080")
    ap.add_argument("--port", type=int)
    ap.add_argument("--no-start", action="store_true",
                    help="the fixture is already running")
    ap.add_argument("--backend", default="codex")
    ap.add_argument("--model", default="")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--max-requests", type=int, default=1500)
    ap.add_argument("--max-duration", type=int, default=2400)
    ap.add_argument("--label", default="")
    ap.add_argument("--out", default=str(Path.home() / ".cache/vigilo-e2e/eval"))
    ap.add_argument("--attach", default="",
                    help="collect and score an existing run id instead of starting one")
    ap.add_argument("--rescore", nargs="*", default=[],
                    help="re-score saved result directories against the current "
                         "ground truth (no run)")
    a = ap.parse_args()
    if a.rescore:
        for d in a.rescore:
            rescore(Path(d))
        return
    if a.list:
        for n, d in fixtures().items():
            spec = json.loads((d / "assessment.json").read_text())
            print(f"{n:18} {spec['mode']:8} {spec['name']}")
        return
    api = Api(a.api)
    api.login()
    for name in a.fixture:
        spec, gt = load(name)
        target = Target(name, spec, a.port)
        if not a.no_start:
            target.start()
        try:
            for i in range(a.repeat):
                if i and not a.no_start:
                    target.stop()
                    target.start()
                stamp = time.strftime("%Y%m%d-%H%M%S") + (f"-{a.label}" if a.label else "")
                one_run(api, name, spec, gt, target, a, Path(a.out) / name / stamp)
        finally:
            if not a.no_start:
                target.stop()


if __name__ == "__main__":
    main()
