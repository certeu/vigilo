#!/usr/bin/env python3
"""End-to-end evaluation of Vigilo against the Acme Workspace fixture, through the
platform's NORMAL HTTP API (exactly what an operator does in the UI).

    python scripts/greybox_acme_eval.py --api http://127.0.0.1:8080 \
        --backend codex --model gpt-6-sol [--interrupt-after 240] [--out DIR]

1. starts the synthetic target (tests/greybox_web/fixtures/acme_portal) unless
   --target-url points at a running one;
2. signs in as the platform admin (VIGILO_FIRST_ADMIN_EMAIL / _PASSWORD from the
   environment or .env; never printed);
3. creates the two synthetic login accounts as vault credentials, a web target with
   them, and starts a run with the chosen model backend;
4. optionally cancels the run after N seconds and resumes it (resume scenario);
5. collects the run, findings (with class and remediation), events, assets and the
   report, and scores them against ground_truth.json.

The agent is told nothing about the seeded issues: the target's objective is the
generic one below. Outputs ``summary.json``, ``summary.md`` and ``report.md``.
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
GT = json.loads((ROOT / "tests/greybox_web/fixtures/acme_portal/ground_truth.json")
                .read_text())
OBJECTIVE = ("Assess the Acme Workspace web application (projects, invoices, "
             "documents) for security weaknesses, using the provided test accounts.")
TERMINAL = {"succeeded", "failed", "cancelled"}


def admin_credentials() -> tuple[str, str]:
    env = dict(os.environ)
    if not env.get("VIGILO_FIRST_ADMIN_EMAIL"):
        from dotenv import dotenv_values
        env.update({k: v for k, v in dotenv_values(ROOT / ".env").items() if v})
    return env["VIGILO_FIRST_ADMIN_EMAIL"], env["VIGILO_FIRST_ADMIN_PASSWORD"]


class Api:
    def __init__(self, base: str) -> None:
        self.c = httpx.Client(base_url=base.rstrip("/"), timeout=60, trust_env=False)

    def login(self) -> None:
        user, pw = admin_credentials()
        r = self.c.post("/auth/jwt/login", data={"username": user, "password": pw})
        r.raise_for_status()
        self.c.headers["Authorization"] = "Bearer " + r.json()["access_token"]

    def get(self, path, **kw):
        r = self.c.get(path, **kw)
        r.raise_for_status()
        return r.json()

    def post(self, path, body=None, ok=(200, 201, 202)):
        r = self.c.post(path, json=body)
        if r.status_code not in ok:
            raise SystemExit(f"POST {path} -> {r.status_code}: {r.text[:400]}")
        return r.json()


def ensure_accounts(api: Api) -> list[str]:
    existing = {c["label"]: c["id"] for c in api.get("/credentials")
                if c.get("kind") == "login_account"}
    ids = []
    for acct in GT["accounts"]:
        label = f"acme-{acct['label']}"
        if label not in existing:
            existing[label] = api.post("/credentials", {
                "kind": "login_account", "label": label,
                "secret": json.dumps({"user": acct["user"],
                                      "password": acct["password"]})})["id"]
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
        time.sleep(10)


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


def score(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    def match(rule, f):
        loc = (f.get("location") or {}).get("url") or ""
        text = " ".join([f.get("title") or "", f.get("description") or "",
                         f.get("check_id") or ""])
        return re.search(rule["location_regex"], loc) and \
            re.search(rule["text_regex"], text)
    rows = []
    for gt in GT["seeded"]:
        hits = [f for f in findings if match(gt["match"], f)]
        verified = [f for f in hits if f["status"] == "verified"]
        best = (verified or hits or [None])[0]
        status = ("Found (verified)" if verified else "Found (unverified)"
                  if hits else "Missed")
        if gt["must_be_verified"] and hits and not verified:
            status = "Found (NOT verified)"
        rows.append({"id": gt["id"], "issue": gt["title"], "expected": gt["expected"],
                     "status": status,
                     "result": (f"[{best['finding_class']}/{best['status']}] "
                                f"{best['title']}") if best else "—",
                     "evidence": (f"finding {best['id'][:8]} · exchanges "
                                  + ",".join(str(e["exchange_id"]) for e in
                                             best.get("evidence", [])
                                             if e.get("exchange_id"))[:60])
                     if best else "—",
                     "class_ok": bool(best) and (gt["class"] == "any"
                                                 or best["finding_class"] == gt["class"])})
    fps = []
    matched = {f["id"] for gt in GT["seeded"] for f in findings if match(gt["match"], f)}
    for f in findings:
        if f["id"] not in matched and f["status"] != "rejected":
            fps.append({"control": "unmatched (review)", "finding": f["title"],
                        "class": f["finding_class"], "status": f["status"]})
    for nc in GT["negative_controls"]:
        for f in findings:
            if match(nc["false_positive_if"], f) and f["status"] != "rejected":
                fps.append({"control": nc["id"], "finding": f["title"]})
    return rows, fps


def metrics(api: Api, run: dict, events: list[dict], findings: list[dict],
            started: float) -> dict:
    rid = run["id"]
    kinds: dict[str, int] = {}
    for e in events:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    tools: dict[str, int] = {}
    for e in events:
        if e["kind"] == "work_order.created":
            t = (e.get("data") or {}).get("tool") or "?"
            tools[t] = tools.get(t, 0) + 1
    llm = [e for e in events if e["kind"] == "llm.response"]
    assets = api.get(f"/greybox/runs/{rid}/graph/assets")
    nodes = assets.get("nodes") or assets.get("assets") or []
    eps = [n for n in nodes if n.get("kind") == "endpoint"]
    hyps = sorted({h for e in llm for h in (e.get("data") or {}).get(
        "hypothesis_labels") or []})
    refused = [e for e in events if e["kind"] == "planner.decision"
               and (e.get("data") or {}).get("reason") in ("no_new_information",
                                                           "repeated_failure")]
    return {
        "run_id": rid, "status": run["status"], "end_reason": run.get("end_reason"),
        "model_backend": run.get("model_backend"), "model": run.get("model"),
        "duration_s": round(time.time() - started),
        "model_calls": len(llm),
        "tokens": sum(int((e.get("data") or {}).get("tokens") or 0) for e in llm),
        "requests": run["counters"].get("requests"),
        "endpoints_discovered": len(eps),
        "endpoint_keys": sorted(urlsplit(n.get("key") or n.get("label") or "").path
                                for n in eps)[:80],
        "hypotheses": hyps,
        "skills_loaded": [{"skill": (e.get("data") or {}).get("skill"),
                           "reason": (e.get("data") or {}).get("reason")}
                          for e in events if e["kind"] == "skill.loaded"],
        "criteria_claim_events": kinds.get("skill.criteria", 0),
        "tools_invoked": dict(sorted(tools.items(), key=lambda x: -x[1])),
        "tools_composed": [(e.get("data") or {}).get("id") for e in events
                           if e["kind"] == "tool.defined"],
        "refused_repeats": len(refused),
        "findings_by_class_status": _count(findings),
        "coverage_verdict": run.get("coverage_verdict"),
        "auth_states": run.get("auth_states"),
        "resumed": kinds.get("run.resumed", 0),
    }


def _count(findings):
    out: dict[str, int] = {}
    for f in findings:
        k = f"{f['finding_class']}/{f['status']}"
        out[k] = out.get(k, 0) + 1
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8080")
    ap.add_argument("--target-url")
    ap.add_argument("--target-port", type=int, default=18640)
    ap.add_argument("--backend", default="codex")
    ap.add_argument("--model", default="")
    ap.add_argument("--max-requests", type=int, default=800)
    ap.add_argument("--max-duration", type=int, default=1800)
    ap.add_argument("--interrupt-after", type=int, default=0,
                    help="cancel after N seconds, then resume (resume scenario)")
    ap.add_argument("--out", default=str(Path.home() / ".cache/vigilo-e2e/eval"))
    a = ap.parse_args()
    out = Path(a.out) / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)

    proc = None
    target = a.target_url
    if not target:
        proc = subprocess.Popen([sys.executable, "-m",
                                 "tests.greybox_web.fixtures.acme_portal",
                                 "--port", str(a.target_port)], cwd=ROOT)
        target = f"http://127.0.0.1:{a.target_port}/"
        for _ in range(50):
            try:
                if httpx.get(target + "api/health", timeout=2,
                             trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
    try:
        api = Api(a.api)
        api.login()
        accounts = ensure_accounts(api)
        t = api.post("/greybox/targets", {
            "name": f"acme-workspace-{time.strftime('%H%M%S')}", "base_url": target,
            "description": OBJECTIVE, "account_ids": accounts,
            "model_backend": a.backend, "model": a.model or None,
            "limits": {"max_requests": a.max_requests, "max_duration_s": a.max_duration,
                       "rate_limit_rps": 10, "max_pages": 60, "max_concurrency": 4,
                       "request_timeout_s": 10}})
        run = api.post(f"/greybox/targets/{t['id']}/runs",
                       {"authorization_confirmed": True})
        rid = run["id"]
        print(f"run {rid} started (backend {a.backend}, model {a.model or 'default'})",
              flush=True)
        started = time.time()
        if a.interrupt_after:
            wait(api, rid, until=time.time() + a.interrupt_after)
            print("interrupting (cancel) ...", flush=True)
            api.post(f"/greybox/runs/{rid}/cancel", {"reason": "evaluation: resume test"})
            before = wait(api, rid)
            snap = {"findings": len(api.get(f"/greybox/runs/{rid}/findings")["items"]),
                    "events": len(all_events(api, rid))}
            (out / "before_resume.json").write_text(json.dumps(
                {"run": before, **snap}, indent=2, default=str))
            print("resuming ...", flush=True)
            api.post(f"/greybox/runs/{rid}/resume", {})
        run = wait(api, rid)
        events = all_events(api, rid)
        items = api.get(f"/greybox/runs/{rid}/findings")["items"]
        findings = [api.get(f"/greybox/runs/{rid}/findings/{f['id']}") for f in items]
        report = api.get(f"/greybox/runs/{rid}/report")
        rows, fps = score(findings)
        m = metrics(api, run, events, findings, started)
        summary = {"kind": "real-model", "target": target, "rows": rows,
                   "false_positives": fps, **m}
        (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
        (out / "events.json").write_text(json.dumps(events, default=str))
        (out / "findings.json").write_text(json.dumps(findings, indent=2, default=str))
        (out / "report.md").write_text(report.get("markdown") or "")
        md = ["| Seeded issue | Expected | Agent result | Status | Evidence |",
              "|---|---|---|---|---|"]
        md += [f"| {r['id']} {r['issue']} | {r['expected']} | {r['result']} | "
               f"{r['status']} | {r['evidence']} |" for r in rows]
        md += ["", f"False positives on negative controls: {fps or 'none'}", "",
               "```json", json.dumps(m, indent=2, default=str), "```"]
        (out / "summary.md").write_text("\n".join(md))
        print("\n".join(md[:2 + len(rows)]))
        print(f"\nresults in {out}")
    finally:
        if proc is not None:
            proc.terminate()


if __name__ == "__main__":
    main()
