"""Skills core, definition of done, anti-loop ledger and route inference (unit level).

The end-to-end proof that the agent selects, loads and is steered by skills lives in
``test_skills_e2e.py``; these tests pin the contracts it relies on.
"""
from __future__ import annotations

import uuid

import pytest

from src.greybox_web import coverage, progress, skillbook
from src.greybox_web.exploration.explorer import system_prompt
from src.greybox_web.tools.routes import infer

WEB_CAPS = {"http", "browser", "dns", "sandbox", "recorded", "skills", "inventory"}


# ------------------------------------------------------------------ catalogue


def test_catalogue_is_valid_and_index_follows_mode_and_capabilities():
    cat = skillbook.catalogue()
    assert {"api-recon", "api-security", "auth-boundaries", "hardening"} <= set(cat)
    for s in cat.values():
        assert s.criteria and len(s.body) <= skillbook.BODY_CAP
    web = skillbook.index_text("web", WEB_CAPS)
    assert all(f"- {n}:" in web for n, s in cat.items() if "web" in s.modes)
    assert "- network-recon:" not in web              # network-only methodology
    net = skillbook.index_text("network", {"tcp_connect", "sandbox", "skills"})
    assert "- hardening:" in net and "api-recon" not in net
    assert "- network-recon:" in net and "business-logic" not in net
    # layer 1 lives in the instructions themselves, not only in tool metadata
    assert "skill.read" in system_prompt("web") and "- api-recon:" in system_prompt("web")
    assert "- api-recon:" not in system_prompt("network")


def test_progressive_disclosure_layer_two_and_parts():
    assert "Phase A" in skillbook.read("api-recon")
    assert "Template inference" in skillbook.read("api-recon", "reference")
    assert "def analyse" in skillbook.read("api-recon", "script:extract_routes.py")
    with pytest.raises(KeyError):
        skillbook.read("api-recon", "script:../../etc/passwd")
    sec = skillbook.playbook_section(["api-recon"],
                                     [{"skill": "api-recon", "part": "reference"}])
    assert "ACTIVE SKILLS" in sec and "## Phase B" in sec and "Template inference" in sec


def test_skills_can_be_disabled_for_baseline_evaluation(monkeypatch):
    monkeypatch.setenv(skillbook.ENABLE_ENV, "off")
    assert skillbook.index_text("web", WEB_CAPS) == ""
    assert "skill.read" not in system_prompt("web")


def test_malformed_skill_is_rejected(tmp_path):
    d = tmp_path / "bad-skill"
    d.mkdir()
    (d / "SKILL.md").write_text("---\nname: bad-skill\ndescription: x\n---\nbody")
    with pytest.raises(skillbook.SkillError, match="description"):
        skillbook._parse(d / "SKILL.md")
    (d / "SKILL.md").write_text(
        "---\nname: bad-skill\ndescription: a valid description here\ncriteria:\n"
        "  - {id: c1, text: t, evidence: {grep: x}}\n---\nbody")
    with pytest.raises(skillbook.SkillError, match="unknown key"):
        skillbook._parse(d / "SKILL.md")


# ------------------------------------------------------------------ evaluation


def _facts(**kw) -> skillbook.RunFacts:
    f = skillbook.RunFacts(mode="web", capabilities=frozenset(WEB_CAPS))
    for k, v in kw.items():
        setattr(f, k, v)
    return f


def _state(skill, f):
    return {s.id: s for s in skillbook.evaluate(skillbook.catalogue()[skill], f)}


def test_engine_evidence_claims_and_blocks():
    f = _facts(
        work=[{"id": "1", "tool": "browser.visit", "status": "done",
               "target": "browser.visit http://a/"},
              {"id": "2", "tool": "tool.compose", "status": "done",
               "target": "tool.compose define:x"}],
        assets=[{"kind": "endpoint", "key": "http://a/api/notes", "tested": False,
                 "data": {"source": ["browser:fetch"]}}],
        observations=[{"key": "route.inventory|3|1", "facts": {}}],
        claims={("api-recon", "correlated"): {"status": "satisfied",
                                               "evidence": ["route.inventory|3|1"]},
                ("api-recon", "gaps"): {"status": "satisfied",
                                         "evidence": ["made-up evidence key"]},
                ("api-recon", "workflows"): {"status": "blocked",
                                              "note": "no second identity"}})
    st = _state("api-recon", f)
    assert st["entry-points"].status == "satisfied" and st["entry-points"].by == "engine"
    assert st["runtime-observed"].status == "satisfied"
    # defining a tool is not running one
    assert st["static-resources"].status == "unsatisfied"
    assert st["correlated"].status == "satisfied" and st["correlated"].by == "agent"
    # a claim citing evidence that does not exist does not count
    assert st["gaps"].status == "unsatisfied" and "without evidence" in st["gaps"].note
    assert st["workflows"].status == "blocked"
    # an identity provider blocks runtime discovery by AUTHENTICATION
    f2 = _facts(auth_states=("identity_provider",))
    st2 = _state("api-recon", f2)
    assert st2["runtime-observed"].status == "blocked"
    assert st2["runtime-observed"].category == "authentication"
    # without a browser, runtime discovery is not applicable
    f3 = _facts(capabilities=frozenset({"http", "skills"}))
    assert _state("api-recon", f3)["runtime-observed"].status == "not_applicable"
    # a single identity blocks object-ownership testing by AUTHORISATION
    st4 = _state("api-security", _facts(identities=1))
    assert st4["object-ownership"].status == "blocked"
    assert st4["object-ownership"].category == "authorisation"
    assert _state("hardening", _facts())["exposure-network"].status == "not_applicable"


def test_coverage_distinguishes_unfinished_blocked_and_unauthorised():
    def verdict(items):
        return coverage.assess(coverage.CoverageInput(
            endpoints=1, endpoints_tested=1, skills=tuple(items)))
    done = verdict([("api-recon", "a", "satisfied", None, ""),
                    ("api-recon", "b", "not_applicable", None, "")])
    assert done.outcome == "completed" and done.skills["api-recon"]["satisfied"] == 1
    unfinished = verdict([("api-recon", "Templates inferred", "unsatisfied", None, "")])
    assert unfinished.outcome == "partial"
    assert "Templates inferred" in unfinished.reasons[0]
    blocked = verdict([("auth-boundaries", "Session valid", "blocked",
                        "authentication", "identity provider")])
    assert blocked.outcome == "blocked"
    unauthorised = verdict([("api-security", "Ownership tested", "blocked",
                             "authorisation", "one identity")])
    assert unauthorised.outcome == "needs_authorisation"
    assert any("Ownership tested" in x for x in unauthorised.limitations)


def test_claims_are_validated_and_bounded():
    raw = [{"skill": "api-recon", "id": "gaps", "status": "satisfied",
            "evidence": ["x" * 500]},
           {"skill": "api-recon", "id": "nope", "status": "satisfied"},
           {"skill": "unknown", "id": "gaps", "status": "blocked"},
           {"skill": "api-recon", "id": "gaps", "status": "unsatisfied"},
           "junk"] + [{"skill": "hardening", "id": "classified",
                       "status": "not_applicable", "note": "n"}] * 20
    out = skillbook.clean_claims(raw)
    assert out[0]["id"] == "gaps" and len(out[0]["evidence"][0]) == 200
    assert len(out) == 12 and all(c["status"] in skillbook.CLAIMABLE for c in out)


# ------------------------------------------------------------------ progress


def _step(tool, params, status="done", y=0, err=""):
    return progress.Step(uuid.uuid4(), tool, progress.signature(tool, params), status, y,
                         f"{tool} {params}", err)


def test_identical_unproductive_or_failing_actions_are_refused():
    steps = [_step("discovery.scripts", {"url": "u"}, y=4),
             _step("discovery.scripts", {"url": "u", "max_scripts": 5}, y=0),
             _step("tool.x", {"args": {"a": 1}}, "failed", err="KeyError: 'b'"),
             _step("tool.x", {"args": {"a": 1}}, "failed", err="KeyError: 'b'")]
    assert progress.refusal(steps, "discovery.scripts", {"url": "u"}) is None
    r = progress.refusal(steps, "discovery.scripts", {"max_scripts": 5, "url": "u"})
    assert r and r[0] == "no_new_information"
    assert progress.refusal(steps, "tool.x", {"args": {"a": 1}})[0] == "repeated_failure"
    assert progress.refusal(steps, "tool.x", {"args": {"a": 2}}) is None
    assert progress.refusal(steps, "verify.x", {}) is None
    s = progress.summary(steps + [_step("browser.visit", {"url": "v"})] * 2)
    assert s["no_new_information_streak"] == 5      # failures yield nothing either
    assert s["failing"][0]["runs"] == 2 and "KeyError" in s["failing"][0]["last_error"]
    assert "PROGRESS CHECK" in progress.warning(s)
    assert progress.warning(progress.summary(steps[:1])) == ""


# ------------------------------------------------------------------ routes


def test_route_templates_are_inferences_with_provenance():
    eps = [{"url": f"http://a/api/notes/{i}", "source": ["browser:fetch"],
            "methods": ["GET"], "tested": i == 123} for i in (123, 456, 789)]
    eps += [{"url": "http://a/api/reports/7", "source": ["script:http://a/app.js"]},
            {"url": "http://a/api/notes", "source": ["browser:fetch"]},
            {"url": "http://a/api/users/0b9c2f4e-1a2b-4c3d-8e9f-001122334455",
             "source": ["browser:xhr", "script:http://a/app.js"]}]
    t = {x["template"]: x for x in infer(eps)}
    notes = t["/api/notes/{id}"]
    assert notes["count"] == 3 and notes["confidence"] == "high" and notes["inferred"]
    assert notes["correlation"] == "runtime_only" and notes["tested"] == 1
    assert t["/api/reports/{id}"]["confidence"] == "low"
    assert t["/api/reports/{id}"]["correlation"] == "static_only"
    assert t["/api/users/{uuid}"]["correlation"] == "both"
    assert "/api/notes" not in t                       # nothing parameter-shaped
