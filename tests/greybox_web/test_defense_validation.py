"""Validation of the generated defenses (waf-opportunities R1-R18, P2).

Tier 1 (always): linters for every format over generated bundles, unit regressions per
defect, and a Python reference of the path rules over an evasion corpus.
Tier 2 (skipped when the binary is missing): ``nginx -t`` / ``httpd -t`` on the assembled
bundle and a live replay through a throw-away nginx / Apache in front of the synthetic
target (recorded exchanges) and a lenient backend (evasions).

Run with pySigma for the Sigma validators and a Splunk conversion::

    uv run --frozen --all-extras --with pytest --with pytest-asyncio \\
        --with pysigma --with pysigma-backend-splunk pytest tests/greybox_web/test_defense_validation.py
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import unquote_to_bytes, urlsplit

import pytest
import yaml
from sqlalchemy import select

from src.greybox_web import defenses as gd
from src.greybox_web.api import defenses as api_defenses
from src.greybox_web.models import GreyboxAsset, GreyboxDefense, GreyboxFinding
from tests.greybox_web import defense_harness as H
from tests.greybox_web.conftest import h
from tests.greybox_web.test_defenses import done_run  # noqa: F401  (fixture)

needs_nginx = pytest.mark.skipif(not H.NGINX, reason="nginx binary not installed")
needs_httpd = pytest.mark.skipif(
    not (H.HTTPD and H.apache_modules()), reason="Apache httpd and modules not installed")

RUN = uuid.UUID("11111111-1111-1111-1111-111111111111")
RUN2 = uuid.UUID("22222222-2222-2222-2222-222222222222")


# ------------------------------------------------------------------ helpers


def engine_path(path: str) -> str:
    """The path as a WAF / web server matches it: decoded, slashes merged, dot segments
    removed (bytes shown as latin-1)."""
    p = unquote_to_bytes(path.split("?")[0]).decode("latin-1")
    p = re.sub(r"/+", "/", p)
    while "/./" in p:
        p = p.replace("/./", "/")
    return p


def finding(check: str, url: str, detail: str = "x", *, status="verified",
            severity="high", hints=None) -> GreyboxFinding:
    return GreyboxFinding(
        id=uuid.uuid4(), run_id=RUN, dedup_key=f"{check}|asset|{detail}", check_id=check,
        title=f"t {detail}", severity=severity, status=status, confidence="high",
        description="d", location={"url": url}, detection_hints=hints or [],
        evidence=[], references=[])


def build(f: GreyboxFinding, run: uuid.UUID = RUN) -> list[gd.DefenseSpec]:
    return gd.build_for_finding(f, run, gd.ModSecIds(), "2026/01/01")


def asset(kind: str, key: str, parent=None, data=None) -> GreyboxAsset:
    return GreyboxAsset(
        id=uuid.uuid4(), run_id=RUN, kind=kind, key=key, label=key.split("//")[-1]
        if kind != "endpoint" else key.split(":80", 1)[-1] or "/",
        parent_id=parent.id if parent else None, in_scope=True, tested=False,
        finding_count=0, state="in_scope", first_seen_seq=1, version=1, data=data or {})


def synthetic_rows(sensitive=("/.git/HEAD", "/.env", "/backup.sql", "/caf%C3%A9.zip",
                              "/admin/"), origin="http://127.0.0.1:80"):
    """Defense rows for a synthetic service with every observation class."""
    host = asset("host", "127.0.0.1")
    svc = asset("service", origin, host, {"surface": {
        "server": "DemoServer/1.2.3", "version_disclosure": ["server", "x-powered-by"],
        "security_headers": {"missing": ["content-security-policy", "x-frame-options",
                                         "x-content-type-options", "referrer-policy"],
                             "counts": {}, "evaluated": 4},
        "cookie_flags": {"session": {"secure": False, "httponly": False, "samesite": None},
                         "XSRF-TOKEN": {"secure": False, "httponly": False,
                                        "samesite": None}},
        "cors": {"reflects_origin": True, "allows_credentials": True,
                 "paths": ["/api/data"]},
        "tls": {"https": False}, "endpoints": {"auth_like": 1},
        "auth_paths": ["/login"],
        "sensitive_paths": [{"path": p, "reason": "x"} for p in sensitive]}})
    login = asset("endpoint", f"{origin}/login", svc)
    specs = gd.build_for_assets([svc], {host.id: host}, {svc.id: [login]}, [], RUN,
                                gd.ModSecIds(), "2026/01/01")
    return [GreyboxDefense(
        id=uuid.uuid4(), run_id=RUN, finding_id=None, asset_id=a.asset.id, scope="asset",
        finding_ids=[], kind=a.spec.kind, format=a.spec.format, title=a.spec.title,
        rationale=a.spec.rationale, content=a.spec.content, confidence=a.spec.confidence,
        status="proposed") for a in specs]


def blocked(status: int) -> bool:
    return status in (403, 404)


# The restrict-by-source path classes (defenses._CLASSES): the platform's own
# recommendation for administrative and diagnostic paths is to allow only admin
# networks — and the replay's placeholder edit (192.0.2.0/24) deliberately leaves
# the replay client out of them.
RESTRICT_REASONS = frozenset({"administrative interface", "diagnostic page",
                              "diagnostic endpoint"})


async def _restricted_paths(session_maker, run_id) -> set[str]:
    """Crawlable paths the run itself flagged into a restrict-by-source class (the
    service surfaces are the same data the defenses were built from)."""
    out: set[str] = set()
    async with session_maker() as s:
        rows = (await s.scalars(select(GreyboxAsset).where(
            GreyboxAsset.run_id == run_id, GreyboxAsset.kind == "service"))).all()
    for a in rows:
        for p in ((a.data or {}).get("surface") or {}).get("sensitive_paths") or []:
            if p.get("reason") in RESTRICT_REASONS and p.get("path"):
                out.add(str(p["path"]).rstrip("/") or "/")
    return out


# ------------------------------------------------------------------ tier 1: unit


@pytest.mark.parametrize("path,cls_key,hits,misses", [
    ("/.git/HEAD", "repo-git",
     ["/.git/HEAD", "/.GIT/head", "/%2egit/HEAD", "//.git/HEAD", "/./.git/x", "/.git",
      "/.git;x=1/HEAD", "/.git/"],
     ["/.github/a.txt", "/.gitignore", "/.gitlab-ci.yml", "/x/.git/HEAD"]),
    ("/.env", "env",
     ["/.env", "/.ENV", "/app/.env", "/.env.production", "/.env.bak", "/%2eenv",
      "/.env;x=1", "/.env/"],
     ["/.environment", "/env", "/app/.envrc", "/x.env.txt"]),
    ("/db.sql", "backup-ext", ["/db.sql", "/a/b/DUMP.BAK", "/x.sql;y=1"],
     ["/sql", "/db.sqlite"]),
    ("/.svn/entries", "repo-svn", ["/.svn/entries", "/.SVN/"], ["/.svnx"]),
    ("/r%C3%A9sum%C3%A9.bak", "backup-ext", ["/r%C3%A9sum%C3%A9.bak"], []),
    ("/caf%C3%A9.zip", None, ["/caf%C3%A9.zip", "/caf%c3%a9.ZIP", "/caf%C3%A9.zip/"],
     ["/other.zip", "/x/caf%C3%A9.zip"]),
    ("/a%20b.zip", None, ["/a%20b.zip", "/a b.zip"], ["/ab.zip"]),
])
def test_path_class_regex_over_an_evasion_corpus(path, cls_key, hits, misses):
    """R5, R6, R8: the class regex matches decoded, normalised, case-insensitive paths
    (the same regex is rendered in ModSecurity, nginx and Apache)."""
    cls = gd.classify(path)
    if cls_key:
        assert cls.key == cls_key
    rx = re.compile("(?i)" + cls.rx)
    for p in hits:
        assert rx.search(engine_path(p)), (cls.key, p)
    for p in misses:
        assert not rx.search(engine_path(p)), (cls.key, p)


def test_archive_is_exact_not_a_class():
    """A legitimate download must not be blocked by an extension class."""
    c = gd.classify("/download/report.zip")
    assert c.key.startswith("exact:")
    assert not re.search("(?i)" + c.rx, "/download/other.zip")


def test_rule_is_identical_in_every_format():
    specs = {s.format: s.content for s in build(finding("exposure.files",
                                                        "http://h/.git/HEAD", "/.git/HEAD"))
             if s.format in ("modsecurity", "nginx", "apache")}
    rx = gd.classify("/.git/HEAD").rx
    assert rx in specs["modsecurity"] and rx in specs["nginx"] and rx in specs["apache"]
    assert "<LocationMatch" in specs["apache"] and "DirectoryMatch" not in specs["apache"]
    assert "location" not in specs["nginx"]          # no location order to lose to


def test_rule_ids_are_stable_unique_and_never_dropped(monkeypatch):
    """R12, R13: ids derive from target + rule + path; seeding keeps them; exhausting
    the block raises instead of silently dropping a rule."""
    a = gd.ModSecIds()
    i1, _ = a.id_for("http://h:80|path|repo-git")
    assert gd.MODSEC_BASE <= i1 < gd.MODSEC_BASE + gd.MODSEC_SPAN
    assert gd.ModSecIds().id_for("http://h:80|path|repo-git")[0] == i1     # across runs
    assert gd.ModSecIds().id_for("http://other:80|path|repo-git")[0] != i1  # per target
    f = finding("exposure.files", "http://h:80/.git/HEAD", "/.git/HEAD")
    ids = lambda run: re.findall(r"\bid:(\d+)", "".join(  # noqa: E731
        s.content for s in build(f, run) if s.format == "modsecurity"))
    assert ids(RUN) == ids(RUN2) and ids(RUN)              # not derived from the run
    seeded = gd.ModSecIds()
    seeded.seed(next(s.content for s in build(f) if s.format == "modsecurity"))
    assert seeded.id_for(f"http://h:80|path|repo-git")[0] == i1
    # collision: force the same slot, the second key takes the next free one
    monkeypatch.setattr(gd, "MODSEC_SPAN", 1000)
    c = gd.ModSecIds()
    got = {c.id_for(f"k{n}")[0] for n in range(1000)}
    assert len(got) == 1000
    with pytest.raises(gd.RuleIdExhausted):
        c.id_for("one too many")


def test_generate_seeds_ids_from_existing_defenses():
    """R13: a second generation never re-issues an id already in a stored rule."""
    f = finding("exposure.files", "http://h:80/.git/HEAD", "/.git/HEAD")
    first = next(s for s in build(f) if s.format == "modsecurity")
    m = gd.ModSecIds()
    m.seed(first.content)
    again = gd.build_for_finding(f, RUN, m, "2026/01/01")
    assert next(s for s in again if s.format == "modsecurity").content == first.content
    other = finding("exposure.files", "http://h:80/.env", "/.env")
    ids = re.findall(r"\bid:(\d+)", "".join(
        s.content for s in gd.build_for_finding(other, RUN, m, "2026/01/01")
        if s.format == "modsecurity"))
    assert ids and not set(ids) & set(re.findall(r"\bid:(\d+)", first.content))


def test_sigma_is_stable_portable_and_split():
    """R14, B1, B3, B6, B7, B8."""
    f = finding("exposure.files", "http://h:80/.git/HEAD", "/.git/HEAD",
                hints=[{"type": "log_signature", "title": "Probes",
                        "content": "These GET lines are the Vigilo check, not an attack."},
                       {"type": "siem_query", "title": "q", "content": "web.accesslog where x"}])
    a, b = build(f, RUN), build(f, RUN2)
    sa = [s.content for s in a if s.format == "sigma"]
    sb = [s.content for s in b if s.format == "sigma"]
    docs_a = [yaml.safe_load(c) for c in sa]
    docs_b = [yaml.safe_load(c) for c in sb]
    assert [d["id"] for d in docs_a] == [d["id"] for d in docs_b]       # per target+rule
    assert len({d["title"] for d in docs_a}) == len(docs_a) == 2
    attempt = next(d for d in docs_a if d["title"].startswith("Attempted"))
    served = next(d for d in docs_a if d["title"].startswith("Exposed"))
    assert attempt["level"] == "informational" and served["level"] == "high"
    assert served["detection"]["selection_ok"]["sc-status"] == [200, 206]
    assert "sc-status" not in str(attempt["detection"])
    assert all(d["vigilo_verified"] is True and d["status"] == "experimental"
               for d in docs_a)
    assert H.lint_sigma("---\n".join(sa)) == []
    assert not gd.placeholders("".join(sa))       # deployable as is
    # attribution hint kept, pseudo-query dropped
    texts = [s.content for s in a if s.format == "text"]
    assert any("Vigilo check" in t for t in texts)
    assert not any("web.accesslog" in t for t in texts)
    # candidate findings: unsupported and flagged
    cand = build(finding("exposure.files", "http://h:80/.git/HEAD", "/.git/HEAD",
                         status="candidate"))
    d = yaml.safe_load(next(s.content for s in cand if s.format == "sigma"))
    assert d["status"] == "unsupported" and d["vigilo_verified"] is False
    # no dirlisting detection (config check, not a detection) and no CORS Sigma
    assert not [s for s in build(finding("exposure.dirlisting", "http://h:80/static/"))
                if s.format == "sigma"]
    assert not [s for s in build(finding("cors.policy", "http://h:80/api/data", "reflect"))
                if s.format == "sigma"]


def test_sigma_deterministic_date():
    f = finding("exposure.files", "http://h:80/.env", "/.env")
    assert [s.content for s in build(f)] == [s.content for s in build(f)]


def test_cors_needs_an_edit_and_does_not_ship_a_trusted_placeholder():
    """R9: the origin is a REQUIRED EDIT sentinel; the ModSecurity rule is disabled."""
    specs = build(finding("cors.policy", "http://h:80/api/data", "reflect"))
    ms = next(s for s in specs if s.format == "modsecurity")
    assert all(ln.lstrip().startswith("#") for ln in ms.content.splitlines() if ln.strip())
    assert "@@REPLACE_ALLOWED_ORIGIN_REGEX@@" in ms.content
    assert H.lint_modsecurity(ms.content, allow_placeholders=True) == []
    rows = synthetic_rows()
    ng = next(r for r in rows if "CORS" in r.title and r.format == "nginx")
    active = "\n".join(ln for ln in ng.content.splitlines() if not ln.startswith("#"))
    assert "@@REPLACE_ALLOWED_ORIGIN@@" in active and "example" not in active
    assert "REQUIRED EDIT" in ng.content
    ap = next(r for r in rows if "CORS" in r.title and r.format == "apache")
    active = "\n".join(ln for ln in ap.content.splitlines() if not ln.startswith("#"))
    assert "@@REPLACE_ALLOWED_ORIGIN_REGEX@@" in active and "example" not in active


def test_csp_is_report_only_first():
    """R11."""
    spec = next(s for s in build(finding("headers.security", "http://h/",
                                         "missing:content-security-policy"))
                if s.format == "nginx")
    assert "Content-Security-Policy-Report-Only" in spec.content
    assert not re.search(r'add_header Content-Security-Policy "', spec.content)
    assert "enforce" in spec.content.lower()


def test_login_throttle_does_not_break_routing_and_is_scoped():
    """R1, R2."""
    rows = synthetic_rows()
    ng = next(r for r in rows if r.format == "nginx" and "rate-limit logins" in r.title)
    assert "location" not in ng.content.replace("no location", "")
    assert "POST" in ng.content and "limit_req zone=" in ng.content
    m = re.search(r'"~\*(\^POST:[^"]+)"', ng.content)
    rx = re.compile("(?i)" + m.group(1))
    for k in ("POST:/login", "POST:/login/", "POST:/LOGIN", "post:/Login/"):
        assert rx.search(k), k
    for k in ("GET:/login", "POST:/login/x", "POST:/loginx", "POST:/api/login"):
        assert not rx.search(k), k
    ms = next(r for r in rows if r.format == "modsecurity" and "throttle logins" in r.title)
    assert H.lint_modsecurity(ms.content) == []
    c = ms.content
    assert '"@streq POST"' in c and "(?i)^/login/?$" in c           # POST only, scoped
    assert c.count("expirevar") == 1 and "&IP:" in c                # set when created only
    assert "tx.vigilo_ip_" in c and "X-Forwarded-For" in c          # configurable key
    assert not re.search(r'SecRule REMOTE_ADDR "@rx \."', c)        # not on every request
    assert "initcol" in c and c.index("initcol") > c.index("@streq POST")


def test_admin_paths_are_restricted_by_source_not_denied():
    """R7."""
    rows = synthetic_rows()
    ng = next(r for r in rows if r.format == "nginx" and "restrict" in r.title)
    ap = next(r for r in rows if r.format == "apache" and "restrict" in r.title)
    assert "@@REPLACE_ADMIN_NETWORK@@" in ng.content and "Require ip" in ap.content
    assert "return 403" in ng.content and "return 404" not in ng.content
    assert not [r for r in rows if r.format == "modsecurity" and "admin" in r.content]
    assert gd.classify("/admin/").level == "medium"       # not constant CRITICAL


def test_cookie_defaults_are_per_cookie_and_spare_script_readable_ones():
    """R10."""
    rows = synthetic_rows()
    ng = next(r for r in rows if r.format == "nginx" and "cookie flags" in r.title)
    assert "proxy_cookie_flags session httponly samesite=lax;" in ng.content
    assert "proxy_cookie_flags ~" not in ng.content
    assert "XSRF-TOKEN httponly" not in ng.content and "XSRF-TOKEN samesite=lax" in ng.content
    assert "xsrf" in ng.rationale.lower() or "XSRF" in ng.rationale
    # finding level: no proxy rule that would break a CSRF cookie
    specs = build(finding("cookies.flags", "http://h/", "csrftoken:missing-httponly"))
    assert not [s for s in specs if s.format in ("nginx", "apache")]


def test_https_redirect_uses_the_real_host():
    """R16."""
    rows = synthetic_rows()
    ng = next(r for r in rows if r.format == "nginx" and "redirect" in r.title)
    assert "server_name 127.0.0.1;" in ng.content and "example.com" not in ng.content
    assert "@@" not in ng.content


def test_headers_and_dirlisting_have_no_bare_location():
    """R2 class: a location without proxy_pass would stop routing."""
    for s in build(finding("exposure.dirlisting", "http://h:80/static/")):
        assert not re.search(r"^\s*location\b", s.content, re.M)
    for r in synthetic_rows():
        if r.format == "nginx":
            assert not re.search(r"^\s*location\b", r.content, re.M), r.title


def test_every_recommendation_leads_with_a_vendor_neutral_policy():
    rows = synthetic_rows()
    assert rows and all(r.rationale.startswith("Policy: ") for r in rows)
    for s in build(finding("exposure.files", "http://h:80/.git/HEAD", "/.git/HEAD")):
        assert s.rationale.startswith("Policy: ") or s.format == "text"


def test_linters_catch_what_the_old_validator_missed():
    """The linters fail the defects R1-R5 (so a regression is visible)."""
    bare = "location = /login {\n    limit_req zone=z burst=5 nodelay;\n}\n"
    assert any("location" in e for e in H.lint_nginx(bare, "server", allow_placeholders=True))
    mixed = ('map $uri $v { default 0; }\nlocation / { proxy_pass http://x; }\n'
             'server_tokens off;\nserver_tokens on;\n')
    errs = H.lint_nginx(mixed, "server")
    assert any("map is not allowed in server" in e for e in errs)
    assert any("duplicate" in e for e in errs)
    assert H.lint_nginx("add_header X 1;\nadd_header X 2;\n", "server")
    assert H.lint_nginx("server_tokens off\n", "server")                      # no ;
    assert H.lint_nginx("map $a $b { default 0;\n", "http")                   # unbalanced
    assert H.lint_nginx("if ($nope) { return 404; }\n", "server")             # undefined var
    old_ms = ('SecRule REMOTE_ADDR "@rx ." "id:1,phase:1,t:none,pass,nolog,'
              'initcol:ip=%{REMOTE_ADDR}"\n')
    assert any("outside the Vigilo block" in e for e in H.lint_modsecurity(old_ms))
    assert H.lint_modsecurity('SecRule X "@rx (" "id:8100001,phase:1,pass"\n')
    assert H.lint_modsecurity('SecRule ARGS "@rx a" "id:8100001,phase:1,pass"\n'
                              'SecRule ARGS "@rx a" "id:8100001,phase:1,pass"\n')
    assert H.lint_modsecurity('SecRule ARGS "@rx a" "id:8100001,phase:1,pass,chain"\n')
    assert H.lint_modsecurity('SecRule ARGS "@rx a" "id:8100001,phase:1,pass" "x"\n')   # args
    assert H.lint_apache("<DirectoryMatch \"/\\.git\">\nRequire all denied\n")      # open
    assert H.lint_apache("ServerTokens Prod\n", "vhost")                      # context
    assert H.lint_apache('Header always edit Set-Cookie "(" "x"\n')
    bad_sigma = yaml.safe_dump({"title": "t", "id": str(uuid.uuid4()), "status": "test",
                                "description": "d", "date": "2026/01/01", "tags": [],
                                "falsepositives": ["authorised"], "level": "low",
                                "logsource": {"category": "webserver"},
                                "detection": {"selection": {"cs-uri-stem": "/x"},
                                              "condition": "selection"}})
    assert any("portable vocabulary" in e for e in H.lint_sigma(bad_sigma))


def test_statement_merge_and_coverage():
    a = "# vigilo-service: http://h:80\nproxy_cookie_flags session httponly;\n"
    b = "proxy_cookie_flags session httponly samesite=lax;\n"
    assert gd.covered("nginx", a, [b]) and not gd.covered("nginx", b, [a])
    s1, s2 = gd.nginx_statements(a)[0], gd.nginx_statements(b)[0]
    assert gd.merge_pcf(s1, s2).body == "proxy_cookie_flags session httponly samesite=lax;"
    assert gd.covered("apache", "Header always set X-Frame-Options \"SAMEORIGIN\"\n",
                      ["# c\nHeader always set X-Frame-Options \"DENY\"\n"]) is False


def test_bundle_assembly_splits_contexts_and_dedupes():
    rows = synthetic_rows()
    rows += [GreyboxDefense(**{**{c.name: getattr(rows[0], c.name)
                                  for c in GreyboxDefense.__table__.columns},
                               "id": uuid.uuid4()}) for _ in range(2)]     # exact duplicates
    files = api_defenses.build_files(rows, "synth")
    assert {"nginx.conf", "nginx-server.conf", "apache.conf", "apache-vhost.conf",
            "modsecurity.conf", "sigma.yml"} <= set(files)
    assert re.search(r"^map ", files["nginx.conf"], re.M)
    assert not re.search(r"^map ", files["nginx-server.conf"], re.M)
    assert files["nginx-server.conf"].count("server_tokens off;") <= 1
    assert files["nginx-server.conf"].count("add_header X-Frame-Options") == 1
    assert re.search(r"^<VirtualHost", files["apache.conf"], re.M)
    assert not re.search(r"^<VirtualHost", files["apache-vhost.conf"], re.M)
    assert re.search(r"^ServerTokens", files["apache.conf"], re.M)
    assert not re.search(r"^ServerTokens", files["apache-vhost.conf"], re.M)
    assert H.lint_bundle(files) == []
    # every placeholder is documented and listed in the file header
    for name, text in files.items():
        for tok in gd.placeholders(text):
            assert tok in gd.REQUIRED_EDITS, tok
            if name != "sigma.yml":
                assert f"#   {tok}" in text.split("\n\n", 1)[0], (name, tok)


# ------------------------------------------------------------------ tier 1: a real run


async def _bundle(client, token, rid, **params) -> dict[str, str]:
    r = await client.get(f"/greybox/runs/{rid}/defenses/download", headers=h(token),
                         params={"format": "all", **params})
    assert r.status_code == 200, r.text
    return H.read_zip(r.content)


async def test_run_bundle_passes_every_linter(client, user_token, done_run):
    files = await _bundle(client, user_token, done_run["id"])
    assert H.lint_bundle(files) == []
    assert "README.txt" in files and "REQUIRED EDITS" in files["README.txt"]
    ms = files["modsecurity.conf"]
    assert "Rollback: SecRuleRemoveById" in ms and "BEFORE" in ms
    # pySigma when installed: validators and conversion (skipped cleanly otherwise)
    res = H.pysigma_check(files["sigma.yml"])
    if res != ["skip"]:
        assert res == [], res
    sp = H.pysigma_splunk(files["sigma.yml"])
    if sp != ["skip"]:
        assert sp == [], sp


async def test_unverified_rules_stay_out_of_the_default_bundle(client, user_token,
                                                               done_run, session_maker):
    from sqlalchemy import select
    rid = uuid.UUID(done_run["id"])
    async with session_maker() as s:
        rows = (await s.scalars(select(GreyboxDefense).where(
            GreyboxDefense.run_id == rid, GreyboxDefense.format == "sigma"))).all()
        assert rows
        for row in rows:
            row.status = "unverified"
        await s.commit()
    default = await _bundle(client, user_token, done_run["id"])
    assert "sigma.yml" not in default
    opted = await _bundle(client, user_token, done_run["id"], include_unverified=True)
    assert "[UNVERIFIED finding]" in opted["sigma.yml"]
    assert "INCLUDED" in opted["README.txt"]


async def test_report_lists_no_duplicate_defense(client, user_token, done_run):
    """R15: no finding/asset-scope duplicates, no repeated block."""
    md = (await client.get(f"/greybox/runs/{done_run['id']}/report",
                           headers=h(user_token))).json()["markdown"]
    section = md.split("## Detection and WAF suggestions", 1)[1].split("\n## ", 1)[0]
    blocks = re.findall(r"```(?:nginx|apache|yaml|text|modsecurity)?\n(.*?)\n```", section,
                        re.S)
    norm = [" ".join(b.split()) for b in blocks]
    assert len(norm) == len(set(norm)), "a defense block is printed twice"
    assert sum("add_header Content-Security-Policy-Report-Only" in b for b in blocks) <= 1
    assert sum("Header always set Content-Security-Policy-Report-Only" in b
               for b in blocks) <= 1
    assert "covered by the network-wide recommendation" in md


# ------------------------------------------------------------------ tier 2: syntax


@needs_nginx
def test_nginx_t_on_the_synthetic_bundle():
    files = api_defenses.build_files(synthetic_rows(), "synth")
    with H.Stack("nginx", files, 9) as st:  # started: also proves it loads
        assert st.get("/")[0] in (200, 502)
    # the old flat layout (everything in one file) does not load: the harness can fail
    flat = {"nginx.conf": files["nginx.conf"] + files["nginx-server.conf"]}
    bad = H.Stack("nginx", flat, 9)
    try:
        ok, out = bad.check()
        assert not ok and "not allowed here" in out
    finally:
        import shutil
        shutil.rmtree(bad.tmp, ignore_errors=True)


@needs_nginx
async def test_nginx_t_on_the_run_bundle(client, user_token, done_run):
    files = await _bundle(client, user_token, done_run["id"])
    st = H.Stack("nginx", files, 9)
    try:
        ok, out = st.check()
        print("nginx -t:", out)
        assert ok, out
    finally:
        import shutil
        shutil.rmtree(st.tmp, ignore_errors=True)


@needs_httpd
def test_httpd_t_on_the_synthetic_bundle():
    files = api_defenses.build_files(synthetic_rows(), "synth")
    st = H.Stack("apache", files, 9)
    try:
        ok, out = st.check()
        print("httpd -t:", out)
        assert ok and "Syntax OK" in out, out
    finally:
        import shutil
        shutil.rmtree(st.tmp, ignore_errors=True)


@needs_httpd
async def test_httpd_t_on_the_run_bundle(client, user_token, done_run):
    files = await _bundle(client, user_token, done_run["id"])
    st = H.Stack("apache", files, 9)
    try:
        ok, out = st.check()
        assert ok and "Syntax OK" in out, out
    finally:
        import shutil
        shutil.rmtree(st.tmp, ignore_errors=True)


# ------------------------------------------------------------------ tier 2: live replay


def _replay_failures(st: "H.Stack", recorded: list[dict], baseline: "H.Stack",
                     restricted: frozenset[str] = frozenset()) -> list[str]:
    """Positive: every recorded request that exposed something is now blocked or fixed;
    negative: every recorded baseline crawl request still gets its status class —
    except paths the platform itself put in a restrict-by-source class (administrative
    or diagnostic), where being refused is the defense working, not a broken replay."""
    fails: list[str] = []
    probes = [r for r in recorded if r["tool"].startswith("exposure.files")
              and r["status"] == 200 and r["method"] == "GET" and r["findings"]]
    assert probes, "the run recorded no exposed-file request to replay"
    for r in probes:
        direct = baseline.get(r["target"], headers=r["headers"])[0]
        got = st.get(r["target"], headers=r["headers"])[0]
        if direct != 200:
            fails.append(f"baseline {r['target']} not served without rules ({direct})")
        if not blocked(got):
            fails.append(f"vulnerable request {r['target']} not blocked ({got})")
    crawl = [r for r in recorded if r["tool"].startswith("discovery.")
             and r["method"] == "GET" and r["status"] and 200 <= r["status"] < 400
             and "/slow" not in r["target"]]
    assert len(crawl) >= 5, "the run recorded too few crawl requests"
    for r in crawl:
        got = st.get(r["target"], headers=r["headers"])[0]
        path = urlsplit(r["target"]).path.rstrip("/") or "/"
        if path in restricted:
            if not blocked(got):
                fails.append(f"restricted crawl request {r['target']} not refused ({got})")
        elif got // 100 != r["status"] // 100:
            fails.append(f"crawl request {r['target']} broke: {r['status']} -> {got}")
    return fails


async def _live(kind, client, user_token, done_run, target_server, session_maker):
    from urllib.parse import urlsplit
    port = urlsplit(target_server.url).port
    files = await _bundle(client, user_token, done_run["id"])
    recorded = await H.recorded_requests(client, h(user_token), done_run["id"])
    restricted = await _restricted_paths(session_maker, uuid.UUID(done_run["id"]))
    with H.Stack(kind, files, port) as st, H.Stack(kind, {}, port, with_bundle=False) as bare:
        fails = _replay_failures(st, recorded, bare, restricted)
        # fixed, not blocked: headers, banner, cookies, CORS
        s, hd, _ = st.get("/")
        for name in ("x-content-type-options", "x-frame-options", "referrer-policy",
                     "content-security-policy-report-only"):
            if name not in hd:
                fails.append(f"header {name} missing after the fix")
        if "content-security-policy" in hd:
            fails.append("CSP is enforced: it must be report-only first")
        if any("DemoServer" in v for v in hd.get("server", [])):
            fails.append(f"banner still shown: {hd.get('server')}")
        _, hd, _ = st.get("/login")
        sc = " ".join(hd.get("set-cookie", [])).lower()
        if "httponly" not in sc or "samesite=lax" not in sc:
            fails.append(f"session cookie flags not applied: {sc!r}")
        # CORS: an unknown origin gets nothing, the configured one is allowed
        evil = {"Origin": "https://evil.invalid"}
        _, hd, _ = bare.get("/api/data", headers=evil)
        assert hd.get("access-control-allow-origin") == ["https://evil.invalid"]   # vulnerable
        _, hd, _ = st.get("/api/data", headers=evil)
        if "access-control-allow-origin" in hd or "access-control-allow-credentials" in hd:
            fails.append(f"evil origin still allowed: {hd}")
        _, hd, _ = st.get("/api/data", headers={"Origin": "https://allowed.test"})
        if hd.get("access-control-allow-origin") != ["https://allowed.test"]:
            fails.append(f"allowed origin not honoured: {hd}")
        # administrative path: restricted by source (network 192.0.2.0/24 in the test)
        if not blocked(st.get("/admin/")[0]):
            fails.append("/admin/ reachable from a non-admin address")
    return fails


@needs_nginx
async def test_nginx_live_replay_of_the_recorded_run(client, user_token, done_run,
                                                     target_server, session_maker):
    fails = await _live("nginx", client, user_token, done_run, target_server,
                        session_maker)
    assert not fails, "\n".join(fails)


@needs_httpd
async def test_apache_live_replay_of_the_recorded_run(client, user_token, done_run,
                                                      target_server, session_maker):
    fails = await _live("apache", client, user_token, done_run, target_server,
                        session_maker)
    assert not fails, "\n".join(fails)


def _evasion_failures(kind: str) -> list[str]:
    files = api_defenses.build_files(synthetic_rows(), "synth")
    server, port = H.serve_lenient()
    fails: list[str] = []
    try:
        with H.Stack(kind, {}, port, with_bundle=False) as bare, \
                H.Stack(kind, files, port) as st, \
                H.Stack(kind, files, port, admin_network="127.0.0.1/32") as inside:
            # control: without the rules every evasion reaches the backend
            for label, p in H.REPO_EVASIONS + H.ENV_EVASIONS:
                got = bare.get(p)[0]
                if got != 200:
                    fails.append(f"control: {label} {p} -> {got} (test would prove nothing)")
            for label, p in H.REPO_EVASIONS + H.ENV_EVASIONS + [
                    ("backup", "/a/DB.SQL"), ("non-ascii archive", "/caf%C3%A9.zip"),
                    ("non-ascii upper", "/caf%C3%A9.ZIP"), ("archive slash", "/caf%C3%A9.zip/")]:
                got = st.get(p)[0]
                if not blocked(got):
                    fails.append(f"evasion not blocked: {label} {p} -> {got}")
            for p in H.COLLATERAL + ["/other.zip", "/db.sqlite", "/login", "/api/data"]:
                got = st.get(p)[0]
                if got != 200:
                    fails.append(f"collateral damage: {p} -> {got}")
            for p in ("/admin/", "/ADMIN", "/admin;x=1/y", "//admin/z", "/%61dmin/"):
                if not blocked(st.get(p)[0]):
                    fails.append(f"admin path reachable from a foreign address: {p}")
                if inside.get(p)[0] != 200:
                    fails.append(f"admin path blocked for the allowed network: {p}")
            if kind == "nginx":
                post = {"method": "POST", "body": b"user=a&password=b",
                        "headers": {"Content-Type": "application/x-www-form-urlencoded"}}
                codes = [st.get("/login", **post)[0] for _ in range(10)]
                if codes[0] == 429 or 429 not in codes:
                    fails.append(f"login throttle did not engage: {codes}")
                for p in ("/Login", "/login/", "/LOGIN/"):
                    if st.get(p, **post)[0] != 429:
                        fails.append(f"throttle bypassed with {p}")
                if st.get("/login")[0] != 200:
                    fails.append("GET /login was throttled (page views must not count)")
                if st.get("/x")[0] != 200:
                    fails.append("routing broke after the throttle")
    finally:
        server.should_exit = True
    return fails


@needs_nginx
def test_nginx_blocks_evasions_and_keeps_collateral_free():
    fails = _evasion_failures("nginx")
    assert not fails, "\n".join(fails)


@needs_httpd
def test_apache_blocks_evasions_and_keeps_collateral_free():
    fails = _evasion_failures("apache")
    assert not fails, "\n".join(fails)


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
