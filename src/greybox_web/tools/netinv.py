"""Network capability: service inventory over an authorised address set (the non-web
assessment path).

Three agent-invoked tools, all through ``ctx.net`` (``netcap.GuardedNet``: scope,
inert payloads, pacing, audit) — never a socket of their own:

``net.sweep``    connect to the authorised (address, port) pairs — the whole
                 boundary or a subset the agent names — and read what each open
                 service says first. Conservative: one connection per pair, the
                 scope's rate, a hard cap on attempts, no payload.
``net.probe``    one service, optionally with one inert identification hello
                 (``crlf``, ``http_head``, ``redis_ping``, ``smtp_quit``): how the
                 agent investigates a service the sweep could not identify.
``net.resolve``  DNS for an authorised name.

What they return is evidence, not verdicts: host and ``tcp://host:port`` service
assets (host → service), one observation per service with its banner and the
identification, and findings ONLY where the evidence itself shows the issue:

* a remote-administration protocol that is cleartext by design (telnet, FTP) is
  reachable — misconfiguration;
* a data store (Redis, MongoDB, Memcached, Elasticsearch, databases) is reachable
  from the assessment network — misconfiguration (segmentation), and a Redis that
  answers ``PING`` without authentication — vulnerability, re-verified by the
  engine with the same inert probe;
* a banner discloses the exact product version — hardening.

Everything else (is that OpenSSH version affected by a known issue? is that port
meant to be reachable from here?) is the agent's reasoning, recorded as hypotheses
and, where it needs computation, as tools it writes itself.
"""
from __future__ import annotations

import re
from typing import Any

from src.greybox_web.tools import (
    AssetSpec,
    EdgeSpec,
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    VerifyResult,
)

MAX_ATTEMPTS = 512
PROBES = ("crlf", "http_head", "redis_ping", "smtp_quit", "memcached_version",
          "smtp_ehlo", "ftp_feat")

# port -> protocol hint (only a hint: the banner wins)
PORT_HINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 587: "smtp", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2375: "docker", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http",
    8443: "https", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
# banner regex -> (protocol, product-group or None)
BANNERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^SSH-\d\.\d+-(?P<product>[A-Za-z0-9_.\-]+)"), "ssh"),
    (re.compile(r"^220[ -].*\bFTP\b|^220[ -].*FileZilla|^220[ -].*vsFTPd", re.I), "ftp"),
    (re.compile(r"^220[ -].*\b(E?SMTP|Postfix|Exim|Sendmail)\b", re.I), "smtp"),
    (re.compile(r"^\+OK\b.*POP", re.I), "pop3"),
    (re.compile(r"^\* OK\b.*IMAP", re.I), "imap"),
    (re.compile(r"^HTTP/\d\.\d \d{3}"), "http"),
    (re.compile(r"^\+PONG"), "redis"),
    (re.compile(r"^-NOAUTH|^-ERR .*auth", re.I), "redis"),
    (re.compile(r"^RFB \d{3}\.\d{3}"), "vnc"),
    (re.compile(r"^VERSION \d+\.\d+"), "memcached"),
    (re.compile(r"^STAT (pid|uptime|version) "), "memcached"),
    (re.compile(r"(?i)login:\s*$|^\xff[\xfb-\xfe]"), "telnet"),
)
VERSION_RE = re.compile(r"(?P<product>[A-Za-z][A-Za-z0-9_\-]{1,30})[/_ -]"
                        r"(?P<version>\d+(?:\.\d+){1,3}[A-Za-z0-9.\-]*)")
CLEARTEXT_ADMIN = {"telnet": "Telnet", "ftp": "FTP"}
DATA_STORES = {"redis": "Redis", "mongodb": "MongoDB", "memcached": "Memcached",
               "elasticsearch": "Elasticsearch", "mysql": "MySQL",
               "postgresql": "PostgreSQL", "mssql": "Microsoft SQL Server",
               "oracle": "Oracle Database", "docker": "Docker Engine API"}


def identify(port: int, banner: str) -> dict[str, Any]:
    """Protocol, product and version from a banner (port only as a fallback)."""
    first = banner.splitlines()[0][:300] if banner else ""
    protocol, how = None, None
    for rx, proto in BANNERS:
        if first and rx.search(first if proto != "telnet" else banner[:300]):
            protocol, how = proto, "banner"
            break
    if protocol is None and port in PORT_HINTS:
        protocol, how = PORT_HINTS[port], "port"
    out: dict[str, Any] = {"protocol": protocol or "unknown",
                           "identified_by": how or "none"}
    m = VERSION_RE.search(first)
    if m:
        out["product"] = m.group("product")
        out["version"] = m.group("version")
    return out


def smtp_capabilities(banner: str) -> dict[str, Any] | None:
    """The EHLO answer of an SMTP banner exchange (``250-…`` lines), or None."""
    lines = [ln[4:].strip().upper() for ln in banner.splitlines()
             if re.match(r"^250[ -]", ln)]
    if not lines:
        return None
    caps = set(" ".join(lines).split())
    auth = [ln for ln in lines if ln.startswith("AUTH")]
    return {"starttls": "STARTTLS" in caps,
            "auth": auth[0][4:].strip().split() if auth else [],
            "extensions": lines[:20]}


def _host_key(host: str) -> str:
    return host.lower()


def _service_key(host: str, port: int) -> str:
    return f"tcp://{host.lower()}:{port}"


def _targets(ctx: ToolContext) -> tuple[list[str], list[int], list[str]]:
    net = ctx.scope.network
    hosts_param = ctx.params.get("targets")
    ports_param = ctx.params.get("ports")
    errors: list[str] = []
    if net is None:
        return [], [], ["this assessment has no network scope"]
    hosts = [str(h) for h in hosts_param] if isinstance(hosts_param, list) \
        else (net.addresses() + list(net.names))
    ports = [int(p) for p in ports_param if str(p).isdigit()] \
        if isinstance(ports_param, list) else list(net.ports)
    return hosts, ports, errors


def _service_assets(host: str, port: int, res, ident: dict) -> list[AssetSpec]:
    banner = res.banner.decode("latin-1")[:400]
    return [
        AssetSpec("host", _host_key(host), True, host,
                  data={"resolved_ip": res.resolved_ip, "kind": "network_host"},
                  tested=True),
        AssetSpec("service", _service_key(host, port), True,
                  f"{ident['protocol']} on {host}:{port}",
                  data={"transport": "tcp", "port": port, "state": res.state,
                        "banner": banner, **ident},
                  parent=("host", _host_key(host)), tested=True),
    ]


def _findings(host: str, port: int, res, ident: dict) -> list[FindingSpec]:
    """Only what the evidence itself shows (see the module docstring)."""
    out: list[FindingSpec] = []
    banner = res.banner.decode("latin-1")
    key = _service_key(host, port)
    proto = ident["protocol"]
    ev = [Evidence(role="proof", exchange_id=res.exchange_id,
                   excerpt=f"tcp://{host}:{port} state={res.state} "
                           f"sent={res.sent or '-'} banner={banner[:200]!r}")]
    if proto in CLEARTEXT_ADMIN and ident["identified_by"] == "banner":
        name = CLEARTEXT_ADMIN[proto]
        out.append(FindingSpec(
            check_id="net.cleartext", detail=f"{proto}|{key}",
            title=f"Cleartext remote-access protocol exposed: {name} on port {port}",
            severity="medium", confidence="high",
            description=(f"{host}:{port} accepts {name} connections and greeted the "
                         f"assessment with {banner[:80]!r}. {name} sends credentials "
                         f"and session content unencrypted, so anyone on the network "
                         f"path can capture them."),
            url=key, cwe="CWE-319", evidence=ev, asset_ref=("service", key),
            finding_class="misconfiguration",
            verify={"host": host, "port": port, "expect": proto},
            remediation={
                "summary": f"Disable {name} and use an encrypted equivalent "
                           f"({'SSH' if proto == 'telnet' else 'SFTP/FTPS'}).",
                "steps": [f"Stop and disable the {name} service on {host}.",
                          "If it must stay, restrict it to a management network with "
                          "a host firewall / security group.",
                          "Rotate credentials that may have been used over it."],
                "validation": [f"A TCP connection to {host}:{port} is refused or "
                               f"filtered from this network segment.",
                               "Re-run net.probe on the port: state must not be "
                               "'open'."],
                "severity_rationale": "Credential exposure requires a network-path "
                                      "attacker; no exploit was attempted."}))
    if proto in DATA_STORES:
        name = DATA_STORES[proto]
        if proto == "redis" and banner.startswith("+PONG"):
            out.append(FindingSpec(
                check_id="net.unauthenticated", detail=f"redis|{key}",
                title=f"Redis answers commands without authentication on {host}:{port}",
                severity="high", confidence="high",
                description=(f"An inert PING to {host}:{port} returned '+PONG' with no "
                             f"authentication. Any client that can reach this port can "
                             f"read and modify the data set (and, depending on "
                             f"configuration, write files on the host). Only PING was "
                             f"sent; no data was read or changed."),
                url=key, cwe="CWE-306", evidence=ev, asset_ref=("service", key),
                finding_class="vulnerability",
                verify={"host": host, "port": port, "expect": "redis_pong"},
                remediation={
                    "summary": "Require authentication and stop exposing Redis to "
                               "this network.",
                    "steps": ["Set `requirepass` (or Redis 6+ ACL users with "
                              "`user default off`).",
                              "Bind to localhost / the application subnet only "
                              "(`bind 127.0.0.1 ::1`, `protected-mode yes`).",
                              "Firewall the port from every network that does not "
                              "host a legitimate client.",
                              "Rename or disable dangerous commands (CONFIG, "
                              "MODULE, DEBUG) for application users."],
                    "validation": ["`redis-cli -h <host> -p <port> PING` from this "
                                   "segment returns NOAUTH or cannot connect.",
                                   "Re-run net.probe with probe=redis_ping."],
                    "reproduction": [f"Send the bytes 'PING\\r\\n' to {host}:{port}; "
                                     f"an unauthenticated server answers '+PONG'."],
                    "severity_rationale": "Unauthenticated read/write access to a "
                                          "data store, reachable over the network."}))
    if proto == "memcached" and re.match(r"^(VERSION \d|STAT )", banner):
        out.append(FindingSpec(
            check_id="net.unauthenticated", detail=f"memcached|{key}",
            title=f"Memcached answers commands without authentication on "
                  f"{host}:{port}",
            severity="high", confidence="high",
            description=(f"An inert 'version' command to {host}:{port} was answered "
                         f"({banner.splitlines()[0][:60]!r}) without any "
                         f"authentication. Memcached's text protocol then also "
                         f"serves stored items (often session data) and accepts "
                         f"writes and flushes from any client that can reach the "
                         f"port. Only 'version' was sent; no item was read or "
                         f"changed."),
            url=key, cwe="CWE-306", evidence=ev, asset_ref=("service", key),
            finding_class="vulnerability",
            verify={"host": host, "port": port, "expect": "memcached_version"},
            remediation={
                "summary": "Stop exposing memcached to this network and require "
                           "authentication where it must be reachable.",
                "steps": ["Bind memcached to localhost or the application subnet "
                          "(`-l 127.0.0.1`), disable UDP (`-U 0`).",
                          "Firewall the port from every network without a legitimate "
                          "client.",
                          "Where remote access is required, enable SASL "
                          "authentication (`-S`) and TLS."],
                "validation": [f"From this segment, {host}:{port} is refused or "
                               "filtered, or 'version' gets an authentication error.",
                               "Re-run net.probe with probe=memcached_version."],
                "reproduction": [f"Send 'version\\r\\n' to {host}:{port}; an "
                                 "unauthenticated server answers 'VERSION x.y.z'."],
                "severity_rationale": "Unauthenticated access to a cache that "
                                      "typically holds sessions, reachable over the "
                                      "network."}))
    caps = smtp_capabilities(banner) if proto == "smtp" else None
    if caps is not None and caps["auth"] and not caps["starttls"]:
        out.append(FindingSpec(
            check_id="net.cleartext", detail=f"smtp-auth|{key}",
            title=f"SMTP offers authentication without STARTTLS on {host}:{port}",
            severity="medium", confidence="high",
            description=(f"The EHLO answer of {host}:{port} advertises AUTH "
                         f"{' '.join(caps['auth'])} but no STARTTLS: clients can "
                         f"only send their credentials in cleartext (PLAIN/LOGIN are "
                         f"base64, not encryption). Only EHLO and QUIT were sent."),
            url=key, cwe="CWE-319", evidence=ev, asset_ref=("service", key),
            finding_class="misconfiguration",
            verify={"host": host, "port": port, "expect": "smtp_auth_cleartext"},
            remediation={
                "summary": "Offer STARTTLS (or implicit TLS on 465) and only allow "
                           "AUTH after TLS.",
                "steps": ["Configure a certificate and enable STARTTLS (Postfix: "
                          "`smtpd_tls_security_level = may`, cert/key files).",
                          "Allow AUTH only over TLS (Postfix: "
                          "`smtpd_tls_auth_only = yes`)."],
                "validation": ["The EHLO answer lists STARTTLS and no AUTH before TLS "
                               "(re-run net.probe with probe=smtp_ehlo)."]}))
    # Product/version remains service inventory, not a security finding.
    return out


async def _scan(ctx: ToolContext, pairs: list[tuple[str, int]], probe: str | None,
                ) -> ToolResult:
    assets: list[AssetSpec] = []
    observations: list[Observation] = []
    findings: list[FindingSpec] = []
    states: dict[str, int] = {}
    refused: list[str] = []
    for host, port in pairs:
        res = await ctx.net.tcp(host, port, send=probe)
        states[res.state] = states.get(res.state, 0) + 1
        if res.state == "blocked":
            refused.append(f"{host}:{port} ({res.reason})")
            continue
        if res.state != "open":
            continue
        banner = res.banner.decode("latin-1")
        ident = identify(port, banner)
        assets += _service_assets(host, port, res, ident)
        observations.append(Observation(
            key=f"net.service|{_service_key(host, port)}"[:300],
            label=f"{ident['protocol']} service open on {host}:{port}",
            facts={"host": host, "port": port, "banner": banner[:300],
                   "sent": res.sent, **ident},
            exchange_ids=[res.exchange_id] if res.exchange_id else []))
        if probe:
            # the probe's own record (the service observation above is updated in
            # place; this one belongs to THIS work order and its results)
            observations.append(Observation(
                key=f"net.probe|{_service_key(host, port)}|{probe}"[:300],
                label=f"{probe} to {host}:{port}: {ident['protocol']}"
                      + (f" ({banner[:60]!r})" if banner else " (no answer)"),
                facts={"host": host, "port": port, "probe": probe,
                       "answer": banner[:300], **ident},
                exchange_ids=[res.exchange_id] if res.exchange_id else []))
        findings += _findings(host, port, res, ident)
    hosts_up = sorted({h for h, _ in pairs})
    summary = (f"{len(pairs)} connection attempt(s): "
               + ", ".join(f"{n} {s}" for s, n in sorted(states.items()))
               + (f"; refused by policy: {', '.join(refused[:5])}" if refused else ""))
    observations.append(Observation(
        key=f"net.sweep|{len(pairs)}|{','.join(hosts_up[:4])}"[:300],
        label=f"network sweep: {states.get('open', 0)} open of {len(pairs)}",
        facts={"attempts": len(pairs), "states": states, "refused": refused[:20],
               "probe": probe}))
    return ToolResult(summary=summary[:300], counts={"attempts": len(pairs), **states},
                      observations=observations, findings=findings, assets=assets,
                      edges=[EdgeSpec("contains", ("host", a.parent[1]),
                                      ("service", a.key))
                             for a in assets if a.kind == "service" and a.parent])


async def sweep(ctx: ToolContext) -> ToolResult:
    """``net.sweep {targets?, ports?, max_attempts?}``."""
    if ctx.net is None or ctx.scope.network is None:
        return ToolResult(summary="net.sweep not applicable: this assessment has no "
                                  "network scope")
    hosts, ports, errs = _targets(ctx)
    cap = min(int(ctx.params.get("max_attempts") or MAX_ATTEMPTS), MAX_ATTEMPTS)
    pairs = [(h, p) for h in hosts for p in ports][:cap]
    if not pairs:
        return ToolResult(summary="net.sweep: nothing to connect to "
                                  + "; ".join(errs))
    return await _scan(ctx, pairs, None)


async def probe(ctx: ToolContext) -> ToolResult:
    """``net.probe {host, port, probe?}``."""
    if ctx.net is None:
        return ToolResult(summary="net.probe not applicable: no network capability")
    host = str(ctx.params.get("host") or "")
    try:
        port = int(ctx.params.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    return await _scan(ctx, [(host, port)], ctx.params.get("probe") or None)


async def resolve(ctx: ToolContext) -> ToolResult:
    """``net.resolve {name}``."""
    if ctx.net is None:
        return ToolResult(summary="net.resolve not applicable: no DNS capability")
    name = str(ctx.params.get("name") or "")
    r = await ctx.net.resolve(name)
    obs = Observation(key=f"net.dns|{name}"[:300],
                      label=f"DNS {name}: {', '.join(r.addresses) or r.reason}",
                      facts=r.as_dict(),
                      exchange_ids=[r.exchange_id] if r.exchange_id else [])
    assets = [AssetSpec("host", _host_key(name), True, name,
                        data={"addresses": r.addresses, "kind": "network_host"})] \
        if r.addresses else []
    return ToolResult(summary=f"{name} -> {', '.join(r.addresses) or r.reason}",
                      observations=[obs], assets=assets)


async def verify(ctx: ToolContext) -> VerifyResult:
    """Independent re-probe for every ``net.*`` finding: the same inert exchange
    must show the same property again."""
    host = str(ctx.params.get("host") or "")
    port = int(ctx.params.get("port") or 0)
    expect = str(ctx.params.get("expect") or "open")
    if ctx.net is None:
        return VerifyResult(False, "net re-probe", "no network capability")
    if expect.startswith("tls_"):
        return await verify_tls(ctx, host, port, expect)
    probe_name = {"redis_pong": "redis_ping", "memcached_version": "memcached_version",
                  "smtp_auth_cleartext": "smtp_ehlo"}.get(expect)
    res = await ctx.net.tcp(host, port, send=probe_name)
    banner = res.banner.decode("latin-1")
    ident = identify(port, banner)
    ok = {"redis_pong": res.state == "open" and banner.startswith("+PONG"),
          "open": res.state == "open",
          "version": res.state == "open" and bool(ident.get("version")),
          "memcached_version": res.state == "open"
          and bool(re.match(r"^VERSION \d", banner)),
          "smtp_auth_cleartext": res.state == "open" and bool(
              (c := smtp_capabilities(banner)) and c["auth"] and not c["starttls"]),
          }.get(expect, res.state == "open" and ident["protocol"] == expect)
    return VerifyResult(
        confirmed=bool(ok), method=f"tcp re-probe {host}:{port}"
                                   + (f" ({probe_name})" if probe_name else ""),
        note=f"state={res.state} banner={banner[:120]!r}",
        exchange_ids=[res.exchange_id] if res.exchange_id else [],
        excerpt=banner[:300])


# ------------------------------------------------------------------ TLS


def tls_findings(host: str, port: int, r) -> list[FindingSpec]:
    """Certificate/protocol properties the handshake itself shows."""
    cert = r.certificate or {}
    if r.state != "ok" or not cert:
        return []
    key = _service_key(host, port)
    ev = [Evidence(role="proof", exchange_id=r.exchange_id,
                   excerpt=(f"tls://{host}:{port} {r.protocol} subject={cert.get('subject')}"
                            f" issuer={cert.get('issuer')} notAfter="
                            f"{cert.get('not_after')} trusted={r.trusted}"
                            + (f" ({r.trust_error})" if r.trust_error else ""))[:500])]
    out = []
    problems = []
    if cert.get("expired"):
        problems.append(f"expired on {cert['not_after'][:10]}")
    if cert.get("not_yet_valid"):
        problems.append(f"not valid before {cert['not_before'][:10]}")
    if cert.get("self_signed"):
        problems.append("self-signed")
    if problems:
        out.append(FindingSpec(
            check_id="net.tls", detail=f"certificate|{key}",
            title=f"TLS certificate on {host}:{port} is {' and '.join(problems)}",
            severity="medium", confidence="high",
            description=(f"The service presents {cert.get('subject')} issued by "
                         f"{cert.get('issuer')}, valid {cert.get('not_before', '')[:10]}"
                         f" – {cert.get('not_after', '')[:10]}. Clients cannot "
                         f"authenticate the server; users are trained to click "
                         f"through warnings, which enables interception. Chain "
                         f"validation against the system trust store: "
                         f"{r.trust_error or 'failed'}."),
            url=key, cwe="CWE-295", evidence=ev, asset_ref=("service", key),
            finding_class="misconfiguration",
            verify={"host": host, "port": port,
                    "expect": "tls_expired" if cert.get("expired") else "tls_untrusted"},
            remediation={
                "summary": "Install a valid certificate from a trusted CA and "
                           "automate its renewal.",
                "steps": ["Issue a certificate for the service's name from the "
                          "organisation's CA or a public CA (ACME).",
                          "Automate renewal and alert well before expiry."],
                "validation": ["A verifying client (`openssl s_client -verify_return_"
                               "error`) accepts the certificate; net.tls reports "
                               "trusted=true and not expired."]}))
    if r.protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(FindingSpec(
            check_id="net.tls", detail=f"protocol|{key}",
            title=f"Deprecated TLS protocol negotiated on {host}:{port} ({r.protocol})",
            severity="medium", confidence="high",
            description=f"The handshake negotiated {r.protocol}, deprecated by RFC 8996.",
            url=key, cwe="CWE-327", evidence=ev, asset_ref=("service", key),
            finding_class="misconfiguration",
            verify={"host": host, "port": port, "expect": "tls_old_protocol"},
            remediation={"summary": "Allow TLS 1.2 and 1.3 only.",
                         "steps": ["Disable TLS 1.0/1.1 in the server configuration."],
                         "validation": ["net.tls negotiates TLSv1.2 or TLSv1.3."]}))
    return out


async def tls(ctx: ToolContext) -> ToolResult:
    """``net.tls {host, port, server_name?}``: one TLS handshake (plus a verifying
    one); the certificate and protocol become service facts."""
    if ctx.net is None or not hasattr(ctx.net, "tls"):
        return ToolResult(summary="net.tls not applicable: no network capability")
    host = str(ctx.params.get("host") or "")
    try:
        port = int(ctx.params.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    r = await ctx.net.tls(host, port, server_name=ctx.params.get("server_name") or None)
    key = _service_key(host, port)
    facts = r.as_dict()
    obs = Observation(key=f"net.tls|{key}"[:300],
                      label=f"TLS {host}:{port}: {r.state} {r.protocol or ''} "
                            f"trusted={r.trusted}",
                      facts=facts,
                      exchange_ids=[r.exchange_id] if r.exchange_id else [])
    assets = [AssetSpec("service", key, True, f"tls on {host}:{port}",
                        data={"transport": "tcp", "port": port, "tls": {
                            k: facts.get(k) for k in ("protocol", "cipher", "trusted",
                                                      "certificate")}},
                        parent=("host", _host_key(host)), tested=True),
              AssetSpec("host", _host_key(host), True, host,
                        data={"kind": "network_host"}, tested=True)] \
        if r.state == "ok" else []
    findings = tls_findings(host, port, r)
    return ToolResult(
        summary=(f"TLS {host}:{port}: {r.state}"
                 + (f", {r.protocol}, {(r.certificate or {}).get('subject')}, trusted="
                    f"{r.trusted}" if r.state == "ok" else f" ({r.reason})"))[:300],
        counts={"findings": len(findings)}, observations=[obs], assets=assets,
        findings=findings)


async def verify_tls(ctx: ToolContext, host: str, port: int, expect: str) -> VerifyResult:
    r = await ctx.net.tls(host, port)
    cert = r.certificate or {}
    ok = r.state == "ok" and {
        "tls_expired": bool(cert.get("expired")),
        "tls_untrusted": r.trusted is False,
        "tls_old_protocol": r.protocol in ("TLSv1", "TLSv1.1", "SSLv3"),
    }.get(expect, False)
    return VerifyResult(confirmed=bool(ok), method=f"tls re-handshake {host}:{port}",
                        note=f"{r.state} {r.protocol} expired={cert.get('expired')} "
                             f"trusted={r.trusted}",
                        exchange_ids=[r.exchange_id] if r.exchange_id else [],
                        excerpt=str(cert.get("subject") or "")[:200])
