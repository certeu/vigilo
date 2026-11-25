"""Vendor-neutral recommendations from the passive network signals.

Asset-scoped defenses (kind ``hardening``, format ``text``) derived from a service's
``data.surface`` (``third_party``, ``leaks``, ``edge``, ``http``) and from the findings
the passive analysis produced (``supply.no_sri``, ``supply.mixed_content``,
``info.leak``). They are *policies and checklists*: no vendor, product or WAF-engine
specific syntax (maintainer decision), and nothing is requested to produce them.

Same hygiene as ``defenses.py``: every target-derived value is validated (host names
against a strict charset, everything else reduced by ``_label``), nothing hostile reaches
the text, and ``defenses._final`` redacts the result again. Called from
``defenses.build_for_assets`` through :func:`build` (one call).
"""
from __future__ import annotations

import re
from typing import Any

_HOST = re.compile(r"[a-z0-9][a-z0-9.\-]{0,252}")


def _hosts(values: list[Any], limit: int = 10) -> list[str]:
    """Host names safe to quote: strict charset, no scheme, no spaces."""
    return [h for h in (str(v).lower() for v in values) if _HOST.fullmatch(h)][:limit]


def _list(items: list[str]) -> str:
    return "".join(f"  - {i}\n" for i in items)


def build(services, endpoints, findings, run_id=None) -> list:
    """``[defenses.AssetSpec]`` for the services' passive network surfaces."""
    from src.greybox_web import defenses as D
    out: list = []
    for svc in services:
        s = (svc.data or {}).get("surface")
        if not isinstance(s, dict) or "third_party" not in s:
            continue
        eps = endpoints.get(svc.id, [])
        ids = {e.id for e in eps} | {svc.id}
        origin = D._origin(svc.key)
        mark = f"# vigilo-service: {origin}\n" if origin else ""
        where = D._label(svc.label)
        https = bool((s.get("tls") or {}).get("https"))

        def add(title: str, why: str, policy: str, body: str,
                prefixes: tuple[str, ...] = (), confidence: str = "medium") -> None:
            out.append(D.AssetSpec(svc, D.DefenseSpec(
                "hardening", "text", title, why, mark + body, confidence, policy),
                D._fids(findings, ids, prefixes) if prefixes else []))

        # ---- third-party content: CSP (report-only first) and SRI
        tp = s.get("third_party") or {}
        origins = _hosts([o.get("host") for o in tp.get("top", []) if isinstance(o, dict)])
        if tp.get("origins") and origins:
            no_sri = int(tp.get("scripts_without_sri") or 0)
            add(f"Restrict and pin third-party content for {where}",
                f"{where} loads content from {tp['origins']} origin(s) outside its own "
                f"scope ({', '.join(origins[:5])}); {no_sri} script reference(s) carry no "
                "Subresource Integrity. These URLs were recorded from page markup and "
                "never requested, so the hashes below must be computed by you. ",
                "Allow only the third-party origins you rely on, pin the scripts you keep "
                "with Subresource Integrity, and prefer self-hosting vetted copies of "
                "critical scripts.",
                "Third-party content checklist\n"
                "1. Inventory. Origins observed in page markup:\n" + _list(origins)
                + "   Remove every origin you no longer use.\n"
                "2. Content-Security-Policy, report-only first. Build the policy from the "
                "inventory (for example script-src 'self' plus the origins you keep), "
                "deliver it as Content-Security-Policy-Report-Only with a reporting "
                "endpoint you operate, review the reports, then enforce it.\n"
                "3. Subresource Integrity for every third-party script and stylesheet "
                "you keep: add integrity=\"sha384-<hash>\" crossorigin=\"anonymous\" to the tag. "
                "Compute the hash over the exact file you reviewed, for example: "
                "openssl dgst -sha384 -binary <file> | openssl base64 -A\n"
                "4. Prefer a vetted self-hosted copy for critical scripts, and re-review "
                "when the version changes.\n"
                "5. Re-run the assessment to confirm the origins and integrity "
                "attributes now match.\n",
                ("supply.no_sri",), "high" if no_sri else "medium")

        # ---- mixed content
        mc = tp.get("mixed_content") or {}
        if (mc.get("active") or 0) + (mc.get("passive") or 0) > 0:
            add(f"Serve every subresource of {where} over https",
                f"Pages of {where} reference http:// subresources "
                f"({mc.get('active', 0)} active, {mc.get('passive', 0)} passive). A network "
                "attacker can read them and, for scripts, stylesheets and frames, modify "
                "them and take over the page. ",
                "Load every subresource over https and tell browsers to upgrade any "
                "leftover http reference.",
                "Mixed content checklist\n"
                "1. Change every http:// reference in templates, stored content and "
                "configuration to https:// (or to a scheme-independent path on the same "
                "origin). Active content first: scripts, stylesheets, frames.\n"
                "2. As a safety net send the Content-Security-Policy directive "
                "upgrade-insecure-requests so browsers rewrite remaining http "
                "subresource URLs.\n"
                "3. Confirm the third-party origin actually serves https; if it does "
                "not, stop using it or host the file yourself.\n"
                "4. Check the browser console of the affected pages for remaining "
                "mixed-content warnings.\n",
                ("supply.mixed_content",), "high")

        # ---- internal host names and addresses
        lk = s.get("leaks") or {}
        seen = _hosts(lk.get("internal_hosts") or [], 6) \
            + [v for v in (lk.get("private_ips") or []) if re.fullmatch(r"[0-9a-f:.]{3,45}", str(v))][:6]
        if lk.get("count") and seen:
            add(f"Stop disclosing internal host names and addresses from {where}",
                f"Responses of {where} disclose {lk['count']} internal host name(s) or "
                "address(es) in headers or page bodies. Internal names help an attacker "
                "map the network behind the service. The values were only recorded, "
                "never contacted. ",
                "Do not expose internal host names or addresses in responses; rewrite "
                "or remove them before a response leaves the trust boundary.",
                "Internal disclosure checklist\n"
                "Observed values (verify before acting):\n" + _list(seen)
                + "1. Remove upstream and backend identification headers (for example "
                "headers naming the backend server, node or upstream) at the reverse "
                "proxy or edge.\n"
                "2. Rewrite redirect Location headers, cookie domains and absolute URLs "
                "so they use the public host name, never an internal one.\n"
                "3. Strip internal names and addresses from error pages, HTML comments, "
                "API responses, source maps and debug output; disable verbose errors in "
                "production.\n"
                "4. Alert on responses that contain private address ranges or your "
                "internal domain suffixes (log the response header or body match, "
                "do not block until tuned).\n"
                "5. Re-run the assessment to confirm the values are gone.\n",
                ("info.leak",), "high")

        # ---- HSTS preload readiness
        http = s.get("http") or {}
        hsts = http.get("hsts")
        if https and isinstance(hsts, dict) and not hsts.get("preload_ready"):
            gaps = []
            if int(hsts.get("max_age") or 0) < 31536000:
                gaps.append("max-age is below one year (31536000 seconds)")
            if not hsts.get("include_subdomains"):
                gaps.append("includeSubDomains is missing")
            if not hsts.get("preload"):
                gaps.append("the preload token is missing")
            add(f"HSTS preload checklist for {where}",
                f"{where} sends Strict-Transport-Security but it is not preload-ready: "
                + "; ".join(gaps) + ". Readiness is computed from the header only; the "
                "preload list itself was not consulted. ",
                "Send a long-lived HSTS policy covering all subdomains, and submit the "
                "domain to browser preload lists only when every subdomain serves https.",
                "HSTS preload checklist\n"
                "1. Serve a valid certificate on the apex and on every subdomain, and "
                "redirect http to https on the same host first.\n"
                "2. Send Strict-Transport-Security on every https response with "
                "max-age of at least 31536000, includeSubDomains and preload.\n"
                "3. Roll out gradually: start with a short max-age, raise it as you "
                "gain confidence.\n"
                "4. Submit the domain to the browser preload lists only when all "
                "subdomains (including internal ones that resolve publicly) support "
                "https; removal from the lists is slow.\n", confidence="medium")

        # ---- HTTP/3 advertised
        if http.get("h3_advertised"):
            add(f"Apply the same filtering to HTTP/3 (UDP 443) for {where}",
                f"Responses of {where} advertise HTTP/3 through Alt-Svc. HTTP/3 runs "
                "over UDP; filtering that only covers TCP 443 can be bypassed. ",
                "Treat UDP 443 like TCP 443: same access control, inspection and "
                "logging, or disable HTTP/3 where that is not possible.",
                "HTTP/3 checklist\n"
                "1. Confirm whether HTTP/3 is intended on this service.\n"
                "2. If yes, allow UDP 443 to the same destinations as TCP 443 and make "
                "sure the WAF, proxy or edge inspects HTTP/3 traffic like HTTP/2.\n"
                "3. If it is not intended, remove the Alt-Svc header and block UDP 443.\n"
                "4. Ensure logs record HTTP/3 requests with the same fields.\n")

        # ---- edge / CDN / WAF in front of the service
        edge = s.get("edge") or {}
        if edge.get("providers"):
            waf = edge.get("waf") or {}
            sigs = ", ".join(_hosts([x.replace(":", "-") for x in
                                     (edge.get("evidence") or [])], 6)) or "headers"
            cache = edge.get("cache") or {}
            sens = [D._np(p) for p in (cache.get("sensitive_cacheable") or [])
                    if str(p).startswith("/")][:5]
            body = ("Edge service checklist\n"
                    "1. Accept traffic for the origin only from the edge service "
                    "(network allow-list or mutual TLS), so the edge cannot be "
                    "bypassed by addressing the origin directly.\n"
                    "2. Restore the real client address in origin logs: trust the "
                    "forwarded-client-address header only from the edge's published "
                    "ranges, so detection and rate limits see real clients.\n"
                    "3. Confirm the WAF policy is in blocking mode for the rules you "
                    "rely on (start in detection mode, tune, then enforce) and review "
                    "its logs.\n")
            if waf.get("state") == "detected":
                body += ("   No blocked response was observed during this run, so "
                         "enforcement is unconfirmed.\n")
            if sens:
                body += ("4. Responses for these sensitive paths looked cacheable at "
                         "the edge; send Cache-Control: private, no-store and exclude "
                         "them from caching:\n" + _list(sens))
            add(f"Review edge and WAF configuration for {where}",
                f"Signals consistent with an edge, CDN or WAF in front of {where} were "
                f"recorded ({sigs}). Attribution is a hint from response headers, not "
                "proof, and nothing was probed to confirm it. ",
                "Make sure the origin is reachable only through the edge, that client "
                "addresses are preserved, and that the WAF enforces its policy.", body)

        # ---- redirects that leave the service insecurely
        bad = [r for r in (http.get("cross_host_redirects") or [])
               if isinstance(r, dict) and (r.get("downgrade") or r.get("ip")
                                           or not r.get("in_scope"))]
        targets = _hosts([r.get("to") for r in bad], 6)
        if bad and targets:
            add(f"Review redirects leaving {where}",
                f"{where} redirects to another host ({', '.join(targets[:3])}"
                + (", including a downgrade from https to http" if any(
                    r.get("downgrade") for r in bad) else "")
                + "). The destinations were recorded, never requested. ",
                "Redirect only to hosts you control, over https, by host name.",
                "Redirect checklist\n"
                "Destinations observed:\n" + _list(targets)
                + "1. Confirm each destination is intended and owned by the same "
                "organisation.\n"
                "2. Never redirect from https to http; never redirect to an IP "
                "address literal.\n"
                "3. Where the destination is a different host, make sure it enforces "
                "https and sends HSTS.\n")
    return out
