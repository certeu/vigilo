---
name: hardening
description: Turn observed configuration and exposure into prioritised, verifiable defensive recommendations, kept distinct from vulnerabilities.
when: towards the end of any assessment (web or network), or when configuration, headers, banners or exposed services were observed.
requires: []
modes: [web, network]
phases:
  - {id: A, title: Collect configuration evidence}
  - {id: B, title: Formulate recommendations}
criteria:
  - id: config-web
    phase: A
    text: Response headers, cookies and disclosure examined on the main services
    evidence: {tool_done: [headers.security, headers.disclosure, cookies.flags]}
    na_when: {mode_not: [web]}
  - id: exposure-network
    phase: A
    text: Exposed services inventoried with protocol and version
    evidence: {tool_done: [net.sweep, net.probe]}
    na_when: {mode_not: [network]}
  - id: classified
    phase: B
    text: Each recommendation classified (misconfiguration / hardening / informational), never inflated into a vulnerability
  - id: verifiable
    phase: B
    text: Each recommendation states how to implement it and how to verify it
  - id: observability
    phase: B
    text: Logging, monitoring and detection opportunities proposed where evidence supports them
---
# hardening — useful advice, honestly classified

Defensive recommendations are part of the deliverable, but they are not
vulnerabilities. A missing CSP is hardening; a cookie without `Secure` on an HTTPS
site is a misconfiguration; neither is "critical".

## Phase A — Collect configuration evidence
Web: security headers (`headers.security`), disclosure (`headers.disclosure`),
cookies (`cookies.flags`, `browser.cookies`), CORS, error pages, TLS/redirect
behaviour, third-party script integrity. Network: every exposed service, its
protocol, product and version (`net.sweep`, `net.probe`), cleartext protocols, authentication posture for data stores, management interfaces. Reachability and product/version alone are inventory, not findings.

## Phase B — Recommendations
For each observation that justifies advice:
- **Class**: misconfiguration (an insecure setting weakening a control),
  hardening (defence in depth), informational. A weakness becomes a vulnerability
  only with evidence of exploitability (api-security / verified findings).
- **What and where**: the exact setting and component ("set `Secure; HttpOnly;
  SameSite=Lax` on `sid` in the session middleware"; "bind Redis to 127.0.0.1 and
  set `requirepass`").
- **Verify**: a concrete retest ("response header contains
  `Strict-Transport-Security: max-age=31536000`"; "TCP connection to :6379 from
  the user network is refused").
- **Observability**: what to log or alert on, tied to what you saw (failed login
  bursts on the observed login API, access to `/admin`, 401→200 sequences across
  ids, connections to the data store from non-application hosts).
- Least privilege: services and roles that expose more than their function needs.

Findings you write through `tool.compose` take `class` and `remediation`
({summary, steps, validation}); built-in checks already carry them.

## Alternatives when a method stalls
| Stalled | Switch to |
|---|---|
| A check is not available in this run | derive the advice from recorded traffic (netview.reexamine / broker.recorded) |
| No configuration evidence for a service | say so; do not invent recommendations |

## Definition of done
`config-web` / `exposure-network` are engine-checked (one of them is not applicable
depending on the target). Claim `classified`, `verifiable` and `observability`
citing finding titles or observation keys.
