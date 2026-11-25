---
name: network-recon
description: Inventory an authorised network segment — hosts, services, protocols, products, authentication and transport security — and turn it into evidence-backed exposure findings.
when: the assessment mode is network (an address set with ports), or a web run discovers non-HTTP services worth identifying.
requires: [tcp_connect]
modes: [network]
phases:
  - {id: A, title: Inventory}
  - {id: B, title: Identify and characterise}
  - {id: C, title: Exposure and configuration}
  - {id: D, title: Conclude}
criteria:
  - id: swept
    phase: A
    text: The authorised boundary swept (every listed host × port has a state)
    evidence: {tool_done: [net.sweep]}
  - id: identified
    phase: B
    text: Every open service identified by its own answer (banner or an inert hello), not only by port number
    evidence: {any: [{tool_done: [net.probe]}, {tool_done: ["tool.*"]}]}
  - id: transport
    phase: B
    text: Transport security of TLS-capable or credential-carrying services examined (certificate, protocol, cleartext authentication)
    evidence: {any: [{tool_done: [net.tls]}, {tool_done: ["tool.*"]}]}
  - id: authentication
    phase: C
    text: For each service, whether it requires authentication established from its own answers (or recorded as untestable without an authentication attempt)
  - id: exposure
    phase: C
    text: Each service judged for whether it should be reachable from this segment (data stores, admin consoles, telemetry)
  - id: verified
    phase: D
    text: Every reported weakness re-verified by the engine or left as a candidate with the reason
  - id: limits
    phase: D
    text: Services that could not be identified, and checks that would need an authentication attempt or an unsupported protocol, recorded
---
# network-recon — what is listening, what is it, and should it be?

The boundary is `run.network` (addresses, ports, protocols). Nothing outside it
is reachable; neighbouring addresses and unlisted ports are never tried.

## Phase A — Inventory
- `net.sweep` over the whole boundary once: each (host, port) gets a state
  (open / closed / filtered) and, for talkative services, a banner.
- Group by host: what role does each host seem to have (gateway, application,
  data, legacy)? Several services on one host tell you its role.

## Phase B — Identify and characterise
- A banner identifies the protocol and often the product/version. A silent
  service needs a hello that fits what the port and context suggest:
  `http_head` (web, metrics, admin consoles), `redis_ping`, `memcached_version`,
  `smtp_ehlo` (capabilities: STARTTLS, AUTH), `ftp_feat`, `crlf` (generic).
  Never identify by port number alone when the service can answer.
- An answer that is TLS (handshake bytes, "plain HTTP sent to HTTPS port"), or a
  service that carries credentials: `net.tls` for the certificate (subject,
  issuer, validity, self-signed, chain trust) and the negotiated protocol.
- HTTP services on the segment: examine them with the HTTP tools when
  `run.capabilities` includes http (headers, what `/` and well-known paths
  expose: `/metrics`, `/status`, `/server-status`, `/actuator`).
- An unfamiliar protocol: write a tool (`tool.compose` with `tcp_connect`) that
  sends one of the inert hellos and parses the answer — never a custom payload.

## Phase C — Exposure and configuration
For each service decide, from evidence:
- **Authentication**: answered a data command without credentials (`+PONG`,
  `VERSION`, `STAT`) → unauthenticated; answered with an authentication error
  (`-NOAUTH`, `FATAL 28000`, `401` + `WWW-Authenticate`) → authentication
  required (a negative result, worth recording). Proving that a login works
  (anonymous FTP, default passwords) is an authentication attempt: only with
  `allow_auth_testing`; otherwise record it as untested.
- **Transport**: cleartext protocols carrying credentials (telnet, FTP, SMTP AUTH
  without STARTTLS, HTTP Basic over http), expired/self-signed/untrusted
  certificates, deprecated TLS versions.
- **Exposure**: data stores, caches, telemetry and admin consoles reachable from
  this segment are an exposure even when authenticated; say who should reach them.
- **Disclosure**: versions in banners (hardening), internal names/addresses in
  answers (metrics, error pages).

## Phase D — Conclude
- Classes: unauthenticated data access → vulnerability; exposure, weak transport,
  certificate problems → misconfiguration; version disclosure → hardening.
- One finding per root cause per service. A correctly configured service is
  coverage, not a finding.
- Record what could not be identified and why (silent, no applicable hello,
  authentication attempt not authorised).

## Alternatives when a method stalls
| Stalled | Switch to |
|---|---|
| Silent port | try the hello that fits the context, then `crlf`; record "unidentified" if still silent |
| TLS port | `net.tls`; then HTTP tools over https if allowed |
| Banner is generic | the protocol's capability/feature hello (`smtp_ehlo`, `ftp_feat`) |
| Need to parse a binary answer | write a tool with `tcp_connect` and an inert hello |

## Definition of done
`swept`, `identified` and `transport` are engine-checked. Claim
`authentication`, `exposure`, `verified` and `limits` in `criteria` with the
observation keys (`net.probe|…`, `net.tls|…`) or finding titles that support them.
