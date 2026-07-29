# Comprehensive Security Assessment Report

**Assessment Date:** 2026-07-09
**Models:** gpt-5.5
**Target:** no target URL - code-only analysis
**Repository:** /repos/target
**Branch:** master | **Commit:** ab57f75

## Table of Contents

- [Executive Summary](#executive-summary)
- [Status Legend](#status-legend)
- [Findings Overview](#findings-overview)
- [Systemic Root Causes](#systemic-root-causes)
- [Injection Vulnerabilities (7)](#injection-vulnerabilities)
- [Cross-Site Scripting (XSS) Vulnerabilities (1)](#cross-site-scripting-xss-vulnerabilities)
- [Authentication Vulnerabilities (6)](#authentication-vulnerabilities)
- [Server-Side Request Forgery (SSRF) Vulnerabilities (2)](#server-side-request-forgery-ssrf-vulnerabilities)
- [Authorization Vulnerabilities (19)](#authorization-vulnerabilities)
- [WebSocket Vulnerabilities (6)](#websocket-vulnerabilities)
- [Cryptography Vulnerabilities (5)](#cryptography-vulnerabilities)
- [Attack Chains](#attack-chains)
- [Supply Chain (SCA) Vulnerabilities (29)](#supply-chain-sca-vulnerabilities)
- [Unpatched Vulnerabilities](#unpatched-vulnerabilities)
- [Hardening Recommendations](#hardening-recommendations)

## Executive Summary

This code-only assessment covered the FastAPI backend, Next.js frontend, the datastore deployment configuration, WebSocket chat interface, asynchronous command/job paths, cryptographic/session design, and third-party dependency manifests. No live URL or authenticated runtime was provided, so public-interface exploitation was limited to source-to-sink validation, reproducible payload construction, dependency analysis, and review of deployment preconditions.

The highest-impact issues are concentrated around the shared-password security model, privileged asynchronous workflows, source ingestion, WebSocket chat, and deployment configuration. In passwordless deployments, the HTTP and WebSocket gates fail open; with a configured shared password, the same raw secret is persisted in browser storage and reused as a long-lived bearer and WebSocket token. Source ingestion and command paths expose file, URL, and worker-side primitives that could lead to local file disclosure, stored SSRF, arbitrary application-writable file effects, or local command execution when the corresponding workers/providers are enabled. The most realistic chains combine passwordless access, stored unsafe URL execution, reusable shared-password tokens, command dispatch, and SSRF-capable source processing.

The authoritative inventory contains 82 unique findings: 31 Critical, 32 High, 16 Medium, 3 Low, and 0 Informational. The category inventory includes 19 authorization findings, 29 supply-chain findings, 7 injection findings, and 7 attack-chain findings. 31 findings are presented in the Hardening Recommendations appendix as code-quality, deployment-hygiene, or theoretical authorization-model improvements rather than directly exploitable vulnerabilities in the reviewed code-only context. The most important systemic patterns are the fail-open shared-password boundary, static shared-secret sessions, missing server-side authorization, absent URL/path confinement, and privileged asynchronous/tool-execution surfaces.

Prioritized remediation should focus on the systemic root causes: fail closed when authentication is not configured; replace the raw shared-password bearer model with server-issued revocable sessions; add server-side principals, RBAC/capability checks, and object relationship enforcement; centralize URL and filesystem confinement; restrict command/worker/tool execution behind admin capability checks and explicit deployment opt-in; keep the datastore private with strong credentials and encrypted transport; and enforce dependency upgrade governance in CI.

## Status Legend

| Status | Meaning |
|--------|---------|
| Exploited | Vulnerability was successfully exercised end-to-end. The exploitation evidence file documents a working payload, a concrete server response, and (where applicable) a screenshot. |
| Potential | Source-to-sink data flow is fully traced and the absence of every relevant defence is verified, but live execution was not performed (e.g. because no live target was available, the environment was code-only, or the exploit requires an external dependency such as a malicious server). |
| Unconfirmed (Analysis) | Identified by code analysis only. No exploit was attempted (typical of cryptographic findings - algorithm choice, key rotation policy, secret comparison method - which are classified by inspection rather than execution). |
| Unconfirmed | Code pattern matches a known weakness but the necessary preconditions for exploitation could not be confirmed in this engagement. |

## Findings Overview

### All Findings

| # | ID | Category | Severity | Title | Status | Fix |
|---|-----|----------|----------|-------|--------|-----|
| 1 | AUTHZ-VULN-01 | Authorization | Critical | Optional Shared Password Disables API Authorization | Potential | `fix/AUTH-VULN-01` |
| 2 | AUTH-VULN-02 | Authentication | High | Optional Password Disables WebSocket Authentication | Potential | `fix/AUTH-VULN-01` |
| 3 | AUTH-VULN-05 | Authentication | High | Shared Password Is Persisted as a Reusable Bearer Token | Potential | `fix/AUTH-VULN-05` |
| 4 | AUTHZ-VULN-02 | Authorization | High | Optional WebSocket Token Allows Anonymous Workspace Chat | Potential | `fix/AUTH-VULN-01` |
| 5 | AUTHZ-VULN-10 | Authorization | High | Chat Execute/Context Cross-Object Authorization Bypass | Potential | `fix/AUTHZ-VULN-09` |
| 6 | AUTHZ-VULN-11 | Authorization | High | WebSocket Client ID Spoofing and Arbitrary Document Context | Potential | `fix/AUTHZ-VULN-09` |
| 7 | AUTHZ-VULN-19 | Authorization | High | Command Dispatcher Exposed to Normal API Users | Potential | `fix/AUTHZ-VULN-18` |
| 8 | AUTHZ-VULN-20 | Authorization | High | Model Defaults and Settings Mutation Without Admin Guard | Potential | `fix/AUTHZ-VULN-18` |
| 9 | AUTHZ-VULN-23 | Authorization | High | Published the datastore Service Bypasses Application Authorization | Unconfirmed | `fix/AUTHZ-VULN-23` |
| 10 | CHAIN-001 | Attack Chains | High | Passwordless API Access to Server-Side File Read or Command Execution | Potential | None recorded |
| 11 | CHAIN-002 | Attack Chains | High | Stored Unsafe URL XSS to Shared Password Replay | Potential | None recorded |
| 12 | CHAIN-003 | Attack Chains | High | Stored XSS to WebSocket Token Replay and Client Identity Spoofing | Potential | None recorded |
| 13 | CHAIN-004 | Attack Chains | High | Adminless Command Dispatch to Lower-Level SSRF | Potential | None recorded |
| 14 | CHAIN-005 | Attack Chains | High | Source Local File Read to Cross-Object Data Exposure | Potential | None recorded |
| 15 | CHAIN-006 | Attack Chains | High | NoSQL Injection to IDOR-Accelerated Data Harvesting | Potential | None recorded |
| 16 | CHAIN-007 | Attack Chains | High | Published the datastore Defaults to Application Auth Bypass | Unconfirmed | None recorded |
| 17 | CRYPTO-002 | Cryptography | High | Authentication is disabled when `OPEN_WORKSPACE_PASSWORD` is unset | Potential | `fix/AUTH-VULN-01` |
| 18 | CRYPTO-004 | Cryptography | High | Sample database credentials include root/root for a published database service | Potential | `fix/AUTHZ-VULN-23` |
| 19 | INJ-VULN-01 | Injection | High | NoSQL Injection in Workspace Ordering | Potential | `fix/INJ-VULN-01` |
| 20 | INJ-VULN-03 | Injection | High | JSON `file_path` Local File Inclusion | Potential | `fix/INJ-VULN-02` |
| 21 | INJ-VULN-04 | Injection | High | Second-Order Arbitrary File Delete via Stored Source Path | Potential | `fix/INJ-VULN-02` |
| 22 | INJ-VULN-05 | Injection | High | Stored Path File Exfiltration to Provider File API | Potential | `fix/INJ-VULN-02` |
| 23 | INJ-VULN-06 | Injection | High | Media job `episode_name` Path Traversal | Potential | `fix/INJ-VULN-06` |
| 24 | INJ-VULN-08 | Injection | High | Agent-Mediated Command Injection in Document Export and Research Jobs | Potential | `fix/INJ-VULN-08` |
| 25 | SCA-VULN-003 | Supply Chain (SCA) | High | Multiple vulnerabilities in axios | Unconfirmed | None recorded |
| 26 | SCA-VULN-009 | Supply Chain (SCA) | High | Multiple vulnerabilities in next | Unconfirmed | None recorded |
| 27 | SSRF-VULN-03 | Server-Side Request Forgery (SSRF) | High | Generic Command Dispatch to Source Processor | Potential | `fix/SSRF-VULN-01` |
| 28 | SSRF-VULN-04 | Server-Side Request Forgery (SSRF) | High | Stored Source URL Retry Replay | Potential | `fix/SSRF-VULN-01` |
| 29 | WS-VULN-01 | WebSocket | High | Unknown | Potential | `fix/AUTH-VULN-01` |
| 30 | WS-VULN-03 | WebSocket | High | Unknown | Potential | `fix/AUTH-VULN-05` |
| 31 | WS-VULN-05 | WebSocket | High | Unknown | Potential | `fix/AUTHZ-VULN-09` |
| 32 | XSS-VULN-01 | Cross-Site Scripting (XSS) | High | Stored Unsafe URL Scheme in Source Link | Potential | `fix/SSRF-VULN-01` |
| 33 | AUTH-VULN-04 | Authentication | Medium | Public Admin Verification Has No Application-Layer Rate Limiting | Potential | `fix/AUTH-VULN-03` |
| 34 | AUTH-VULN-06 | Authentication | Medium | Logout Does Not Invalidate Server-Side Access | Potential | `fix/AUTH-VULN-05` |
| 35 | AUTH-VULN-07 | Authentication | Medium | WebSocket Token Is Replayed From URL | Potential | `fix/AUTH-VULN-05` |
| 36 | AUTH-VULN-08 | Authentication | Medium | WebSocket Session Identity Is Caller-Supplied | Potential | `fix/AUTHZ-VULN-09` |
| 37 | AUTHZ-VULN-18 | Authorization | Medium | Media job Profile Management Without Backend Admin Guard | Potential | `fix/AUTHZ-VULN-18` |
| 38 | AUTHZ-VULN-21 | Authorization | Medium | Embedding Rebuild Maintenance Operation Without Admin Guard | Potential | `fix/AUTHZ-VULN-18` |
| 39 | AUTHZ-VULN-22 | Authorization | Medium | Global Transformation Prompt Management Without Trusted-Author Guard | Potential | `fix/AUTHZ-VULN-18` |
| 40 | CRYPTO-001 | Cryptography | Medium | Shared application password is used directly as a long-lived bearer/WebSocket token | Potential | `fix/AUTH-VULN-05` |
| 41 | CRYPTO-003 | Cryptography | Medium | the datastore uses plaintext WebSocket transport while the database port is published | Potential | None recorded |
| 42 | INJ-VULN-07 | Injection | Medium | Transformation Prompt Server-Side Template Injection | Potential | `fix/INJ-VULN-07` |
| 43 | SCA-VULN-020 | Supply Chain (SCA) | Medium | LangChain: Path traversal and sandbox escape in LangChain file-search middleware and loaders | Unconfirmed | None recorded |
| 44 | SCA-VULN-021 | Supply Chain (SCA) | Medium | LangChain: Path traversal and sandbox escape in LangChain file-search middleware and loaders | Unconfirmed | None recorded |
| 45 | SCA-VULN-022 | Supply Chain (SCA) | Medium | langchain-openai: Image token counting SSRF protection can be bypassed via DNS rebinding | Unconfirmed | None recorded |
| 46 | SCA-VULN-023 | Supply Chain (SCA) | Medium | LangGraph checkpoint loading has unsafe msgpack deserialization | Unconfirmed | None recorded |
| 47 | WS-VULN-02 | WebSocket | Medium | Unknown | Potential | `fix/AUTHZ-VULN-09` |
| 48 | WS-VULN-04 | WebSocket | Medium | Unknown | Potential | `fix/AUTHZ-VULN-09` |
| 49 | WS-VULN-06 | WebSocket | Medium | Unknown | Potential | `fix/AUTHZ-VULN-09` |
| 50 | AUTHZ-VULN-04 | Authorization | Low | Cross-Workspace Source Attach/Detach | Unconfirmed (Analysis) | None recorded |
| 51 | AUTHZ-VULN-07 | Authorization | Low | Unauthorized Source Retry Side Effect | Unconfirmed (Analysis) | None recorded |
| 52 | AUTHZ-VULN-08 | Authorization | Low | Note IDOR for Read, Update, and Delete | Unconfirmed (Analysis) | None recorded |
| 53 | AUTHZ-VULN-12 | Authorization | Low | Source Chat Session Creation on Arbitrary Source | Unconfirmed (Analysis) | None recorded |
| 54 | AUTHZ-VULN-13 | Authorization | Low | Studio Job IDOR | Unconfirmed (Analysis) | None recorded |
| 55 | AUTHZ-VULN-14 | Authorization | Low | Cross-Workspace Studio Artifact Import | Unconfirmed (Analysis) | None recorded |
| 56 | AUTHZ-VULN-15 | Authorization | Low | Media job Episode IDOR | Unconfirmed (Analysis) | None recorded |
| 57 | AUTHZ-VULN-16 | Authorization | Low | Diagram IDOR | Unconfirmed (Analysis) | None recorded |
| 58 | AUTHZ-VULN-17 | Authorization | Low | Insight IDOR and Cross-Workspace Save-As-Note | Unconfirmed (Analysis) | None recorded |
| 59 | SCA-VULN-001 | Supply Chain (SCA) | Low | When Vitest UI server is listening, arbitrary file can be read and executed | Unconfirmed | None recorded |
| 60 | SCA-VULN-002 | Supply Chain (SCA) | Low | When Vitest UI server is listening, arbitrary file can be read and executed | Unconfirmed | None recorded |
| 61 | SCA-VULN-004 | Supply Chain (SCA) | Low | Regular Expression Denial of Service in FastAPI multipart form parsing | Unconfirmed | None recorded |
| 62 | SCA-VULN-005 | Supply Chain (SCA) | Low | Multiple vulnerabilities in flatted | Unconfirmed | None recorded |
| 63 | SCA-VULN-006 | Supply Chain (SCA) | Low | form-data: CRLF injection in form-data via unescaped multipart field names and filenames | Unconfirmed | None recorded |
| 64 | SCA-VULN-007 | Supply Chain (SCA) | Low | Multiple vulnerabilities in lodash | Unconfirmed | None recorded |
| 65 | SCA-VULN-008 | Supply Chain (SCA) | Low | Multiple vulnerabilities in minimatch | Unconfirmed | None recorded |
| 66 | SCA-VULN-010 | Supply Chain (SCA) | Low | Multiple vulnerabilities in picomatch | Unconfirmed | None recorded |
| 67 | SCA-VULN-011 | Supply Chain (SCA) | Low | Rollup 4 has Arbitrary File Write via Path Traversal | Unconfirmed | None recorded |
| 68 | SCA-VULN-012 | Supply Chain (SCA) | Low | Multiple vulnerabilities in setuptools | Unconfirmed | None recorded |
| 69 | SCA-VULN-013 | Supply Chain (SCA) | Low | Multiple vulnerabilities in tar | Unconfirmed | None recorded |
| 70 | SCA-VULN-014 | Supply Chain (SCA) | Low | Multiple vulnerabilities in vite | Unconfirmed | None recorded |
| 71 | SCA-VULN-015 | Supply Chain (SCA) | Low | Multiple vulnerabilities in ws | Unconfirmed | None recorded |
| 72 | SCA-VULN-016 | Supply Chain (SCA) | Low | ajv has ReDoS when using `$data` option | Unconfirmed | None recorded |
| 73 | SCA-VULN-017 | Supply Chain (SCA) | Low | brace-expansion: Zero-step sequence causes process hang and memory exhaustion | Unconfirmed | None recorded |
| 74 | SCA-VULN-018 | Supply Chain (SCA) | Low | follow-redirects leaks Custom Authentication Headers to Cross-Domain Redirect Targets | Unconfirmed | None recorded |
| 75 | SCA-VULN-019 | Supply Chain (SCA) | Low | JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases | Unconfirmed | None recorded |
| 76 | SCA-VULN-024 | Supply Chain (SCA) | Low | PostCSS has XSS via Unescaped </style> in its CSS Stringify Output | Unconfirmed | None recorded |
| 77 | SCA-VULN-025 | Supply Chain (SCA) | Low | PostCSS has XSS via Unescaped </style> in its CSS Stringify Output | Unconfirmed | None recorded |
| 78 | SCA-VULN-026 | Supply Chain (SCA) | Low | pytest has vulnerable tmpdir handling | Unconfirmed | None recorded |
| 79 | SCA-VULN-027 | Supply Chain (SCA) | Low | python-dotenv: Symlink following in set_key allows arbitrary file overwrite via cross-device rename fallback | Unconfirmed | None recorded |
| 80 | SCA-VULN-028 | Supply Chain (SCA) | Low | @babel/core: Arbitrary File Read via sourceMappingURL Comment | Unconfirmed | None recorded |
| 81 | SCA-VULN-029 | Supply Chain (SCA) | Low | @eslint/plugin-kit is vulnerable to Regular Expression Denial of Service attacks through ConfigCommentParser | Unconfirmed | None recorded |
| 82 | CRYPTO-005 | Cryptography | Informational | Chat client isolation can fall back to non-cryptographic `Math.random()` | Unconfirmed (Analysis) | None recorded |

### Findings by Category

| Category | Critical | High | Medium | Low | Informational | Total |
|----------|----------|------|--------|-----|---------------|-------|
| Injection | 6 | 1 | 0 | 0 | 0 | 7 |
| Cross-Site Scripting (XSS) | 1 | 0 | 0 | 0 | 0 | 1 |
| Authentication | 3 | 3 | 0 | 0 | 0 | 6 |
| Server-Side Request Forgery (SSRF) | 2 | 0 | 0 | 0 | 0 | 2 |
| Authorization | 17 | 2 | 0 | 0 | 0 | 19 |
| WebSocket | 0 | 4 | 2 | 0 | 0 | 6 |
| Cryptography | 0 | 2 | 2 | 1 | 0 | 5 |
| Attack Chains | 0 | 7 | 0 | 0 | 0 | 7 |
| Supply Chain (SCA) | 2 | 13 | 12 | 2 | 0 | 29 |

## Systemic Root Causes

The assessment surfaced 7 systemic patterns that account for the bulk of the actionable findings. These clusters identify the controls that will reduce the most risk when fixed centrally rather than one route at a time.

### Root Cause 1: Fail-Open Shared-Password Boundary

**Affected findings:** AUTH-VULN-02, AUTHZ-VULN-01, AUTHZ-VULN-02, CRYPTO-002, WS-VULN-01, CHAIN-001 (6 findings)

The application uses `OPEN_WORKSPACE_PASSWORD` as the primary HTTP and WebSocket security boundary, but both `api/auth.py` and `api/routers/ws_chat.py` allow access when the variable is unset. Because the application has no per-user server-side principal, passwordless deployment turns normal API and WebSocket routes into anonymous global access.

**Remediation:** Fail closed when no authentication provider or deployment password is configured. Require an explicit local-development opt-out, enforce startup checks in CI and deployment templates, and run integration tests that assert protected HTTP and WebSocket routes reject anonymous access by default.

### Root Cause 2: Static Shared Secret as Session Credential

**Affected findings:** AUTH-VULN-05, AUTH-VULN-06, AUTH-VULN-07, CRYPTO-001, WS-VULN-03, CHAIN-002, CHAIN-003 (7 findings)

The frontend stores the deployment password in `localStorage`, reuses it as the bearer token, and embeds it in WebSocket URLs. The backend has no server-issued session, expiry, revocation, nonce, or binding to a browser/client session.

**Remediation:** Issue opaque server-side sessions or signed short-lived tokens, prefer `HttpOnly`, `Secure`, `SameSite` cookies for browser state, add logout revocation, and authenticate WebSockets with cookies, headers, or one-time tickets rather than URL query parameters.

### Root Cause 3: Missing Server-Side Authorization Model

**Affected findings:** AUTHZ-VULN-10, AUTHZ-VULN-11, AUTHZ-VULN-18, AUTHZ-VULN-19, AUTHZ-VULN-20, AUTHZ-VULN-21, AUTHZ-VULN-22, AUTH-VULN-08, WS-VULN-04, WS-VULN-05 (10 findings)

Administrative and cross-object workflows rely on the same shared-password holder model. Routes in `api/routers/chat.py`, `api/routers/ws_chat.py`, profile/settings/model routers, and command/embedding routes do not enforce a server-side role, capability, owner, or workspace membership boundary before reading or mutating global objects.

**Remediation:** Introduce server-side principals and capabilities, centralize authorization helpers for workspace/object relationships and admin-only operations, and add route tests that exercise direct object IDs and cross-object workflow inputs with unauthorized callers.

### Root Cause 4: Absent URL, Scheme, and Path Confinement

**Affected findings:** INJ-VULN-03, INJ-VULN-04, INJ-VULN-05, INJ-VULN-06, SSRF-VULN-03, SSRF-VULN-04, XSS-VULN-01 (7 findings)

Several APIs accept paths or URLs and pass them to filesystem, browser-navigation, provider-upload, or outbound-fetch sinks without a shared allowlist and containment layer. The affected code includes source creation/retry, media job generation, provider file upload, and source detail navigation.

**Remediation:** Adopt shared path and URL validators: resolve filesystem paths under explicit roots, reject traversal and absolute paths where not needed, enforce `http`/`https` plus DNS/IP non-global checks for server fetches, reject dangerous browser navigation schemes, and add regression tests for each route that accepts a path or URL.

### Root Cause 5: Privileged Asynchronous and Tool-Execution Surfaces

**Affected findings:** INJ-VULN-08, AUTHZ-VULN-19, SSRF-VULN-03, CHAIN-004, INJ-VULN-09 (5 findings)

The application exposes asynchronous command, Studio, and research workflows that can trigger lower-level processing or local tool-enabled provider flows. User-controlled input can influence command arguments, source-processing state, and tool-capable report/research prompts.

**Remediation:** Treat command dispatch and tool-enabled provider flows as privileged operations. Require admin/capability checks, allowlist command names and argument schemas, separate user data from tool instructions, disable local shell tools by default, and require explicit deployment opt-in plus audit logging for tool-capable jobs.

### Root Cause 6: Dependency Version Governance Gaps

**Affected findings:** SCA-VULN-003, SCA-VULN-009, SCA-VULN-020, SCA-VULN-021, SCA-VULN-022, SCA-VULN-023 (6 findings)

Software Composition Analysis found vulnerable direct and transitive dependencies in Python and frontend manifests. Several are package/version findings where a reachable vulnerable library feature was not proven, but the dependency set still increases exposure and maintenance risk.

**Remediation:** Automate dependency updates with lockfile-aware SCA in CI, enforce maximum vulnerability age for production dependencies, distinguish dev-only from runtime packages, and require security review when package lower bounds permit vulnerable versions.

### Root Cause 7: Published Database Service and Default Credential Risk

**Affected findings:** AUTHZ-VULN-23, CRYPTO-003, CRYPTO-004, CHAIN-007 (4 findings)

`docker-compose.yml` publishes the datastore on host port `8000`, the app defaults to plaintext `ws://` database transport, and sample credentials include `root/root`. When deployed directly to an untrusted network, this places the database data plane outside the application authorization boundary.

**Remediation:** Keep the datastore on a private network, remove default host port publishing, require strong non-sample credentials, fail startup with known defaults, and use TLS or trusted network isolation for all database transport crossing host boundaries.

## Injection Vulnerabilities

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| INJ-VULN-01 | High | NoSQL Injection in Workspace Ordering | Potential |
| INJ-VULN-03 | High | JSON `file_path` Local File Inclusion | Potential |
| INJ-VULN-04 | High | Second-Order Arbitrary File Delete via Stored Source Path | Potential |
| INJ-VULN-05 | High | Stored Path File Exfiltration to Provider File API | Potential |
| INJ-VULN-06 | High | Media job `episode_name` Path Traversal | Potential |
| INJ-VULN-08 | High | Agent-Mediated Command Injection in Document Export and Research Jobs | Potential |
| INJ-VULN-07 | Medium | Transformation Prompt Server-Side Template Injection | Potential |

Injection risk spans NoSQL construction, filesystem path handling, template rendering, and local tool-enabled job flows. No live exploitation was possible, but the code paths show attacker-controlled input reaching query, file, template, and worker/tool boundaries without the required allowlists or containment checks.

### INJ-VULN-01: NoSQL Injection in Workspace Ordering

**Severity:** High
**Status:** Potential
**Location:** `api/routers/workspaces.py:17`, `api/routers/workspaces.py:22`, `api/routers/workspaces.py:30`, `api/routers/workspaces.py:53`, `webapp/database/repository.py:362`
**Preconditions:** valid shared password unless OPEN_WORKSPACE_PASSWORD is unset, public API route reachable, the datastore accepts attacker-controlled ORDER BY syntax sufficiently to alter the query
**Remediation Branch:** `fix/INJ-VULN-01`

**Description.** NoSQL Injection in Workspace Ordering affects `api/routers/workspaces.py:17`, `api/routers/workspaces.py:22`, `api/routers/workspaces.py:30`, `api/routers/workspaces.py:53`, `webapp/database/repository.py:362`. The finding is exploitable under the stated preconditions: valid shared password unless OPEN_WORKSPACE_PASSWORD is unset, public API route reachable, the datastore accepts attacker-controlled ORDER BY syntax sufficiently to alter the query. In this code-only assessment, the evidence supports a potential finding because the relevant source-to-sink path is present and no live target was available to exercise it end to end.

**Exploitation.**

**Evidence for `INJ-VULN-01`.**

**Summary:**
- **Vulnerable location:** `GET /api/workspaces?order_by=...`
- **Current Blocker:** No target URL, no bearer token status, and no live the datastore-backed application endpoint were provided.
- **Potential Impact:** NoSQL query manipulation and possible data extraction from application tables if the datastore accepts injected clause or stacked-query syntax through this client path.
- **Confidence:** HIGH

**Evidence of Vulnerability:**
The route accepts `order_by` as a raw string at `api/routers/workspaces.py:17`, interpolates it into `ORDER BY {order_by}` at `api/routers/workspaces.py:22-28`, executes the raw query with `repo_query(query)` at `api/routers/workspaces.py:30`, and returns exception text in the HTTP 500 detail at `api/routers/workspaces.py:52-53`. No field or direction allowlist was present in this path.

**Attempted Exploitation:**
No network exploitation attempt could be made because the scope contains no public target URL. Code validation confirmed the source-to-sink path, but no parser error, boolean differential, timing signal, table enumeration, or data extraction could be produced.

**How This Would Be Exploited:**
If a public target URL and required authorization were supplied:

1. Confirm normal behavior:
   ```bash
   curl -i -H 'Authorization: Bearer [SESSION_TOKEN]' \
     '[TARGET_URL]/api/workspaces?order_by=updated%20desc'
   ```
2. Probe NoSQL syntax control with the queued witness payload:
   ```bash
   curl -i -H 'Authorization: Bearer [SESSION_TOKEN]' \
     '[TARGET_URL]/api/workspaces?order_by=updated%20desc%3B%20SELECT%20*%20FROM%20source'
   ```
3. Use parser feedback from the 500 detail to adapt NoSQL payloads for schema enumeration and data extraction.

**Expected Impact:**
Successful exploitation would expose workspace/source/note/chat metadata and potentially cleartext document content stored in the datastore.

**Proof of impact.**

Successful exploitation would expose workspace/source/note/chat metadata and potentially cleartext document content stored in the datastore.

#### Remediation: INJ-VULN-01

**Remediation Branch:** `fix/INJ-VULN-01` (7eebcb2)

Replaced raw ORDER BY interpolation with an allowlisted sort field/direction parser and 400 rejection for invalid values.

**Files Changed:**
- `api/routers/workspaces.py`
- `tests/test_workspaces_api.py.`

**Validation:** pytest tests/test_workspaces_api.py passed (3 passed); ruff and git diff --check passed.

### INJ-VULN-03: JSON `file_path` Local File Inclusion

**Severity:** High
**Status:** Potential
**Location:** `api/models.py:295`, `api/routers/sources.py:324`, `webapp/graphs/source.py:122`, `webapp/graphs/source.py:134`, `webapp/graphs/source.py:159`
**Preconditions:** valid shared password unless OPEN_WORKSPACE_PASSWORD is unset, public API route reachable, local target file readable by application user, source processing completes and source can be retrieved
**Remediation Branch:** `fix/INJ-VULN-02`

**Description.** JSON `file_path` Local File Inclusion affects `api/models.py:295`, `api/routers/sources.py:324`, `webapp/graphs/source.py:122`, `webapp/graphs/source.py:134`, `webapp/graphs/source.py:159`. The finding is exploitable under the stated preconditions: valid shared password unless OPEN_WORKSPACE_PASSWORD is unset, public API route reachable, local target file readable by application user, source processing completes and source can be retrieved. In this code-only assessment, the evidence supports a potential finding because the relevant source-to-sink path is present and no live target was available to exercise it end to end.

**Exploitation.**

**Evidence for `INJ-VULN-03`.**

**Summary:**
- **Vulnerable location:** `POST /api/sources/json` with `{"type":"upload","file_path":"..."}`
- **Current Blocker:** No target URL, runtime file system, or source IDs were provided.
- **Potential Impact:** Read local files as the application user and persist extracted content in source records.
- **Confidence:** HIGH

**Evidence of Vulnerability:**
`SourceCreate.file_path` is a plain optional string in `api/models.py:295`. The JSON endpoint delegates to source creation at `api/routers/sources.py:555-559`; the route copies the supplied path into `content_state["file_path"]` at `api/routers/sources.py:318-324`. Source processing later reads from that path through CSV/plaintext handling at `webapp/graphs/source.py:120-135` or forwards it to `extract_content()` at `webapp/graphs/source.py:159`. Extracted content is saved to `source.full_text` at `webapp/graphs/source.py:181-183`.

**Attempted Exploitation:**
No API request could be made. Code validation confirmed direct assignment of caller-controlled `file_path` into file-reading processors without root confinement.

**How This Would Be Exploited:**
If a public target URL and required authorization were supplied:

1. Create a source pointing at a harmless local proof file such as `/etc/hosts`:
   ```bash
   curl -i -X POST -H 'Authorization: Bearer [SESSION_TOKEN]' \
     -H 'Content-Type: application/json' \
     --data '{"type":"upload","file_path":"/etc/hosts","workspaces":[],"async_processing":false}' \
     '[TARGET_URL]/api/sources/json'
   ```
2. Extract the returned source ID and retrieve the source:
   ```bash
   curl -i -H 'Authorization: Bearer [SESSION_TOKEN]' \
     '[TARGET_URL]/api/sources/[SOURCE_ID]'
   ```

**Expected Impact:**
Successful exploitation would disclose local files readable by the application process, potentially including environment/config files, service metadata, or mounted data files.

**Proof of impact.**

Successful exploitation would disclose local files readable by the application process, potentially including environment/config files, service metadata, or mounted data files.

#### Remediation: INJ-VULN-03

**Remediation Branch:** `fix/INJ-VULN-02` (8893110)

Added upload-root path security helpers; sanitized upload names; confined local file reads, downloads, retries, deletes, provider uploads, and provider-created files to the upload root.

**Files Changed:**
- `webapp/utils/path_security.py`
- `api/routers/sources.py`
- `webapp/graphs/source.py`
- `webapp/domain/workspace.py`
- `webapp/providers/anthropic_chat.py`
- `tests/test_path_security.py.`

**Validation:** ruff, compileall, and python -m pytest tests/test_path_security.py passed (4 passed).

### INJ-VULN-04: Second-Order Arbitrary File Delete via Stored Source Path
*(Also tracked as: INJ-VULN-02)*

**Severity:** High
**Status:** Potential
**Location:** `api/routers/sources.py:324`, `api/routers/sources.py:52`, `api/routers/sources.py:56`, `api/routers/sources.py:72`, `api/routers/sources.py:922`, `api/routers/sources.py:97`, `webapp/domain/workspace.py:425`, `webapp/domain/workspace.py:428`
**Preconditions:** valid shared password unless OPEN_WORKSPACE_PASSWORD is unset, public API route reachable, attacker can store source.asset.file_path, target file exists and is deletable by application user
**Remediation Branch:** `fix/INJ-VULN-02`

**Description.** Second-Order Arbitrary File Delete via Stored Source Path affects `api/routers/sources.py:324`, `api/routers/sources.py:52`, `api/routers/sources.py:56`, `api/routers/sources.py:72`, `api/routers/sources.py:922`. The finding is exploitable under the stated preconditions: valid shared password unless OPEN_WORKSPACE_PASSWORD is unset, public API route reachable, attacker can store source.asset.file_path, target file exists and is deletable by application user. In this code-only assessment, the evidence supports a potential finding because the relevant source-to-sink path is present and no live target was available to exercise it end to end.

**Exploitation.**

**Evidence for `INJ-VULN-04`.**

**Summary:**
- **Vulnerable location:** `POST /api/sources/json` path poisoning followed by `DELETE /api/sources/{source_id}`
- **Current Blocker:** No target URL and no writable runtime proof file were provided.
- **Potential Impact:** Delete arbitrary files writable by the application user.
- **Confidence:** HIGH

**Evidence of Vulnerability:**
The source creation path can store caller-controlled `asset.file_path` as described for INJ-VULN-03. Deletion loads the source at `api/routers/sources.py:925-929`, then `Source.delete()` converts `self.asset.file_path` to a `Path` at `webapp/domain/workspace.py:424-425`, checks only existence at line 426, and calls `os.unlink(file_path)` at line 428. No upload-root boundary check is performed.

**Attempted Exploitation:**
No runtime proof file could be created or deleted because there is no reachable application target.

**How This Would Be Exploited:**
If a public target URL and required authorization were supplied:

1. Create or identify a harmless writable proof file in the application runtime.
2. Store the proof file path in a source:
   ```bash
   curl -i -X POST -H 'Authorization: Bearer [SESSION_TOKEN]' \
     -H 'Content-Type: application/json' \
     --data '{"type":"upload","file_path":"/tmp/delete-me.txt","workspaces":[],"async_processing":true}' \
     '[TARGET_URL]/api/sources/json'
   ```
3. Delete the poisoned source:
   ```bash
   curl -i -X DELETE -H 'Authorization: Bearer [SESSION_TOKEN]' \
     '[TARGET_URL]/api/sources/[SOURCE_ID]'
   ```

**Expected Impact:**
Successful exploitation would allow deletion of application-writable files outside the upload directory, causing data loss or denial of service.

**Additional evidence for `INJ-VULN-02`.**

**Summary:**
- **Vulnerable location:** `POST /api/sources` multipart upload, `UploadFile.filename`
- **Current Blocker:** No target URL or runtime upload environment was provided.
- **Potential Impact:** File write outside the intended uploads directory as the application user.
- **Confidence:** HIGH

**Evidence of Vulnerability:**
`save_uploaded_file()` passes `upload_file.filename` to `generate_unique_filename()` at `api/routers/sources.py:68`. That helper uses the original filename as `new_filename` at `api/routers/sources.py:52` and joins it with the upload root at `api/routers/sources.py:56`. The resulting path is opened for write at `api/routers/sources.py:72` without resolving and checking containment.

**Attempted Exploitation:**
No multipart request could be sent because no reachable target URL exists. Code validation confirmed that traversal segments are not stripped before file write.

**How This Would Be Exploited:**
If a public target URL and required authorization were supplied:

1. Submit a benign traversal filename:
   ```bash
   printf 'path traversal write poc\n' > /tmp/inj-vuln-02.txt
   curl -i -X POST -H 'Authorization: Bearer [SESSION_TOKEN]' \
     -F 'type=upload' \
     -F 'async_processing=false' \
     -F 'file=@/tmp/inj-vuln-02.txt;filename=../upload-poc.txt' \
     '[TARGET_URL]/api/sources'
   ```
2. Confirm the write through a later read/download path or server-side log if accessible through the authorized public interface.

**Expected Impact:**
An attacker could write files outside the upload folder where the app user has permission, creating persistence, data tampering, or follow-on file processing impact.

**Proof of impact.**

Successful exploitation would allow deletion of application-writable files outside the upload directory, causing data loss or denial of service.

#### Remediation: INJ-VULN-04

**Remediation Branch:** `fix/INJ-VULN-02` (8893110)

Added upload-root path security helpers; sanitized upload names; confined local file reads, downloads, retries, deletes, provider uploads, and provider-created files to the upload root.

**Files Changed:**
- `webapp/utils/path_security.py`
- `api/routers/sources.py`
- `webapp/graphs/source.py`
- `webapp/domain/workspace.py`
- `webapp/providers/anthropic_chat.py`
- `tests/test_path_security.py.`

**Validation:** ruff, compileall, and python -m pytest tests/test_path_security.py passed (4 passed).

### INJ-VULN-05: Stored Path File Exfiltration to Provider File API

**Severity:** High
**Status:** Potential
**Location:** `webapp/providers/anthropic_chat.py:1171`
**Preconditions:** provider file-upload/code-execution chat path enabled and configured; valid shared password unless OPEN_WORKSPACE_PASSWORD is unset, public API route reachable, attacker can store source.asset.file_path, valid workspace/chat context, chosen file readable by application user
**Remediation Branch:** `fix/INJ-VULN-02`

**Description.** Stored Path File Exfiltration to Provider File API affects `webapp/providers/anthropic_chat.py:1171`. The finding is exploitable under the stated preconditions: provider file-upload/code-execution chat path enabled and configured; valid shared password unless OPEN_WORKSPACE_PASSWORD is unset, public API route reachable, attacker can store source.asset.file_path, valid workspace/chat context, chosen file readable by application user. In this code-only assessment, the evidence supports a potential finding because the relevant source-to-sink path is present and no live target was available to exercise it end to end.

**Exploitation.**

**Evidence for `INJ-VULN-05`.**

**Summary:**
- **Vulnerable location:** Stored `source.asset.file_path` selected in chat/WebSocket context with provider code execution enabled
- **Current Blocker:** No target URL, source/workspace IDs, provider configuration, or chat runtime were provided.
- **Potential Impact:** Upload local readable files from the server to a third-party provider file API.
- **Confidence:** HIGH

**Evidence of Vulnerability:**
The source creation path can store a caller-controlled local path. During chat setup, when code execution and documents are enabled, `webapp/providers/anthropic_chat.py:1166-1171` pulls `file_path` from document metadata, checks only that it exists, opens it with `open(fpath, "rb")`, and uploads it to the provider file API at `webapp/providers/anthropic_chat.py:1172-1175`.

**Attempted Exploitation:**
No live application, workspace/source IDs, or provider-enabled runtime were available, so the exfiltration path could not be triggered.

**How This Would Be Exploited:**
If a public target URL, authorization, provider configuration, and valid workspace/source context were supplied:

1. Create a source with a proof local path:
   ```bash
   curl -i -X POST -H 'Authorization: Bearer [SESSION_TOKEN]' \
     -H 'Content-Type: application/json' \
     --data '{"type":"upload","file_path":"/etc/hosts","workspaces":["[WORKSPACE_ID]"],"async_processing":true}' \
     '[TARGET_URL]/api/sources/json'
   ```
2. Start a chat execution that includes the source in context and enables the provider file upload path.
3. Confirm provider upload evidence in the API response, job/session record, or application logs.

**Expected Impact:**
Successful exploitation would move local server files into an external provider account, creating confidentiality and compliance impact.

**Proof of impact.**

Successful exploitation would move local server files into an external provider account, creating confidentiality and compliance impact.

#### Remediation: INJ-VULN-05

**Remediation Branch:** `fix/INJ-VULN-02` (8893110)

Added upload-root path security helpers; sanitized upload names; confined local file reads, downloads, retries, deletes, provider uploads, and provider-created files to the upload root.

**Files Changed:**
- `webapp/utils/path_security.py`
- `api/routers/sources.py`
- `webapp/graphs/source.py`
- `webapp/domain/workspace.py`
- `webapp/providers/anthropic_chat.py`
- `tests/test_path_security.py.`

**Validation:** ruff