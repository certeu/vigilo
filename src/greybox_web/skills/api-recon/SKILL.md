---
name: api-recon
description: Discover what an application's API really does by combining static code evidence with runtime browser observation, with provenance.
when: the target is a web application or API and its endpoints, parameters or workflows are not yet mapped — especially a JavaScript/SPA shell.
requires: [http]
modes: [web]
phases:
  - {id: A, title: Static discovery}
  - {id: B, title: Runtime discovery}
  - {id: C, title: Consolidation}
criteria:
  - id: entry-points
    phase: A
    text: Application entry points fetched or rendered
    evidence: {tool_done: [discovery.fetch_root, browser.visit, discovery.crawl]}
  - id: static-resources
    phase: A
    text: The application's own scripts, source maps and runtime configuration examined
    evidence: {all: [{tool_done: discovery.scripts}, {tool_done: client.assets}]}
  - id: static-candidates
    phase: A
    text: Candidate routes extracted from static evidence (or none exist)
    evidence: {asset: {kind: endpoint, source_prefix: "script:"}}
  - id: runtime-observed
    phase: B
    text: API activity observed at runtime in the browser
    evidence: {asset: {kind: endpoint, source_prefix: "browser:", api: true}}
    na_when: {capability_missing: browser}
    blocked_when: {auth_state: [identity_provider, expired, missing]}
    blocked_category: authentication
  - id: workflows
    phase: B
    text: Authenticated workflows walked with each available identity (or the boundary recorded)
    blocked_when: {auth_state: [identity_provider, expired, missing]}
    blocked_category: authentication
  - id: provenance
    phase: C
    text: Discovered endpoints inventoried with their provenance
    evidence: {observation: {key_prefix: "route.inventory|"}}
  - id: templates
    phase: C
    text: Parameterised route templates inferred from multiple samples (recorded as inferences)
    evidence: {observation: {key_prefix: "route.template|"}}
  - id: correlated
    phase: C
    text: Static and runtime evidence correlated (static-only and runtime-only routes explained)
  - id: parameters
    phase: C
    text: Parameters of the important endpoints identified (query, form, JSON body)
    evidence: {asset: {kind: parameter}}
  - id: gaps
    phase: C
    text: Remaining discovery gaps documented
---
# api-recon — map the real API

Goal: know which endpoints, methods, parameters and workflows the application
actually has, where each piece of knowledge came from, and what is still unknown.
An HTML crawl of a modern front end typically finds a shell and a bundle and nothing
else; the API lives in code and in runtime traffic.

## Phase A — Static discovery
- Fetch or render the entry points (`discovery.fetch_root`, `browser.visit`).
- Read the application's OWN code: `discovery.scripts` on the page's bundles and
  any manifest/schema you see (OpenAPI/Swagger, GraphQL introspection result,
  `manifest.json`, source maps). Endpoints it extracts carry `source: script:<url>`.
- Surface the UI never calls: request the well-known API metadata and documentation
  paths once each (`/api`, `/api/health`, `/health`, `/status`, `/version`,
  `/api/version`, `/actuator`, `/metrics`, `/openapi.json`, `/swagger.json`,
  `/api-docs`, `/.well-known/security.txt`) with `discovery.crawl {seeds}` — public
  health/version endpoints routinely disclose internal hosts, builds and dependencies.
- An unfamiliar format (custom envelope, minified route table, protobuf-ish JSON):
  write an analyser with `tool.compose` (template: `skill.read {name: api-recon,
  part: "script:extract_routes.py"}`) instead of re-reading the same bundle.

- API-first services: the schema IS the map. Read `openapi.json`/`swagger.json`
  fully with a written analyser: every path × method, parameters, security
  requirements, and vendor annotations about roles or scopes (`x-required-role`,
  `x-scopes`, `security: [{oauth: [admin]}]`) — they are documented
  expectations for api-security and business-logic. Paths the schema omits but
  the API reveals are the most interesting surface.
- Follow the API's own links: `_links`/`links`/`href` fields, `Link:` headers
  (`rel="next"`, `rel="service-desc"`), `next`/`next_cursor`, ids of related
  objects (`payment_id`, `owner_id`, `parent`) — each names an interface or an
  instance. Probe the interface a reference implies (`/payments/{id}` from
  `payment_id`) even when no schema documents it.
- Opaque tokens in pagination (`cursor`, `page_token`, `continuation`) are often
  base64/JSON: decode them with a written analyser and record what they contain
  (an offset, a tenant, a filter) — that is a parameter the server trusts.

**Gate A.** Static evidence is *sufficient* only if it names the API calls the UI
makes. If it names none, or only a few literals, go to Phase B — do NOT re-run
static extraction on the same bundles (it is refused as repetition anyway).

## Phase B — Runtime discovery
- `browser.visit` the main views; `browser.act` to drive the UI (open a record,
  open settings, submit a search, click navigation). Each call reports the XHR /
  fetch requests it caused, with methods and JSON body field names; those become
  endpoints with `source: browser:<type>`.
- Do this as EVERY available identity (`session` = anon, provided-cookie, account
  labels after `auth.login`): roles see different APIs.
- If the browser lands on an identity provider or a login view, the session is not
  valid for that area: record it (auth-boundaries skill) and continue with static
  evidence and any identity that works. Never analyse the IdP as the target.

**Gate B.** Runtime coverage is adequate when every navigable area reachable with
the available identities was walked at least once and produced its API calls, or
the reason it could not be is recorded (blocked: authentication).

## Phase C — Consolidation
- Run `discovery.routes`: it infers route templates (`/api/notes/{id}` from
  `/api/notes/1`, `/api/notes/7`, `/api/notes/42`) with confidence by number of
  samples, recorded as INFERENCES separate from what was observed, and classifies
  each template as static-only, runtime-only or both.
- Explain the gaps: static-only routes (dead code? another role? admin?) and
  runtime-only routes (generated URLs? another bundle?) are leads, not noise.
- Make sure parameters of the important endpoints are known (query, form, JSON
  body); record what you could not reach.

## Alternatives when a method stalls
| Stalled | Switch to |
|---|---|
| Static extraction finds no API | runtime observation in the browser |
| Browser blocked by login / IdP | static evidence + auth.login with provided accounts; record the boundary |
| Bundle too large / unusual | an analyser via tool.compose (`ctx.broker.recorded()` reads what was fetched) |
| Same endpoint seen only once | look for siblings (lists → detail views) before inferring a template |
| No browser surface (JSON-only API) | the schema, the API index and hypermedia links are the runtime map; claim runtime-observed not_applicable with that reason |
| Ids are slugs (`atlas`, `b7k2xq`) | they are ids when a list returned them: request the detail as each identity |
| Nothing new after 3 actions | change identity, area or method; or close the phase as blocked |

## Evidence expectations
Every endpoint you rely on must exist as an asset with a provenance (`source`).
Templates are inferences: cite their samples. "No API found" is a claim that needs
both a static and a runtime attempt behind it.

## Definition of done
Engine-checked where the evidence is observable (see knowledge skills.loaded).
Claim `correlated`, `workflows` and `gaps` in your reply's `criteria` with the
observation keys / endpoint URLs that support them, or as blocked /
not_applicable with a reason.

## Client artifacts
For an SPA, run `discovery.scripts` on the shell and lazy chunks. Follow every reported source map and runtime `.json` configuration, then run `client.assets` on them. A source map is reportable only when original source contains non-public implementation detail. In runtime config, separate public/publishable keys and ordinary endpoints from server credentials or private material.
