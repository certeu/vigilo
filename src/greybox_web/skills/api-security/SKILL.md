---
name: api-security
description: Test an API's security properties — authentication consistency, object ownership, role boundaries, input handling and exposure — with the run's identities.
when: API endpoints are mapped (api-recon) and you need to decide whether they enforce who may do what.
requires: [http]
modes: [web]
phases:
  - {id: A, title: Prepare identities and targets}
  - {id: B, title: Test security properties}
  - {id: C, title: Conclude with evidence}
criteria:
  - id: identities
    phase: A
    text: At least two identities available to compare (anonymous plus a test account, or two accounts)
    evidence: {identities: {min: 2}}
    blocked_when: {identities_lt: 2}
    blocked_category: authorisation
  - id: targets
    phase: A
    text: Security-relevant endpoints selected (object-addressed, state-bearing, privileged)
    evidence: {observation: {key_prefix: "route.template|"}}
  - id: authn-consistency
    phase: B
    text: Each important endpoint compared unauthenticated vs authenticated
    evidence: {any: [{tool_done: [authz.object]}, {tool_done: ["tool.*"]}]}
  - id: object-ownership
    phase: B
    text: Object ownership tested across identities on sibling identifiers
    evidence: {all: [{identities: {min: 2}}, {any: [{tool_done: [authz.object]}, {tool_done: ["tool.*"]}]}]}
    blocked_when: {identities_lt: 2}
    blocked_category: authorisation
  - id: roles
    phase: B
    text: Role differences tested (or only one role exists)
  - id: input-handling
    phase: B
    text: Input handling of discovered parameters probed with inert inputs
    evidence: {tool_done: ["injection.*", "redirect.open", "tool.*"]}
  - id: exposure
    phase: B
    text: Sensitive information exposure checked (errors, metadata, excessive fields)
    evidence: {tool_done: [info.errors, exposure.files, headers.disclosure, "tool.*"]}
  - id: verified
    phase: C
    text: Every reported weakness reproduced or explicitly left as a candidate
  - id: remediation
    phase: C
    text: Each confirmed weakness has concrete remediation and a retest
---
# api-security — does the API enforce who may do what?

Mapping is not testing. Test properties, compare identities, and conclude only
from evidence you can point to.

## Phase A — Prepare
- Identities: anonymous, the provided cookie, every account (`auth.login` with
  the account LABEL; you never see secrets). Fewer than two identities means
  object-level authorisation cannot be tested: record it as blocked
  (authorisation: "provide two test accounts"), do not pretend.
- Targets: from api-recon's inventory pick object-addressed routes
  (`/api/x/{id}`), state-bearing ones (POST/PUT), privileged-looking ones
  (`admin`, `manage`, `export`, `users`), and static-only routes (unused UI).

## Phase B — Test properties
- **Authentication consistency.** The same request with no identity and with a
  valid one. A wall of 401s for anonymous is the EXPECTED baseline, not coverage:
  the authenticated comparison is what tests anything.
- **Object ownership (IDOR/BOLA).** As identity A, read objects owned by B,
  including sibling ids next to the ones A legitimately sees. `authz.object` does
  one URL; for a list of ids × identities with ownership decided from the response
  body, write a tool (template: `skill.read {name: api-security, part:
  "script:authz_matrix.py"}`) and run it with `args`. Equal responses across
  identities, or a non-owner reading an owner's record, is the finding.
- **Roles (function-level).** Compare what each role's UI calls; call
  higher-role endpoints as the lower role. A schema's role annotation
  (`x-required-role: admin`) is a DOCUMENTED expectation: record it in the
  security model and call every such operation as each lower role in the same
  tenant/organisation. A 200 where the documentation says admin-only is the
  finding; a 403 is coverage.
- **Tenant and ownership everywhere an identifier travels.** Not only the path:
  query filters (`?customer_id=`, `?org=`), cursors and page tokens (decode them:
  an embedded tenant or owner the server trusts is a parameter), embedded links
  and top-level shortcuts (`/payments/{id}` next to `/orgs/{org}/payments/{id}`).
  Harvest ids as the identity that owns them, replay them as one from another
  tenant/organisation.
- **Secondary interfaces.** Feeds, exports, search, history/versions,
  notifications and list views must apply the same rule as the resource's own
  read endpoint. When the own endpoint refuses an identity, request the
  secondary interfaces as that identity; verify a "refused here, shown there"
  case with `authz.exposure` (see the business-logic skill).
- **Cross-origin policy.** Run `cors.policy` on an authenticated API endpoint, not
  only on the page: APIs often send CORS headers the HTML never does, and a reflected
  origin with credentials lets any site read the user's API data.
- **Input handling.** Discovered parameters (query, form, JSON) with the inert
  probes (`injection.reflection`, `injection.errors`, `redirect.open`); never
  destructive payloads. State-changing methods only if the run allows them.
- **Exposure.** Error pages, debug output, over-broad JSON (password hashes,
  internal ids, other users' emails), version disclosure, public health/status
  endpoints naming internal hosts. Feeds, audit logs, notifications and exports that
  return OTHER users' records (who did what, their object ids, e-mails, IPs) are a
  disclosure finding in their own right — report it with a written analyser
  (`class: vulnerability`, `affected` the feed URL) even when no object behind it is
  directly readable; then use the leaked ids to test object access.

## Evidence requirements
- A finding names the identity, the resource (instance id), the expected rule
  and its basis (schema, UI, membership, operator description), the observed
  behaviour, and the exchanges. "Different responses" or "data returned" alone is
  not a finding: ask whether the identity is entitled to it.
- Rule out: the data is the caller's own (an echo of `requested_by`), public by
  design, a soft-404 shell, or a different object with the same shape.

## Phase C — Conclude
- A weakness is confirmed only when reproduced (the engine verifies candidates);
  an unreproduced one stays a likely vulnerability. Inconclusive tests stay open
  hypotheses with the reason.
- Remediation names the missing property and where to enforce it, e.g. "load
  notes scoped to the session user (`WHERE owner = :user`) in the notes read
  handler; return 404 for foreign ids" — plus a retest ("as user B, GET
  /api/notes/{A's id} returns 404").

## Alternatives when a method stalls
| Stalled | Switch to |
|---|---|
| Only anonymous identity | static analysis of role checks in code; record authorisation as blocked |
| Every call returns 401 | establish a session (auth.login / browser) before concluding anything |
| Responses differ only by timestamps | compare a field-level diff with a written analyser |
| Ids are opaque (UUIDs) | harvest ids from list endpoints of each identity, then cross-read |

## Definition of done
`identities`, `authn-consistency`, `object-ownership`, `input-handling` and
`exposure` are checked by the engine against the run's actions. Claim `roles`,
`verified` and `remediation` in `criteria`, citing finding titles or observation
keys, or as blocked / not_applicable with the reason.
