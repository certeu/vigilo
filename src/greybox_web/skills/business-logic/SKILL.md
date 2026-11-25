---
name: business-logic
description: Understand the application's workflows, identities and resources, state the access rules they imply, and test those rules across every interface that exposes the same resource.
when: the application has users with different roles or memberships, shared or owned resources, workflow states (draft/approved, active/removed), or secondary views (feeds, exports, history, search) of the same data.
requires: [http]
modes: [web]
phases:
  - {id: A, title: Understand the workflows}
  - {id: B, title: State expectations}
  - {id: C, title: Test across interfaces}
  - {id: D, title: Conclude and record assumptions}
criteria:
  - id: workflows
    phase: A
    text: The application's important workflows recorded in the security model (or none exist)
    evidence: {asset: {kind: workflow}}
  - id: entities
    phase: A
    text: Identities, roles and resource types recorded with their relations (ownership, membership, parent/child)
    evidence: {all: [{asset: {kind: resource_type, min: 2}}, {asset: {kind: identity, min: 2}}]}
    blocked_when: {identities_lt: 2}
    blocked_category: authorisation
  - id: expectations
    phase: B
    text: Access expectations stated, each with its basis (documented, configured, observed in the UI, or an explicit assumption)
    evidence: {observation: {key_prefix: "model.expect|", min: 2}}
  - id: multi-identity
    phase: C
    text: Each resource type's interfaces requested as at least two identities
    evidence: {identities: {min: 2}}
    blocked_when: {identities_lt: 2}
    blocked_category: authorisation
  - id: cross-interface
    phase: C
    text: Secondary interfaces (feeds, exports, history, search, lists) compared with the resource's own interface
    evidence: {any: [{tool_done: [authz.exposure]}, {tool_done: ["tool.*"]}]}
  - id: signals-settled
    phase: D
    text: Every security_model signal verified, explained as authorised/public, or left open with the reason
  - id: assumptions
    phase: D
    text: Unverified assumptions and untestable transitions (state-changing steps the activity policy forbids) recorded
---
# business-logic — what is this application FOR, and who may do what?

Endpoint checks find a missing check on a URL. They do not find a rule that is
enforced on one interface and forgotten on another, or a permission that should
have ended when a membership did. Those need understanding first.

## Phase A — Understand the workflows
- Walk the application as each identity (api-recon) and say what it does in one
  line per workflow: "members browse projects → open documents → drafts become
  in_review → approvers approve"; "admins manage members"; "users export boards".
- Record it in the reply's `model` field (see SECURITY MODEL):
  - entities: `identity` (each account; `attributes.role`), `role`,
    `resource_type` (project, document, invoice…), notable `resource` instances
    (the ids you will test with), `workflow`, `workflow_state`;
  - relations: `owns`, `member_of`, `has_role`, `belongs_to` (document → project),
    `references` (feed → document), `has_state`, `transitions_to`, `acts_on`.
- Look for the data that explains access: `/me`-style profiles (memberships,
  roles, history such as `removed_at`), member lists, `owner`/`author` fields,
  state fields (`draft`, `archived`), schema annotations (`x-required-role`),
  what the UI hides or greys out.

## Phase B — State expectations (before testing)
For each resource type, write who SHOULD read/list/update it, in `expectations`,
with the basis and evidence:
- `documented` — a schema, an annotation, the operator's description;
- `observed_ui` — the UI omits the object for this identity, the resource's own
  API refuses it (cite the exchange: `exchange:<id>`);
- `configured` — the operator's account set-up says so;
- `stated` — your assumption: allowed, but it stays an assumption.
Typical invariants worth stating:
- a non-member/non-owner cannot read the resource **or data about it** through
  ANY interface (feed, export, search, history, version, notification, list);
- a state hides content (a draft is the author's) on every interface;
- a revoked membership/role revokes access on every interface, immediately;
- a lower role cannot call a function a schema reserves for a higher role;
- identifiers from another tenant are refused everywhere, including in cursors,
  filters and embedded links.

## Phase C — Test across interfaces
- Read `security_model.signals`: the engine pairs observations where the SAME
  instance was refused to an identity on one interface and served to it on
  another. Each signal is a lead.
- For every resource type, list its interfaces (`security_model.interfaces`):
  the own detail interface, list, sub-resources (versions, comments, export),
  and secondary views that mention it (feeds, notifications, search, dashboards).
  Request each as every identity; harvest ids as the identity that legitimately
  has them, then use them as the one that should not.
- Verify a "refused here, shown there" case with `authz.exposure` (url = the
  secondary interface, control_url = the resource's own interface, marker = an id
  or title from the resource, owner = an identity that has it). It re-requests
  everything and rules out echo, public data, authorised access and
  non-existence. A custom format or a computation (decode a cursor, diff two
  identities' feeds) → write a tool.
- State transitions you cannot perform (the activity policy forbids
  state-changing methods) are tested through their RESULTS that already exist
  (an old membership, an existing draft, a past approval), never by forcing them.

## Phase D — Conclude
- Every signal: a verified finding, an explanation (`authorised`, `public`,
  different instance), or an open hypothesis with the reason.
- An expectation contradicted by verified evidence is a finding; an expectation
  that held is coverage. One root cause = one finding: name every interface it
  affects in the description rather than reporting each separately; two
  different rules violated = two findings.
- Record what stayed an assumption (`basis: stated`) and what could not be
  exercised, in `criteria` (`assumptions`).

## Alternatives when a method stalls
| Stalled | Switch to |
|---|---|
| Only one identity | static evidence of roles; record multi-identity as blocked (authorisation) |
| Ids are opaque | harvest them from lists/feeds/links of the identity that has them |
| No signal appears | request secondary interfaces (feeds, exports, history) as the identity that is refused the resource |
| Unsure whether data is meant to be visible | look for a basis (UI, schema, membership); otherwise keep the expectation `stated` and the result inconclusive |

## Definition of done
`workflows`, `entities`, `expectations`, `multi-identity` and `cross-interface`
are engine-checked against the security model and the run's actions. Claim
`signals-settled` and `assumptions` in `criteria` with the finding titles,
observation keys or exchange references that support them.
