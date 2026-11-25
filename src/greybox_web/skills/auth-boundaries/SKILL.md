---
name: auth-boundaries
description: Establish which identities work, where authentication boundaries and identity providers are, and what each boundary leaves unassessed.
when: the target has a login, SSO redirect, session cookie or configured accounts — or responses suggest the session is not accepted.
requires: [http]
modes: [web]
phases:
  - {id: A, title: Inventory identities}
  - {id: B, title: Exercise the boundary}
  - {id: C, title: Record limits}
criteria:
  - id: identity-inventory
    phase: A
    text: Available identities established (anonymous, provided cookie, each account)
    evidence: {any: [{tool_done: [auth.login]}, {tool_done: [browser.visit, browser.cookies]}]}
  - id: session-validity
    phase: A
    text: Each identity shown to reach the application (not a login page or IdP)
    blocked_when: {auth_state: [identity_provider, expired, missing]}
    blocked_category: authentication
  - id: idp-boundary
    phase: B
    text: Identity-provider redirects identified and not assessed as the target
    evidence: {observation: {key_prefix: "auth.state|"}}
  - id: multi-identity
    phase: B
    text: At least two identities exercised on the same areas
    evidence: {identities: {min: 2}}
    blocked_when: {identities_lt: 2}
    blocked_category: authorisation
  - id: session-hardening
    phase: B
    text: Session cookie attributes and behaviour examined
    evidence: {tool_done: [cookies.flags, browser.cookies]}
  - id: limits-recorded
    phase: C
    text: What each failed or missing identity left unassessed is recorded
---
# auth-boundaries — who can the assessment be, and where does that stop?

A run that cannot authenticate observes the login page, not the application.
Knowing that — and saying it — is as important as any finding.

## Phase A — Inventory identities
- The knowledge lists `run.accounts` (labels) and `run.sessions` (live identities).
- Establish each account with `auth.login {url, account, user_field,
  password_field, body?}` on the login endpoint (for a script-driven login, find
  the endpoint first with `browser.act` on the login view — api-recon Phase B).
  It handles the three common styles: an HTML form (hidden CSRF fields and the
  pre-session cookie are taken from the login page), a JSON document
  (`body: "json"`, or automatically when the form is not understood), and a
  bearer token returned in the JSON answer (`access_token`, `token`…), which
  becomes the identity's Authorization header. Use the field names the login
  page or the observed request uses (`username`, `email`…).
- Prove each identity works: `browser.visit {url, session}` must land in the
  application (dashboard, profile), not on a login form or an identity provider.

## Phase B — Exercise the boundary
- SSO: a redirect to `login.microsoftonline.com`, Okta, Keycloak, `/oauth2/...` is
  an identity provider. The platform stops there and reports `auth.state`; never
  try to assess the IdP. An expired provided cookie looks exactly like this.
- Compare identities on the same areas (see api-security for object ownership).
- Session hardening: `browser.cookies` / `cookies.flags` (Secure, HttpOnly,
  SameSite, lifetime); does logout invalidate the session (only if state-changing
  actions are authorised)?

- Identity context: each request in the security model is attributed to the
  identity that made it. Confirm per identity that it reaches ITS OWN data
  (`/me`, profile), not someone else's or an anonymous view, before comparing
  identities.
- Membership and role transitions: profiles and member lists often show
  history (`removed_at`, `expires_at`, former roles). A past membership is a
  boundary to test: what the identity could read before the transition must be
  refused on every interface after it (business-logic Phase C).

## Phase C — Record limits
- For every identity that could not be established, record what it leaves
  unassessed (claim `limits-recorded` with the observation keys). An expired
  session is a blocked assessment, not a completed one.
- Sessions do not survive a resumed run unless restored by the platform; re-check
  `run.sessions` after a resume.

## Alternatives when a method stalls
| Stalled | Switch to |
|---|---|
| Login form not found in HTML | browser.act on the login view to observe the login API call |
| auth.login rejected | check field names from the observed request body; do not guess passwords |
| Every page redirects to an IdP | the provided session is invalid: record blocked (authentication) and assess only the pre-login surface |
| One account only | record multi-identity as blocked (authorisation); ask the operator for a second account |

## Definition of done
`identity-inventory`, `idp-boundary`, `multi-identity` and `session-hardening`
are engine-checked; `session-validity` is blocked automatically when the run met
an identity provider or an expired session. Claim `session-validity` (citing the
browser observation that reached the app) and `limits-recorded`.
