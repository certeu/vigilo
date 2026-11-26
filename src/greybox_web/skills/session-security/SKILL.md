---
name: session-security
description: Assess authentication state and the session lifecycle across identities and requests.
when: the application has login, logout, cookies, bearer tokens, identity switching, or role changes.
requires: [http]
modes: [web]
phases: [{id: A, title: Establish sessions}, {id: B, title: Test lifecycle}, {id: C, title: Verify boundaries}]
criteria:
  - {id: identities, phase: A, text: Every configured identity authenticated or its failure recorded}
  - {id: lifecycle, phase: B, text: Session creation logout and cross-request consistency assessed}
  - {id: outcomes, phase: C, text: Protected reads compared before and after the relevant lifecycle event}
---
# session-security
Use `auth.login` for each label and record which identity each request represents. Compare anonymous and authenticated access, cookie flags, token placement, fixation indicators, and logout/expiration behavior. A logout UI alone is not invalidation proof: reuse only the synthetic session in an authorised disposable workflow, then request a harmless protected profile. Test role or membership changes only when state-changing activity is enabled; re-read both own and related interfaces afterward. Never expose token values. Missing time or permission to test expiry/revocation is inconclusive.
