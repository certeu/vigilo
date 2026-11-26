---
name: workflow-security
description: Verify role and state invariants across controlled multi-step application workflows.
when: security depends on approval sharing ownership membership or another state transition.
requires: [http]
modes: [web]
phases: [{id: A, title: Define invariant}, {id: B, title: Run disposable transition}, {id: C, title: Re-read consequences}]
criteria:
  - {id: invariant, phase: A, text: Actors states and expected transition recorded}
  - {id: transition, phase: B, text: Allowed test transition attempted or policy limitation recorded}
  - {id: consequence, phase: C, text: Result independently read from affected and control interfaces}
---
# workflow-security
Before acting, name the invariant, current state, permitted actor, resource, and expected readers. Use a brokered generated tool for the smallest multi-step operation; mark state-changing POST/RPC calls `state_changing: true`. All writes remain guarded and are refused unless configured. Use disposable synthetic records; when no create operation is documented, an existing resettable test record and an explicit cleanup/reset are acceptable. Do not probe invented creation method names. Record the successful mutation response plus fresh reads by the actor, subject, and one control identity. The mutation endpoint returning 200 is not proof: only an unintended state or access consequence confirms the weakness. Do not mutate real resources or infer success from the tool's own claim.
