---
name: api-protocols
description: Model APIs where many operations share one GraphQL or RPC endpoint.
when: schemas traffic or scripts show GraphQL JSON-RPC operation names or method dispatch.
requires: [http]
modes: [web]
phases: [{id: A, title: Inventory operations}, {id: B, title: Compare identities}, {id: C, title: Verify effects}]
criteria:
  - {id: operations, phase: A, text: Distinct operation names and input shapes inventoried}
  - {id: boundaries, phase: B, text: Security-relevant operations compared across identities}
  - {id: effects, phase: C, text: State or data impact independently observed}
---
# api-protocols
Treat method or operation name plus endpoint as the interface identity; do not correlate only on URL. Extract names and variables from schemas, client scripts, and recorded JSON. For GraphQL use `operationName`, selected fields and variables; for JSON-RPC use `method`, `params` and `id`. Prefer legitimate object ids harvested by their owning identity. Compare errors, data and omitted fields, then re-read a protected detail or state to verify impact. For an authorised mutation, use a generated brokered tool, mark the mutation `state_changing=True`, and report engine-owned before/action/after exchange ids in the finding `effect`. Schema introspection or a callable method alone is informational, not exploitation.
