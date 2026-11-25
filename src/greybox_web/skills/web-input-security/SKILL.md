---
name: web-input-security
description: Safely determine whether untrusted input crosses a server or browser interpretation boundary.
when: routes accept query, form, JSON, header, template, search, redirect, or markup input.
requires: [http]
modes: [web]
phases:
  - {id: A, title: Map input boundaries}
  - {id: B, title: Use controlled markers}
  - {id: C, title: Verify interpretation}
criteria:
  - {id: inputs, phase: A, text: Inputs and their output contexts mapped}
  - {id: baselines, phase: B, text: Each tested input has an inert baseline and a unique marker, evidence: {tool_done: ["injection.*", "tool.*"]}}
  - {id: impact, phase: C, text: Reflection distinguished from unsafe interpretation and failures reproduced or left inconclusive}
---
# web-input-security
Test a property, not a payload list. Establish the normal response, send one unique inert marker, then inspect its exact output context. Reflection is a lead; encoded text is not XSS. Demonstrate browser interpretation only with a harmless marker and independent browser observation. For injection, require a control/probe delta and a backend-specific result or repeatable error; do not call latency or one 500 proof. For SSRF, use only an operator-controlled in-scope listener and require that listener's evidence. If a useful control, canary, or observable consequence is unavailable, report inconclusive.

When `run.state_changing_allowed` is true and a writable form, RPC or API operation was discovered, test stored/server-side input handling through one disposable resource. Create a baseline and one uniquely labelled probe, then read it through an independent interface or browser session and compare the resulting state or interpretation. A successful save is not exploitation: confirm SQL/query influence, template or browser execution, command output, unintended file/network access, or a concrete security-boundary effect. Prefer safe in-band markers over delays and never spray payload lists. Record cleanup/reset as a final state transition when the target supports it.
