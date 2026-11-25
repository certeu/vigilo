---
name: artifact-security
description: Assess an uploaded repository inventory offline for exposed credentials dependencies configuration and source-code security properties.
when: assessment mode is artifact.
requires: [inventory]
modes: [artifact]
phases: [{id: A, title: Inventory}, {id: B, title: Inspect}, {id: C, title: Corroborate}]
criteria:
  - {id: files, phase: A, text: Repository files and manifests inventoried, evidence: {asset: {kind: resource_type}}}
  - {id: risks, phase: B, text: Security-relevant files read through the inventory capability}
  - {id: proof, phase: C, text: Findings cite uploaded content and separate examples placeholders and public data}
---
# artifact-security
Use the offline inventory only; never request the network. Read package manifests, lock files, deployment/configuration files and targeted source based on import/routing evidence. Confirm a credential only when a secret-like field has a concrete non-placeholder value and application context; do not report filenames alone. Dependency names and versions are inventory unless mapped to a locally supplied advisory. For source properties, trace input to a security boundary and record any missing runtime assumption. Use a generated analysis tool when several files must be correlated.
