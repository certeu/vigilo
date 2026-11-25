# Assessment options and checks

Vigilo has two complementary pipelines. **Grey-box** investigates a running web/API
target, isolated network, or uploaded artifact without needing its source. **White-box**
starts from a repository and can use a running target to prove findings and verify
patches.

This page explains the operator controls and what they change. The server remains the
authority for scope, credentials, rate limits and activity permissions; an agent or
analyst message cannot override them.

## Grey-box configuration

### Assessment type

| Type | What the agent can assess | Required boundary |
|---|---|---|
| **Web application / API** | HTTP, JavaScript UI, REST, GraphQL/JSON-RPC hints, sessions, resources and workflows | Base URL plus explicit hosts, schemes, ports and paths |
| **Network segment** | Hosts, open TCP services, banners, DNS, HTTP and TLS/security posture | Explicit IPs, CIDRs or names plus ports and protocols |
| **Artifact** | Repository tree, manifests, configuration and synthetic secret evidence offline | Uploaded snapshot through the artifact API |

Artifact mode is currently API-backed rather than exposed in the normal web-target
selector.

### Scope and network controls

- **Allowed hosts, schemes and ports** define where requests may go. Wildcards are
  limited to subdomain suffixes; a bare `*` is rejected.
- **Path prefixes** narrow the application area and **excluded paths** always win.
  Exclude destructive or operational routes such as `/logout` or `/admin/reset`.
- **Redirect policy** follows at most five in-scope hops or follows none. A redirect
  never expands the authorised boundary.
- **Network targets and ports** accept explicit addresses, CIDRs, hostnames and ranges.
  Network scope is capped and revalidated by the server.
- **Protocols** select TCP connect/banner, DNS for listed names and HTTP on listed
  address/port combinations.
- **Forward proxy** is optional. Its own host allowlist is checked in addition to the
  assessment scope.
- **Limits** cap requests, duration, concurrency, request rate, timeout and pages.
  Every browser navigation, HTTP exchange and network action is also recorded.

Private-address access is a deployment-level policy. Enabling it does not remove the
per-assessment host and port boundary.

### Authentication and identities

- **Session-cookie credential** supplies an existing low-privilege test session to
  in-scope requests. Cookie values are encrypted and redacted from model context,
  evidence and logs.
- **Test accounts** let the agent log in normally. Passwords remain in the credential
  vault and login traffic is identity-attributed. Configure the login URL with the
  account so the agent does not have to infer it.
- Two or more distinct identities enable meaningful ownership, tenant and role
  comparisons. Anonymous access is also treated as an identity.
- **Allow authentication testing** permits active login-oriented checks, including
  the bounded default-credential check. It is separate from providing a valid test
  session.

Use synthetic identities with documented ownership, membership and role differences.
A successful login alone is not an access-control vulnerability.

### Controlled state-changing tests

**Allow controlled state-changing tests** is deliberately off by default. When
selected it grants `scope.activity.state_changing=true` for that target.

The permission lets the agent exercise discovered create, update, approval, sharing,
ownership or delete operations against disposable test data. Vigilo should capture a
baseline, the authorised action and a fresh observation of its effect. A successful
write is not automatically exploitation: the finding needs an unintended persisted
state or security-boundary impact.

This checkbox is a permission, not an instruction to damage data or spray payloads.
Prefer resettable local fixtures or dedicated test records. If the option is off, the
engine refuses state-changing requests and records the blocked proof as a limitation.

### Selectable checks

The current check catalogue is:

| Area | Checks | What constitutes useful evidence |
|---|---|---|
| Browser protections | Security headers, cookie flags | Response/cookie metadata from the affected page; reported as hardening unless impact is shown |
| Disclosure | Version disclosure, exposed files, directory listing, debug/error pages, client assets | Content-signature or concrete source/config/credential exposure, not a path-shaped 404 |
| Cross-origin behavior | CORS policy | An arbitrary origin reflected with credential support on the affected interface |
| Input handling | Reflected input, error-based injection indicators, open redirect | A baseline/probe difference using one inert canary; an indicator becomes a vulnerability only after impact verification |
| Authentication | Bounded default credentials | A confirmed login under the operator's auth-testing permission |
| Authorization | Object-level access, cross-interface exposure | The same resource compared across identities and interfaces, with expected access and an independently observed violation |
| Offline artifact | Artifact inspection | A concrete, non-placeholder synthetic credential/configuration issue in the uploaded snapshot |

You can deselect individual checks. Authentication checks are unavailable unless
authentication testing is allowed. **Discovery is adaptive and always available**:
root/robots/sitemap fetches, crawling, script and source-map analysis, browser
rendering, request observation, passive traffic re-examination, API relationship
mapping and security-model construction are not represented by one checkbox each.

Checks establish observations; the exploration agent uses progressive methodology
skills to decide where to apply them and when a generated analyser or brokered request
is needed. Unsupported or inconclusive work remains visible in coverage rather than
being upgraded into a finding.

### Model, objective and live guidance

- **Objective and application context** tells the agent what the application does and
  what matters to its owner. It does not weaken deterministic checks.
- **AI model** selects a configured exploration backend/model. Scope and budgets are
  enforced outside that model.
- **Live analyst guidance** is available after a run starts. Ask the agent to inspect
  a workflow, focus on an endpoint, add a seed, compare identities, skip a noisy check
  or deprioritise a lead. Messages can be sent from a graph node for exact context.
- Guidance can alter investigation priority but cannot add a host, identity,
  state-changing permission or request budget.

Useful guidance is concrete: “compare the chat object as each test account” or “test
the approval transition using one disposable document.” An attack string alone is not
proof; ask the agent to verify the resulting effect through an independent read or UI.

## Grey-box result semantics

- **Confirmed exploitable weakness**: an unintended security-boundary effect was
  reproduced with attributable evidence.
- **Confirmed misconfiguration**: the configured behavior is directly established,
  but exploit impact is not assumed.
- **Potential vulnerability / inconclusive**: an indicator exists but proof, identity,
  expectation or observable consequence is missing.
- **Expected or authorised behavior**: the check completed and the relationship model
  supports the access or state transition.
- **Not reproducible**: verification did not reproduce the claimed observation.
- **Blocked by configuration**: proof needed an activity, identity, route or target the
  operator did not authorise.

Coverage separately records what was explored, tested, blocked and still unknown.

## White-box configuration

White-box always requires a repository. Choose:

| Preset | Stages |
|---|---|
| **Findings** (`vuln`) | Survey, plan, investigate, prove, adversarially review and report |
| **Findings + patches** (`vuln_patch`) | Findings plus isolated fix branches and re-verification |
| **Full** (`full`) | Adds supply-chain and repository-integrity analysis |

Optional controls include a **live target URL**, an existing **cookie session** for
logged-in proof, **email notification**, maximum parallel agents, leads per
investigator, findings per prover, follow-up investigation rounds and retry policy.
The live target supplements source analysis; URL-only testing belongs in grey-box.

Repository settings additionally provide:

- **Description / context**, **Focus on** and **Skip / avoid** instructions shared by
  that repository's future analyses.
- Per-repository **executor** (`claude`, `codex` or `opencode`) and small, medium and
  large model overrides.
- **Push patches back to GitLab**, a separate opt-in from selecting the patch preset.
  It uses the server-side write credential; the repository clone token remains
  read-oriented and never reaches an agent.
- Private-repository visibility and access grants for platform users.

White-box proof and patches remain constrained by the checked-out repository and its
configured harness. Upload credentials and service secrets never need to reach an
agent.

## Choosing safe settings

- Start production assessments read-only, tightly scoped and rate-limited.
- Use multiple synthetic users for authorization and business-logic work.
- Enable authentication testing only on accounts and login workflows explicitly
  approved for the run.
- Enable controlled state changes only with disposable data and a reset/cleanup path.
- Include the relevant workflow and expected access rules in the objective, then use
  live guidance when new evidence changes priorities.
