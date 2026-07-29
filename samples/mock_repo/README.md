# Mock Vulnerable Repo

A tiny, **intentionally vulnerable** FastAPI app used to demonstrate the Vigilo
platform end-to-end. It contains deliberate flaws (SQL injection, command injection,
SSRF, `eval` RCE, hardcoded secret, info exposure) and pinned outdated dependencies
for supply-chain (SCA) findings.

**Do not deploy.** This exists only so a pipeline run produces representative findings.
