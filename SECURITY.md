# Security Policy

## Supported Versions

Vigilo is under active development, yet currently still in alpha.

| Version | Supported |
| ------- | --------- |
| < 1.0   | :x:       |

## Reporting a Vulnerability

To report a vulnerability, please contact CERT-EU via
[services@cert.europa.eu](mailto:services@cert.europa.eu).

## Security model and known limitations

Vigilo runs AI agents that read, execute and test the code and applications you point it at.
Treat it as a security tool that handles hostile input:

- **Only scan what you are authorised to test**, and run Vigilo on infrastructure you control.
- **The scanned repository is untrusted input.** Its content can try to manipulate (prompt-inject)
  the agents. Agents run as subprocesses of the pipeline worker, in the worker's container and
  network. They do not receive the platform's own secrets (database, encryption and session keys
  are kept out of the worker), but a compromised agent acts with the worker's reach: it can
  contact the workflow orchestrator and the API's internal listener, and on a worker shared by
  concurrent runs it may be able to obtain another active run's session cookie.
- **Model credentials** (API keys for your LLM backend) are available to the agents' processes.
  Use keys scoped to Vigilo and rotate them if you suspect a compromised scan.
- **Session cookies** you give Vigilo for logged-in testing are passed to the agents that test
  the live application. They are masked in Vigilo's logs, saved prompts, reports and merge
  requests, but an agent can still copy them elsewhere. Use **dedicated, low-privilege test
  accounts** and short-lived sessions.
- **GitLab tokens** for pushing fix branches are stored encrypted, delivered to the worker only for
  the push, and never shown to the agents. Use a token scoped to the target project with the
  minimum permissions needed to push branches and open merge requests.
- **Never expose** the API's internal listener (`VIGILO_INTERNAL_PORT`), the workflow orchestrator
  or Postgres outside the Docker network, and set strong values for `POSTGRES_PASSWORD`,
  `VIGILO_JWT_SECRET` and `VIGILO_FERNET_KEY`.

Running each scan in its own isolated sandbox container is the planned next step. Until then,
prefer running one scan at a time when scanning repositories you do not trust.

## See also

- PGP fingerprint: [4522 E470 EFA2 10AB C77B 6FED A8A6 0841 891D 04EC](https://www.cert.europa.eu/files/certs/CERT-for-the-European-Institutions.asc)
- Our [vulnerability disclosure policy](https://www.cert.europa.eu/coordinated-vulnerability-disclosure-policy)
