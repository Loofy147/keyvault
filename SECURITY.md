# Security policy

## Scope and deployment model

keyvault handles local credentials and exposes a credential-use tool to MCP agents. Treat it as security-sensitive software. Current status and gaps are documented in [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md). The current build must **not** be considered production-ready while P0 gates remain open.

The local UI is loopback-only. Do not expose it to the network. keyvault is not a sandbox against malicious code running as the same OS user, and the run-wrapper intentionally passes a selected secret to its child process.

## Reporting a vulnerability

Do not publish secret values, live tokens, vault files, session caches or exploit details in a public issue.

Use GitHub's private vulnerability reporting / Security Advisory facility for this repository when available. If unavailable, contact the maintainer through the GitHub profile and ask for a private disclosure channel before sending technical details. Do not assume a public issue is a private channel.

A report should include:
- affected commit/version and platform;
- preconditions and attacker capability required;
- minimal reproduction using fake credentials and synthetic data;
- impact and possible exfiltration path;
- relevant logs with secrets removed.

Please allow time for triage and remediation before public disclosure. This document does not promise a fixed response SLA.

## Security design rules

- Keep host/method authorization in trusted code; never rely on agent instructions.
- Never put credential values in MCP tool output, client configuration snippets, audit events, URLs, logs or exception text.
- Host allowlists must be paired with destination-IP validation at connection time before production use.
- Native keychain failure must not silently switch to file storage.
- A local append-only-looking JSONL file is not tamper-proof against the owner or administrator.
- Do not merge security-sensitive changes without tests, a threat-model update and release-gate review.

## External references

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
