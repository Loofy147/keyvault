# Threat model

Last reviewed: 2026-10-25  
Status: working threat model for release planning, not an independent security assessment.

## System in scope

keyvault stores local provider credentials in an encrypted vault, supports one-time injection into a wrapped process, exposes a local stdio MCP server, and has a loopback-only browser UI. The purpose is to let an agent **use** credentials without receiving their values.

The intended deployment is a single trusted OS user on a local machine. The current implementation is not a team vault, remote service, sandbox, or public web application.

## Assets to protect

| Asset | Primary confidentiality/integrity goal |
|---|---|
| Provider credential values | Never reveal to the model/UI response/log; transmit only to the intended authorized destination |
| Master passphrase and derived key | Avoid persistent plaintext; bound session duration; do not leak through logs or child environments unnecessarily |
| Encrypted vault and backup | Detect tampering; preserve recoverability; disclose that backup may retain prior credential versions |
| Credential policy | Apply allowed host and method scope in trusted code; prevent the agent from overriding policy |
| MCP client configuration | Include names and scoped command only, never credential values |
| Audit events | Preserve useful metadata without secrets or bodies; clearly state that local files are not tamper-proof |
| Local UI session | Restrict to loopback and same local origin; reject cross-origin state-changing requests |

## Adversaries and capabilities

### A. Malicious or prompt-injected agent with only keyvault MCP tools
May submit arbitrary tool parameters, hostile URLs, headers, methods, bodies or instructions embedded in tool data. It should not be able to request a secret value, override credential policy, or use a credential outside its allowlist.

### B. Malicious or compromised API endpoint
May echo credentials in response bodies/headers, redirect requests, return oversized/binary payloads, send unusual content types, or exploit response parsing/redaction assumptions.

### C. Malicious DNS/operator of a permitted hostname
May cause a host to resolve to loopback, private, link-local, multicast or otherwise forbidden destination addresses, or change DNS answers between a validation lookup and connection.

**Known unresolved high-risk issue:** current code applies hostname allowlisting but does not enforce destination-IP validation and pinning at connection time. A matching hostname alone is insufficient. This is a production blocker.

### D. Hostile website opened in the same browser
May attempt cross-site requests to the loopback UI, DNS rebinding, or injection through metadata fields. The UI uses Host/Origin checks, CSRF token and restrictive security headers, but it still needs real-browser end-to-end validation.

### E. Local process running as the same OS user
May be able to inspect accessible files, memory, the native keychain according to OS policy, child process environments or local browser traffic. keyvault is not intended to isolate secrets from same-user malware.

### F. OS administrator/root or compromised endpoint
Can generally access the machine and its data. This is outside the protection boundary.

### G. Accidental operator error
May grant too many hosts/methods, enable an overly broad agent scope, use a weaker file session cache, leave an unlocked session open, commit a vault/backup, or assume deleting a record erased all encrypted backups.

## Security goals

- Never expose secret values via MCP metadata tools or UI JSON responses.
- Treat all agent input as untrusted and enforce policy in trusted code.
- Restrict access by credential name, allowed hostname and allowed HTTP method.
- Keep redirects disabled by default and cap response size.
- Keep secret values out of audit, logs, URLs and thrown errors.
- Use authenticated encryption and bounded KDF parameters.
- Prefer native OS credential stores for cached derived keys; fail closed when unavailable.
- Allow operators to lock sessions and understand that this does not revoke an upstream provider token.
- Keep the UI local-only, not remotely addressable.
- Make unsupported environments and residual uncertainty visible.

## Current protections and evidence

| Control | Current implementation/evidence | Confidence / limitation |
|---|---|---|
| Vault encryption | scrypt + AES-256-GCM; tests cover wrong passphrase and tamper | Tested on Ubuntu CI; needs independent crypto review and additional fuzzing |
| Per-credential host/method restrictions | Proxy applies host pattern and method checks; negative tests | Does not close DNS rebinding without connect-time IP pinning |
| Redirect control | Automatic redirects disabled; redirect test | Tested in regression suite |
| MCP secret separation | MCP test checks metadata and outputs against canary values | Does not protect a process with shell/filesystem access |
| Native session cache | Explicit native backend selection, TTL and salt binding, test double | Native OS integrations remain unverified |
| Local UI request guard | Loopback bind, Host/Origin checks, per-process CSRF token | Server-side tests exist; browser E2E still required |
| Audit privacy | Structured events and field filtering; tests check canary absence | Local log can be modified/deleted by same user; no strong tamper evidence |
| Dependency visibility | Immutable action pins, Dependabot and pip-audit workflow | Initial scan clean; no reproducibly locked release dependency set yet |

## Risks deliberately not solved by current design

- DNS rebinding / destination-IP pinning.
- Malicious same-user process, admin/root compromise or memory scraping.
- Guaranteed secret redaction if an API transforms, encrypts, hashes or splits a secret before echoing it.
- Strong local audit-log tamper resistance.
- Cross-process write serialization and conflict detection.
- Native keychain behavior on every supported platform.
- Backup purge/restore lifecycle that proves old deleted values are no longer recoverable.
- Multi-user authorization, remote UI, remote MCP transport, OAuth refresh and request signing.

## Required release tests

- [ ] DNS rebinding with deterministic resolver and pinned connection tests.
- [ ] Destination address classes and IPv4/IPv6 edge cases.
- [ ] Real native keychain tests on macOS, Windows and Linux Secret Service.
- [ ] Browser E2E for hostile origin/host, CSRF, XSS, session expiry and lock.
- [ ] Cross-process write conflict and crash recovery tests.
- [ ] Secret-canary scan across stdout, stderr, tool output, UI API responses, audit, CI logs and artifacts.
- [ ] Mutation tests for authorization, redirect, destination, session and redaction controls.
- [ ] Independent security review of the outbound HTTP transport.
- [ ] Evidence and residual risk recorded in [production readiness](PRODUCTION_READINESS.md).

## References

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [OWASP ASVS 5.0](https://asvs.owasp.org/)
