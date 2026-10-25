# Production readiness status

**Status: NOT PRODUCTION READY.** This is the authoritative release-gate document. A passing suite demonstrates tested behavior; it does not establish production readiness by itself.

Last reviewed: 2026-10-25  
Repository: https://github.com/Loofy147/keyvault  
Latest verified regression result for the readiness update: **62 passed on each of Python 3.11, 3.12, 3.13 and 3.14 on Ubuntu** ([CI matrix run](https://github.com/Loofy147/keyvault/actions/runs/40226816791)). Native keychain OS integration and browser E2E have not yet been verified. The initial dependency audit reported **No known vulnerabilities found** ([security workflow](https://github.com/Loofy147/keyvault/actions/runs/40226816792)).

## Evidence ledger

| Area | Current evidence | Status | Required next proof |
|---|---|---|---|
| Encrypted vault | scrypt-derived key and AES-256-GCM; tamper and wrong-passphrase tests | Tested on Linux CI | Crypto review, malformed-envelope fuzzing, restore tests |
| MCP boundary | stdio SDK integration tests; scope and secret-redaction assertions | Tested on Linux CI | Desktop-client compatibility; hostile-input review |
| Native session stores | Backend-selection code; in-memory keychain double | **Not proven on native stores** | Real macOS Keychain, Windows Credential Locker and Linux Secret Service tests |
| HTTP destination policy | HTTPS, credential host patterns, method allowlist, no automatic redirects | **Security blocker** | Destination-IP policy enforced at connection time; DNS rebinding and IP-class tests |
| Local UI | Host/Origin/CSRF checks and JavaScript syntax check | Partially tested | Browser end-to-end tests and session-race tests |
| Persistence integrity | Atomic replacement; encrypted backup copy | **Concurrency gap** | Cross-process writer locking and crash-recovery evidence |
| Audit | Structured JSONL events | Local tampering is possible | Retention/integrity model, rotation and disk-full tests |
| Supply chain | Immutable action pins, weekly dependency audit and Dependabot updates; initial audit found no known vulnerabilities | Partially hardened | Keep reviewing updates; add release-specific artifact provenance and exception expiry |
| Release/recovery | CLI commands exist; backup semantics documented | Incomplete | Reproducible artifacts, clean install, recovery and rollback evidence |

## Release-blocking issues

### P0 — HTTP destination / SSRF boundary

The proxy checks hostname allowlists but does not pin and validate the actual network destination. DNS rebinding or a malicious domain can resolve to loopback, private, link-local, multicast or other non-public addresses. A hostname-only allowlist is not sufficient for a production credential broker.

**Acceptance criteria**
- Resolve all A and AAAA answers and reject forbidden address classes by default.
- Prevent time-of-check/time-of-use gaps: connect to a validated address while preserving hostname-based TLS certificate validation and SNI.
- Apply policy to retries and future redirect handling.
- Reject mixed allowed/forbidden answers or define and test an equally strict policy.
- Add deterministic tests for IPv4/IPv6, IPv4-mapped IPv6, loopback, private, link-local, multicast, reserved ranges, DNS rebinding between validation and connection, and allowlist look-alikes.
- Keep redirects disabled by default. If enabled later, revalidate every target and hop.
- Obtain an independent security review of the transport implementation before release.

Reference: [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

### P0 — Native credential-store evidence

The default implementation selects native OS backends, but tests use a fake/in-memory backend. Until tested, macOS, Windows and Linux desktop/headless behavior is not established.

**Acceptance criteria**
- CI on macOS and Windows covers install, unlock, TTL expiry, lock, re-key invalidation, missing item, permission/service failure and no-fallback behavior.
- Linux tests cover both a running Secret Service session and an absent/unavailable D-Bus/keyring.
- Failure messages avoid secret values and reveal no environment content.
- Do not label a platform supported until its native test path passes.

### P0 — Cross-process writes and recovery

The documented behavior is “last write wins.” Two CLI/UI processes can overwrite each other's updates, and an interrupted write must not leave backup semantics ambiguous.

**Acceptance criteria**
- Serialize writers across processes, or use a validated compare-and-swap revision model.
- Add concurrent update/delete tests and crash/failure injection around backup creation and replacement.
- Verify both current vault and backup can be recognized as valid encrypted envelopes.
- Never silently merge or discard conflicting edits.

### P0 — Local UI security verification

The UI is an HTTP server restricted to loopback. It is not an authenticated multi-user service and must not be deployed to a network.

**Acceptance criteria**
- Browser tests cover hostile Origin/Host, CSRF, XSS payloads in all metadata fields, locking while a page is open, expired sessions, duplicate submissions, and reload after lock.
- Confirm credentials, passphrases and secret-bearing bodies do not enter URLs, browser storage, server logs, traces or audit events.
- Keep service bound to 127.0.0.1; do not add remote binding before a separately reviewed authentication/transport design.

### P1 — Audit and secret lifecycle

The audit file is local and editable by the same OS identity. Filtering events in the UI is not tamper protection. An encrypted backup can preserve an earlier value after a credential is deleted or rotated.

**Acceptance criteria**
- Document event schema, excluded fields, retention/rotation, clock assumptions and tamper limits.
- Add a tested backup purge and recovery procedure. A deleted credential is not irrecoverable while an earlier backup remains.
- Ensure every failure path avoids leaking exception text containing URLs or credential material.
- Add tests for disk full, partial/corrupt audit lines, log rotation and secrets in exception paths.

## Release gate

- [ ] All P0 issues above are closed with evidence links.
- [ ] Native keychain tests pass on every platform claimed as supported.
- [x] Python support floor excludes end-of-life interpreters.
- [ ] Regression, targeted security and mutation suites pass on the release commit.
- [x] Initial dependency audit reported no known vulnerabilities ([run](https://github.com/Loofy147/keyvault/actions/runs/40226816792)); repeat and review exceptions for each release.
- [x] Third-party actions are pinned to reviewed full commit SHAs.
- [ ] Clean wheel/source-distribution install works; package includes the UI asset.
- [ ] Backup/restore, passphrase change, secret rotation and incident recovery are rehearsed.
- [ ] Browser tests pass; UI remains explicitly documented as local-only.
- [ ] README, changelog, threat model, roadmap and compatibility matrix match the evidence.
- [ ] Release artifact is checksummed; build provenance and rollback steps are recorded.
- [ ] License choice and private vulnerability-reporting path are reviewed.

## External guidance

This plan uses guidance for prioritization; it does not claim compliance:
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — least privilege, rotation, lifecycle and audit.
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — validate resolved destinations and avoid DNS time-of-check/time-of-use gaps.
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) — scoped credentials, untrusted tool outputs, validation and sandboxing.
- [OWASP ASVS 5.0](https://asvs.owasp.org/) — a verification catalog for the local web surface; keyvault is not certified or fully assessed against ASVS.
- [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) — immutable action pins and least-privilege workflow permissions.
- [Python supported-version schedule](https://devguide.python.org/versions/) — do not claim support after interpreter end of life.
