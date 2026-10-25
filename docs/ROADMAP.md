# keyvault roadmap

Prioritize risk reduction and evidence over feature count. Add-ons do not bypass release blockers. A checkbox is complete only when the stated artifact or test evidence exists.

## Phase 0 — Baseline established

- [x] Encrypted local vault using scrypt and AES-256-GCM.
- [x] CLI for credential CRUD, environment import, child-process injection, session unlock/lock and audit viewing.
- [x] stdio MCP server with scoped credential use and server-side HTTP credential attachment.
- [x] Native OS keychain is the default session cache; file cache is explicit opt-in.
- [x] Local-only UI for credential management, session controls, audit view and scoped MCP configuration.
- [x] Linux/Ubuntu CI matrix: 62 passed each on Python 3.11, 3.12, 3.13 and 3.14 ([CI evidence](https://github.com/Loofy147/keyvault/actions/runs/40227286219)).
- [ ] Real-browser end-to-end tests; current UI coverage includes server-side HTTP checks and JavaScript syntax validation, not full browser automation.
- [ ] Establish release owner, license choice, supported-platform matrix and vulnerability-reporting route.

## Phase 1 — Close security blockers (P0)

### HTTP destination control
- [ ] Implement destination-IP policy for the credential proxy.
- [ ] Enforce validated-address connection pinning to close DNS rebinding/time-of-check-time-of-use gaps.
- [ ] Cover A/AAAA, IPv4-mapped IPv6, private/loopback/link-local/multicast/reserved addresses and mixed DNS answers.
- [ ] Add rebinding and retry tests; verify TLS hostname validation and SNI are retained.
- [ ] Obtain independent review of the transport boundary.

### Session and native keychain
- [ ] Add real native keychain integration tests for macOS, Windows and Linux Secret Service.
- [ ] Test unavailable/keychain-locked/backend-exception states and prove no implicit file fallback.
- [ ] Document exact lock semantics, including processes that use an explicit passphrase environment variable.
- [ ] Do not describe file-cache opt-in as equivalent protection.

### Vault integrity and recovery
- [ ] Implement cross-process writer locking or revision-based conflict detection.
- [ ] Add crash/fault-injection tests for atomic writes and backup updates.
- [ ] Design explicit encrypted backup restore and purge commands, including the fact that deletion/rotation can leave the prior secret in the backup.
- [ ] Add corruption/malformed-envelope fuzzing and verify bounded KDF resource use.

### Local UI
- [ ] Add browser-driven end-to-end tests for create/unlock/lock/CRUD/MCP snippet/audit.
- [ ] Test hostile metadata, XSS payloads, CSRF, Host/Origin rejection and state races.
- [ ] Verify passphrases/new secret values are cleared from the UI after all success and error paths.
- [ ] Retain loopback-only bind; no LAN or remote deployment in this phase.

**Exit gate:** every P0 issue is closed, with tests and review links recorded in PRODUCTION_READINESS.md.

## Phase 2 — Hardening and operations (P1)

- [ ] Define audit event schema/version, retention/rotation, integrity expectations and filesystem failure behavior.
- [ ] Verify secret-bearing material is absent from error text, request URLs, logs, audit, traces and CI artifacts.
- [ ] Add safe backup/restore and a recovery drill.
- [ ] Add a user-confirmed backup purge that explains the recovery consequences.
- [ ] Add per-credential request rate limits and response budgets; test them.
- [ ] Add fuzz/property testing for credential validation, URL parsing, envelopes, dotenv parsing and redaction boundaries.
- [x] Add a manual mutation-check workflow.
- [ ] Run and review mutation results against the current code state.
- [x] Add dependency vulnerability scanning; the initial scan reported no known vulnerabilities ([run](https://github.com/Loofy147/keyvault/actions/runs/40227286267)).
- [ ] Document a bounded vulnerability-exception process covering risk, owner, expiry and re-review date.
- [ ] Add a reproducible locked dependency set for release/test builds and audit the exact resolved set used for release artifacts.
- [x] Pin GitHub Actions to full immutable commit SHAs and maintain minimal permissions.
- [x] Move the supported Python floor to 3.11; Python 3.10 reached end of life on 2026-10-01.

## Phase 3 — Compatibility and packaging (P1)

- [x] Run CI across Python 3.11–3.14 while those interpreters remain supported ([matrix result](https://github.com/Loofy147/keyvault/actions/runs/40227286219)).
- [ ] Run OS-native keychain jobs on macOS, Windows and Linux.
- [ ] Add smoke tests for Claude Desktop, Cursor and one additional MCP client; record exact tested versions/configurations.
- [ ] Build wheel and source distribution; install in a clean environment and verify the packaged UI loads.
- [ ] Add install/uninstall/upgrade guidance and a tested rollback.
- [ ] Choose and add an open-source license before presenting the repository as a reusable open-source package.
- [ ] Publish support policy, changelog and artifact checksums.

## Phase 4 — Add-ons after core safety

1. **Generic HMAC signing profiles:** byte-exact canonicalization contract, test vectors, managed headers and replay/timestamp controls.
2. **AWS SigV4 adapter:** separate provider-specific implementation with official test vectors; SigV4 is not a generic HMAC mode.
3. **OAuth lifecycle support:** refresh-token storage, scopes, expiry and revocation, after lifecycle/audit semantics are established.
4. **Credential lifecycle metadata:** owner/purpose, last used, rotation due date and expiration reminders.
5. **Safe health checks:** explicitly read-only connection tests; never print response bodies or secrets.
6. **Audit export/integrity helpers:** sanitized JSONL export; optional hash chaining for tamper evidence, not tamper prevention.
7. **Encrypted backup/restore:** versioned export format, integrity verification and recovery drill.
8. **UI quality of life:** session countdown, per-MCP profiles, broad-wildcard warnings and dangerous-method warnings.

## Phase 5 — New security design required

- [ ] Remote/web-accessible UI, multi-user roles or shared/team vault.
- [ ] Remote HTTP MCP transport.
- [ ] Automatic arbitrary command execution from the UI.
- [ ] Unrestricted URL proxying or trusting arbitrary DNS destinations.
- [ ] Cloud sync without an end-to-end encryption and recovery design.

## Change-control rule

Every feature proposal must name its threat-model effect, required permissions, failure modes, tests, documentation changes and rollback path. A commit alone does not complete an item; repeatable evidence and the release gate do.
