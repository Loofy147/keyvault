# Add-on feature portfolio

The order assumes the production blockers remain open. The feature with the most immediate user-visible appeal is not necessarily the next feature to implement.

| Rank | Add-on | User value | Risk / dependency | Decision |
|---|---|---|---|---|
| A0 | DNS/IP-pinned HTTP proxy | Prevents sending credentials to private/internal destinations through DNS tricks | Security-critical transport work, tests and review | **Required before production** |
| A0 | Writer locking and backup lifecycle | Prevents lost updates and clarifies deleted-secret recovery | Cross-platform filesystem semantics | **Required before production** |
| A1 | Generic HMAC signing profiles | Supports APIs requiring request signatures | Canonicalization errors can invalidate signatures or leak keys | After core security review |
| A1 | AWS SigV4 adapter | Supports a major signed API family | Separate canonical request, date/key derivation and scope rules | Provider-specific adapter |
| A1 | OAuth refresh and revocation | Reduces manual expiry handling | Refresh-token lifecycle, scopes, concurrency and provider behavior | After lifecycle model |
| A1 | Encrypted backup/restore | Recovery from device loss or vault corruption | Exports become portable high-value ciphertext | Build with recovery gate |
| A1 | Expiry/rotation reminders | Makes lifecycle visible; reduces stale credentials | Metadata may be misleading when providers do not report status | After lifecycle schema |
| A2 | Read-only credential health checks | Detects invalid tokens and misconfiguration | Endpoint may have side effects or expose sensitive error body | Explicit opt-in; no body by default |
| A2 | Audit export/tamper evidence | Easier incident review and portable records | Hash chains do not stop an administrator rewriting the whole local log | Sanitized export; state limitations |
| A2 | Named per-agent access profiles | Reduces repetitive MCP setup | Scope mistakes and stale config drift | Single policy source of truth |
| A2 | UI quality improvements | Session countdown, keyboard navigation, risk cues | Must not add external dependencies or weaken loopback-only guard | Only after browser E2E |
| A3 | Remote/team UI | Multi-device and shared operations | Requires identity, authorization, TLS, isolation, audit attribution and recovery | Separate security design |
| A3 | Multi-header auth/client certificates | Supports advanced providers | Credential composition and TLS-key handling broaden the threat model | Separate adapter contract |
| A3 | Remote HTTP MCP transport | Remote access and centralized hosting | Requires MCP auth, identity, transport, isolation and replay defenses | Not a small add-on |

## Add-on design contracts

### HMAC request signing
- Use a typed signer interface rather than spreading provider logic through the proxy.
- Define the canonical request byte-for-byte: method, path, query ordering/escaping, selected headers, body digest and timestamp.
- Keep signing keys in the vault; never expose them to tools or UI responses.
- Validate against upstream official vectors and independently written vectors.
- Specify clock-skew limits, replay behavior and retry rules.
- Do not label a generic HMAC adapter AWS-compatible. SigV4 requires its own provider-specific implementation.

### OAuth refresh
- Model access and refresh tokens separately, with scopes, token endpoint, expiry and revocation behavior.
- Serialize refresh operations to avoid concurrent refresh-token races.
- Do not log token endpoint bodies or authorization responses.
- Require configured approved issuer/token endpoints; do not accept arbitrary agent-provided URLs.
- Return explicit reauthorization errors; never silently widen scopes.

### Backup and restore
- Use a versioned encrypted format rather than plaintext exports by default.
- Validate envelope, KDF bounds and authentication tag before replacing an existing vault.
- Include a dry-run/inspect mode that outputs metadata only.
- Require confirmation before overwrite and retain a recoverable prior copy.
- Separate backup purge from passphrase changes and explain which prior values become unrecoverable.

### Credential health checks
- Each provider profile specifies an approved health endpoint and permitted method.
- Default output is status code, latency and a sanitized outcome label; discard bodies.
- Make checks opt-in and rate-limited.
- An unsuccessful response must never trigger automatic rotation or permission broadening.

## Definition of an accepted add-on

- [ ] Threat-model change documented.
- [ ] Input and output schemas validated in trusted code.
- [ ] Least privilege preserved, including per-server scope.
- [ ] Secret values excluded from agent output, UI output, logs and audit.
- [ ] Failure, timeout, retry and concurrency semantics specified.
- [ ] Unit, integration, negative, mutation and provider-vector tests added.
- [ ] README, architecture, operations and incident documentation updated.
- [ ] Backward compatibility and rollback tested.
