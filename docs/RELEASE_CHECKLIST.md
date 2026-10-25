# Production release checklist

A release is blocked until every required item is checked and its evidence link recorded. “Code committed” is not evidence that a control works.

## 1. Scope and ownership

- [ ] Exact release version and commit SHA recorded.
- [ ] Supported OS/Python/MCP-client matrix declared and backed by evidence.
- [ ] License selected and included.
- [ ] Security contact and private vulnerability-reporting route verified.
- [ ] Changelog lists user-visible changes, behavior changes, migrations and known limits.

## 2. Security gates (blocking)

- [ ] DNS/IP policy is enforced at connection time, not only in a prior lookup.
- [ ] IPv4/IPv6 and DNS rebinding tests pass, including private, loopback, link-local, multicast and reserved addresses.
- [ ] Redirects remain disabled unless every hop is separately revalidated.
- [ ] Native OS keychain test matrix passes for every claimed platform.
- [ ] Missing/broken keychain cannot silently fall back to a file.
- [ ] Cross-process writes are serialized or conflicts fail explicitly.
- [ ] Vault and backup crash-recovery tests pass.
- [ ] Secret-bearing input is absent from URLs, CLI arguments, logs, audit, test artifacts and CI output.
- [ ] MCP authorization is enforced in code; tool descriptions are not policy.
- [ ] UI is loopback-only and browser E2E covers Host/Origin/CSRF/XSS/session expiration.
- [ ] Passphrase environment variable, file-cache opt-in and same-user threat boundary are documented prominently.
- [ ] Independent security review findings are closed or explicitly block release.

## 3. Quality gates

- [ ] Full pytest suite passes across supported Python versions on the release commit.
- [ ] Mutation tests pass or every survivor is explained, risk-assessed and assigned an owner.
- [ ] Fuzz/property tests cover URL policy, vault envelopes, metadata, dotenv import and redaction boundaries.
- [ ] Dependency scan has no unresolved high/critical issue; exceptions have owner, reason and expiry.
- [ ] Package builds as wheel and source distribution.
- [ ] Clean-install tests confirm the UI asset is included.
- [ ] Console command and module entry point work after clean install.
- [ ] MCP SDK tests pass; target desktop clients have documented smoke tests.
- [ ] Error behavior remains deliberate, bounded and secret-free.

## 4. Operations and documentation

- [ ] Backup restore drill completed and recorded.
- [ ] Backup purge behavior and encrypted backup semantics tested.
- [ ] Credential rotation and provider revocation runbook exercised.
- [ ] Lock/TTL semantics tested against a live MCP subprocess.
- [ ] Audit retention, file permissions, rotation and tamper limits documented.
- [ ] README, architecture, operations, threat model, roadmap and add-on docs match code.
- [ ] Every environment-variable escape hatch is documented.
- [ ] Known limitations and unsupported environments appear in release notes.

## 5. Supply chain and release artifact

- [ ] Third-party GitHub Actions pinned to full commit SHAs.
- [ ] Workflow permissions are least privilege; fork pull requests cannot access release secrets.
- [ ] Dependency update alerts and a review policy are active.
- [ ] Build logs, artifact hashes and release commit are retained.
- [ ] Artifact installation and checksum verification work in a clean environment.
- [ ] Rollback procedure is tested.
- [ ] No real secrets or live provider credentials were used in tests.

## 6. Sign-off record

| Field | Value |
|---|---|
| Release tag/version | TBD |
| Commit SHA | TBD |
| CI run(s) | TBD |
| Security review | OPEN |
| Backup/restore drill | OPEN |
| Supported-platform evidence | OPEN |
| Residual risks | See PRODUCTION_READINESS.md |
| Decision | **NO-GO until every blocking gate is closed** |
