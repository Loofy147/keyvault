# Operations runbook

These steps describe current local behavior. Do not assume a passing test makes unverified platforms production-supported.

## First-time setup

1. Install in an isolated environment: **pip install -e .**
2. Initialize with a strong, unique passphrase: **keyvault init**.
3. Add credentials through hidden input. Do not place values in command-line arguments.
4. Use exact hostnames and the smallest required method set. Keep GET/HEAD by default unless writes are necessary.
5. Unlock for the shortest practical duration: **keyvault unlock --ttl 30m**.
6. Start the UI with **keyvault ui** or use the CLI. Keep the UI on loopback only.
7. Generate an MCP snippet with a narrow allowlist, then inspect its command and arguments before enabling it in the client.

## Session modes

### Native OS credential store (default)
- macOS: Keychain.
- Windows: Credential Locker.
- Linux: Freedesktop Secret Service; a usable user session/keyring must be available.
- Missing/unavailable native storage should fail closed.

Native platform integration is not established by Linux CI alone. Check the compatibility evidence in PRODUCTION_READINESS.md.

### Explicit file-cache fallback

Set **KEYVAULT_SESSION_BACKEND=file** only when native credential service is unavailable and the reduced protection is understood. Configure it consistently in CLI and every MCP client environment. The fallback is not equivalent to a native OS keychain.

## Locking and expiry

- Use short TTLs, especially when agents have shell or filesystem tools.
- Run **keyvault lock** when done.
- Locking removes the configured session cache but cannot erase values already copied into process memory, child environments or logs outside keyvault's control.
- An explicit **KEYVAULT_PASSPHRASE** may independently authorize processes; remove it from environments that do not need it.
- Do not assume a child launched with a credential can be revoked by locking the vault. Revoke the provider credential if compromise is suspected.

## Backup caution and recovery

The vault uses **vault.json** and may retain an encrypted **vault.json.bak** from a previous write. The backup may contain deleted or rotated values encrypted under the prior vault state. Encryption at rest does not mean that old values have been erased.

Before copying backups:
- Lock keyvault.
- Restrict the backup directory to the owner.
- Never upload the vault, backup or session cache to public issue trackers or chat.
- Keep backup-passphrase handling separate from the backup file.
- Record a checksum and restore-test date without recording secrets.

**Restore requires a tested recovery path.** Until a dedicated backup/restore/purge command is shipped, manual replacement of vault.json is an expert operation. Preserve current files first, work in a private copy, and verify passphrase and metadata before replacing anything.

After deletion or rotation, do not treat an old value as unrecoverable while an older backup remains. A passphrase change currently removes the old-key backup but also changes the vault passphrase; it is not a substitute for a dedicated, separately reviewed purge operation.

## Suspected credential exposure

1. **Contain:** run **keyvault lock**, then stop affected MCP clients and wrapped child processes where possible.
2. **Revoke upstream:** disable the provider credential first. Keyvault cannot invalidate a token at its provider.
3. **Rotate:** create a new least-privilege token and update the keyvault entry using CLI or UI.
4. **Inspect:** review **keyvault audit** and the UI audit trail. Check host/method scope and denied requests.
5. **Clean up:** investigate backups, client configs, shell history, terminal capture, CI logs and child process environments. Never publish the affected secret while asking for help.
6. **Revalidate:** use fake credentials to run policy/integration tests and search outputs, logs and audit for secret leakage.
7. **Record:** document timeline, credential name/provider, revocation timestamp, observed access and residual uncertainty—never the secret itself.

## Local UI safety

- Run **keyvault ui** on a trusted desktop/local machine.
- Do not use the port option as a remote exposure mechanism.
- Do not put the UI behind a reverse proxy, tunnel, port-forward, public ingress or LAN bind.
- Stop the UI when not in use.
- Consider a dedicated browser profile if extensions and other local web apps are outside the trust boundary.
- Never send the UI passphrase, browser devtools data, request body or screenshot to an untrusted party.

## Routine checks

- Before changes: confirm backups exist securely and recovery steps are understood.
- After changes: inspect allowed hosts, methods and per-MCP scopes.
- Periodically: verify credential validity with safe provider-specific checks; rotate/revoke according to provider policy.
- For an incident: prefer immediate upstream revocation over relying on local cache expiry.
- Before release: perform docs/RELEASE_CHECKLIST.md.
