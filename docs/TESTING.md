# Testing strategy

## What the current suite establishes

The latest recorded GitHub Actions run before this readiness update passed **62 pytest tests** on Linux/Python 3.12 ([run](https://github.com/Loofy147/keyvault/actions/runs/40225556583)). Coverage includes vault encryption/tampering, session cache logic with test doubles, CLI flows, URL/method restrictions, response filtering, stdio MCP behavior, local UI HTTP/CSRF/Host behavior and embedded JavaScript syntax.

It does **not** establish:
- native OS keychain behavior on macOS/Windows/Linux desktop;
- DNS/IP-pinning or DNS-rebinding protection (not implemented);
- production-grade concurrent writer behavior;
- real-browser end-to-end behavior;
- compatibility with every desktop MCP host;
- resilience against every secret transformation or prompt-injection path.

## Local commands

~~~sh
python -m pip install -e '.[test]'
python -m pytest -q
python tests/mutation_check.py
python tests/live_github_check.py
~~~

The live GitHub check requires internet access and deliberately uses a fake token. Never change it to use a real token. The mutation harness intentionally breaks code in a temporary copy; inspect its output and verify all mutations were applied, tested and correctly classified. A successful process exit alone is not a substitute for reviewing the mutation report.

## Required test layers

### Unit tests
- Vault envelope parse, KDF bounds, wrong passphrase, corruption, permissions and atomic write.
- Credential input and host-pattern validation.
- HTTP URL parsing, methods, managed headers, response truncation and secret-sensitive error paths.
- Session TTL, salt rebinding, lock, backend errors and cache fallback policy.
- UI schemas, sanitized output and audit field filtering.

### Integration tests
- Real stdio MCP SDK client against keyvault.
- Wrapped unrelated MCP server receives only intended environment values.
- Session lock/expiry cuts off a long-running server that relies on the session cache.
- Browser-to-local-UI flows using a browser automation framework.
- Native OS keychain backends on actual OS runners.
- Clean wheel install and packaged UI asset.
- Backup/restore and concurrent-process behavior.

### Security tests
- DNS rebinding and connection pinning, not only string-based URL tests.
- Hostile Origin/Host, CSRF, XSS, clickjacking headers and unexpected content types.
- Prompt-injection-style parameters that attempt to alter scope or exfiltrate credentials.
- Mutation testing for authorization, destination, redaction and session boundaries.
- Secret-canary search over stdout, stderr, audit, traces, artifacts and tool output.
- Fuzz/property tests for URL parser disagreement, IDNA, unusual IPv6 syntax, encoded separators, dotenv edge cases and malformed encrypted envelopes.

## Evidence rules

For each claim, record:
- **Claim:** exact property being asserted.
- **Evidence:** test name, CI URL, OS/runtime, commit SHA and result.
- **Scope:** configuration and threat model covered.
- **Limit:** what the evidence does not establish.
- **Status:** verified, partially verified, contradicted or open.

Never upgrade a claim merely because it has been repeated. Native OS-store behavior requires native OS evidence; a hostname test cannot establish DNS pinning; syntax checking cannot establish browser security.
