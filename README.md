# keyvault

A local, encrypted vault for API keys and bearer tokens, with two ways to hand them to MCP servers and agents **without pasting secrets into config files or chat**.

| Use case | Command | What the other side gets |
|---|---|---|
| A third-party MCP server (or any program) that reads a token from its environment | `keyvault run CRED -- COMMAND ...` | the token, as an env var, at launch |
| An agent that needs to call REST APIs | `keyvault serve` (an MCP server on stdio) | tools `list_credentials` and `http_request`. The agent names a credential; keyvault attaches the secret itself. **No tool returns a secret.** |

Your MCP client config then holds credential *names*, never tokens.

## Install

    python -m venv .venv && . .venv/bin/activate
    pip install -e .            # Python >= 3.10; pulls mcp>=2, cryptography, httpx, keyring

## Quick start

    keyvault init
    keyvault add github --provider github --kind bearer --host api.github.com \\
        --env-var GITHUB_TOKEN --methods GET,POST      # secret via hidden prompt (or --value-stdin)
    keyvault import-env .env --dry-run                 # gather many at once; prints names only
    keyvault unlock --ttl 8h                           # lets non-interactive clients open the vault
    keyvault list

    keyvault snippet serve --allow github              # JSON for your client's mcpServers section
    keyvault snippet run github -- npx -y <mcp-server-package>

Secrets are only ever read from a hidden prompt or stdin, never from command-line arguments.

## Local web UI

Run `keyvault ui` to open the control panel at `http://127.0.0.1:8765/`. Use `keyvault ui --port 0 --no-browser` to choose an ephemeral port and print the URL without launching a browser. The first-run screen can create a vault; existing vaults can be unlocked for a selected TTL.

The UI provides credential creation, editing and rotation; host and method allowlists; session unlock/lock; a sanitized audit trail; and a **scoped MCP config builder** that generates a client entry with only the credentials you select. The UI never returns secret values from its API, and leaves the secret blank when editing so an existing value is preserved unless you explicitly enter a rotation value. The passphrase and any newly entered secret exist transiently in the page and local request body; they are not put in browser storage, URLs, request logs or audit events.

**Keep this service local.** The built-in server binds only to `127.0.0.1`, validates Host and Origin headers, requires a per-process request token for state changes, sets restrictive browser security headers, rate-limits failed passphrase attempts, and makes no external requests. Do not expose it through a reverse proxy, public tunnel, port forward or LAN bind. It uses the same session cache as the CLI/MCP server, so `Lock vault` invalidates that cached session for processes using it. If `KEYVAULT_PASSPHRASE` is set in the launching environment, the CLI may still unlock independently of the UI session; the UI warns about this.

## Credential settings

- `--kind`: `bearer` (Authorization: Bearer), `header` (+ `--header-name`), `query` (+ `--param-name`), `basic` (secret is `user:password`), or `none` (env-only; invisible to agents).
- `--host` (repeatable; `*.example.com` matches subdomains only): the only hosts the secret may ever be sent to.
- `--methods`: HTTP methods agents may use; default `GET,HEAD` (read-only).
- `--env-var`: variable name used by `keyvault run` (`-e VAR=CRED` overrides per command).
- `--provider`, `--tag`: shown to agents. `--note`: private, never shown to agents.
- Scope each agent separately: `keyvault serve --allow a,b`.

## What `http_request` enforces

https only; host must match the credential's list; method must be enabled; redirects are **not** followed (the 3xx is returned); callers cannot set the auth header or the credential's query parameter; responses are text-only and capped (100 KB, `--max-bytes`); the secret (raw, URL-encoded and base64 forms) is redacted from the body and from the few response headers returned. Every call and every denial goes to `audit.log` (no secrets, no bodies, query *keys* only). `keyvault audit` shows it.

## How the vault is stored

scrypt (default N=2^17) -> AES-256-GCM. The KDF parameters are authenticated, so editing them in the file makes decryption fail. Fresh nonce per write, atomic write, mode 0600. One previous version is kept as `vault.json.bak` (still encrypted); `keyvault passwd` removes it.

## Limits you should know about

- **Anything running as you can read secrets while the vault is unlocked** (`keyvault get/run`, or the session cache). The proxy only protects secrets from an agent that has *only* the MCP tools. If an agent also has a shell tool, don't leave an unlocked session around: short `--ttl`, `keyvault lock`. `get` and `run` are audited.
- `keyvault run` hands the plaintext token to the wrapped program; that is what it is for.
- `unlock` caches the *derived key* in the native OS credential store by default: macOS Keychain, Windows Credential Locker, or Linux Freedesktop Secret Service. The key becomes unusable after its TTL, is bound to the vault's current salt, and is removed by `keyvault lock`; an expired item is deleted the next time keyvault checks it. The native store must be available; keyvault does not silently fall back to a file.
- On a headless system without a usable native credential service, you can explicitly opt into the legacy mode-0600 session file by setting `KEYVAULT_SESSION_BACKEND=file` in **every environment that launches keyvault**, including MCP client environments. The file lives under `$XDG_RUNTIME_DIR/keyvault/` if set, otherwise under `~/.keyvault/`. This is a weaker security choice. `keyvault snippet` propagates this setting when it is present.
- `KEYVAULT_PASSPHRASE` also works for unattended access, but exposes the passphrase to the process environment and is weaker than interactive unlock.
- Redaction is best effort: an API that echoes a *transformed* secret can get past it.
- No DNS/IP checks: a wildcard host pattern trusts DNS under that domain.
- One secret per credential: no request signing (HMAC, AWS SigV4), no multi-header schemes, no OAuth refresh.
- Remote (HTTP) MCP servers that need a bearer header are not covered.
- Concurrent writers: last write wins.
- Native keychain backends are selected explicitly rather than through keyring's automatic backend selection, which can include third-party or file-backed stores. Linux requires a working Secret Service/D-Bus session. If it is unavailable, unlock fails closed unless `KEYVAULT_SESSION_BACKEND=file` is deliberately set.
- Session cache tests use an in-memory keychain double. Real native keychain behavior still needs platform-specific verification on Linux desktop/headless, Windows Credential Locker, and macOS Keychain.
- Tested on Linux with Python 3.12 and mcp 2.3.0. The MCP side was exercised with the MCP Python SDK client over stdio, not with specific desktop clients. Windows/macOS are untested (`run` uses an untested subprocess fallback on non-POSIX).

## Tests

    pip install -e '.[test]' && pytest         # 62 tests in the current Linux/Python 3.12 CI run (runtime depends on platform and scrypt performance)
    python tests/mutation_check.py             # breaks 26 behaviours on purpose, expects a test to fail each time
    python tests/live_github_check.py          # needs internet: real HTTPS call with a FAKE token
