# Architecture and trust boundaries

## Purpose

keyvault is a local encrypted credential store with a CLI, stdio MCP server, credential-injecting HTTPS proxy and local-only browser UI. The core property is **use without disclosure**: a tool uses a named credential while the model does not receive the stored value.

## Components

~~~text
                    Trusted local user
                           |
                  +--------+--------+
                  |                 |
               CLI              Local UI
                             (127.0.0.1 only)
                  |                 |
                  +--------+--------+
                           |
                    Vault model / crypto
                           |
              +------------+------------+
              |                         |
       vault.json (AES-GCM)      Session cache
                                 native OS keychain by default
                                 file only by explicit opt-in
                           |
              +------------+------------+
              |                         |
          keyvault run             keyvault serve (stdio)
              |                         |
     third-party process          MCP tools / trusted code
      receives env token           - list_credentials
                                   - http_request
                                          |
                                  policy + HTTP proxy
                                          |
                                    HTTPS API endpoint
~~~

## Data classification

| Data | Classification | Where it may exist |
|---|---|---|
| Master passphrase | Secret | Hidden CLI prompt or transient UI request; environment variable is weaker |
| Derived vault key | Secret | Process memory while in use; native keychain cache by default; explicit weaker file backend |
| Credential value | Secret | Encrypted vault at rest; process memory; intended child environment for run-wrapper; outbound auth field |
| Credential metadata | Private/operational | Encrypted vault and owner UI/CLI; only restricted subset is exposed to MCP |
| Request/response body | Potentially sensitive | Request processing memory; a bounded response subset may return to the model after filtering/redaction |
| Audit events | Sensitive operational metadata | Local JSONL log; should not contain secrets, bodies or credential query values |
| MCP config snippet | Configuration, not secret | Local command, scope and credential names only |

## Trust boundaries

### Encrypted file to crypto layer
The vault file is untrusted input. Validate format version and KDF bounds before expensive derivation. AES-GCM authentication must fail closed on tampering. Never accept unbounded KDF work from a supplied envelope.

### CLI/UI to vault operations
Both interfaces use the same vault model. A blank secret during edit means preserve the current value; explicit nonblank input rotates it. UI fields and request bodies contain transient plaintext while editing, so a local browser compromise remains part of the threat model.

The UI binds only to 127.0.0.1; rejects unexpected Host and Origin; uses a per-process CSRF token; avoids external assets and browser storage; does not return secret values in API responses; and is not an authenticated multi-user service.

### MCP agent to tool boundary
Treat all tool parameters as untrusted model output. The agent provides credential name, URL, method, headers and optional request body. Trusted code must enforce scope and policy regardless of agent instructions.

- list_credentials: metadata only; no secret value, private note or environment variable name.
- http_request: server-side secret attachment; host/method validation; redirects disabled; response-size cap and best-effort redaction.

MCP descriptions and responses are untrusted context, not authorization controls. Actual checks must live in the proxy.

### HTTP proxy to network
Current protection includes HTTPS-only requests except explicitly enabled loopback HTTP for tests, hostname patterns, method restrictions, managed-auth-header protection, disabled redirects, response-size limits and best-effort redaction.

**Unclosed critical gap:** resolved destination IPs are not validated and pinned at connection time. Do not consider the proxy production-ready until the P0 SSRF gate is closed. A hostname allowlist does not prevent DNS rebinding.

### Session cache to running processes
Native OS credential store is the default cache. File backend is an explicit weaker option. TTL and vault-salt binding invalidate stale session items.

The lock command removes the configured session item. It cannot erase secrets already copied into another process's memory or child environment. A process with the explicit passphrase environment variable may continue opening the vault under that independent authority.

## Security assumptions

- The OS account and native keychain are trusted.
- A process with the same OS identity may be able to inspect memory or accessible files; keyvault is not a sandbox against same-user malware.
- The run-wrapper intentionally gives plaintext to the wrapped process.
- The agent has only intended MCP tools unless additional capabilities, such as shell, were explicitly granted.
- The UI is used locally and is not exposed through tunnel, reverse proxy or port forwarding.
- Network destinations and DNS are not trusted merely because a configured hostname matches.

## Non-goals

The current architecture does not provide team multi-tenancy, remote access, centralized identity, distributed audit integrity, OAuth refresh, request signing or safe unrestricted arbitrary-URL access. Those require architecture changes, not UI toggles.

## Design references
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
