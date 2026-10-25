# Changelog

User-visible changes are recorded here. Unreleased entries are not a release guarantee.

## Unreleased — production-readiness work

- Added a formal readiness gate, prioritized roadmap, add-on portfolio, architecture/trust-boundary guide, operations runbook, release checklist, testing strategy, vulnerability-reporting policy and contributor instructions.
- Identified DNS/IP destination pinning, real native keychain validation, cross-process writer safety, backup lifecycle and browser E2E coverage as release gates.
- CI hardening and supported-Python changes are part of this readiness work; only completed runs tied to exact commits count as evidence.

## 0.1.0 — initial repository baseline

- Local encrypted vault using scrypt and AES-256-GCM.
- CLI credential management and environment import.
- Environment injection for child processes via run-wrapper.
- stdio MCP server with scoped credentials and server-side HTTP requests.
- Native OS keychain session cache by default, with explicit weaker file-cache fallback.
- Local-only web UI for credentials, session control, audit view and scoped MCP config generation.
