# Changelog

User-visible changes are recorded here. Unreleased entries are not a release guarantee.

## Unreleased — production-readiness work

- Added a formal readiness gate, prioritized roadmap, add-on portfolio, architecture/trust-boundary guide, operations runbook, release checklist, testing strategy, vulnerability-reporting policy and contributor instructions.
- Identified DNS/IP destination pinning, real native keychain validation, cross-process writer safety, backup lifecycle and browser E2E coverage as release gates.
- Removed Python 3.10 from the declared support range after its 2026-10-01 end-of-life date; CI now tests Python 3.11–3.14, with 62 tests passing on each in the recorded matrix run ([CI](https://github.com/Loofy147/keyvault/actions/runs/40226816791)).
- Pinned GitHub Actions to reviewed full commit SHAs, added weekly dependency auditing and Dependabot update proposals, and added a manual mutation-test workflow.
- Initial pip-audit run reported no known vulnerabilities ([security CI](https://github.com/Loofy147/keyvault/actions/runs/40226816792)).

## 0.1.0 — initial repository baseline

- Local encrypted vault using scrypt and AES-256-GCM.
- CLI credential management and environment import.
- Environment injection for child processes via run-wrapper.
- stdio MCP server with scoped credentials and server-side HTTP requests.
- Native OS keychain session cache by default, with explicit weaker file-cache fallback.
- Local-only web UI for credentials, session control, audit view and scoped MCP config generation.
