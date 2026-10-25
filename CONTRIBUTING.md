# Contributing

## Setup

Use a currently security-supported Python version. The project requires Python 3.11 or newer. Python 3.10 reached end of life on 2026-10-01.

~~~sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
python -m pytest -q
~~~

Run the mutation harness when changing a security boundary:

~~~sh
python tests/mutation_check.py
~~~

The live GitHub check uses a deliberately fake token and requires network access:

~~~sh
python tests/live_github_check.py
~~~

Never insert or use a real credential in tests, fixtures, screenshots, test output or CI artifacts.

## Required for every pull request

- [ ] State the user problem and intended behavior.
- [ ] Name affected trust boundaries and attacker capabilities.
- [ ] Add positive and negative tests, including a regression test for the original failure.
- [ ] Show evidence run and exact commit SHA.
- [ ] Update README and relevant architecture/operations/security/roadmap docs.
- [ ] Keep credentials/passphrases out of arguments, output, logs, URLs and fixtures.
- [ ] Keep CLI, MCP and UI aligned to one policy model.
- [ ] Explain compatibility, migration, failure modes and rollback.
- [ ] Record known gaps; do not label untested behavior production-ready.

## Security-sensitive changes

Changes to crypto, session caching, request authorization, DNS/IP handling, audit, redaction, permissions or MCP contracts require:
1. a threat-model update;
2. targeted adversarial tests;
3. mutation coverage or a documented reason a property cannot be mutated;
4. review of logs/errors/audit for secret disclosure;
5. a production-readiness status update.

## Commit discipline

Prefer small commits mapping to one concern. Never commit live vaults, encrypted backups, session-cache files, .env files, credentials, logs or real request captures. Keep dependency updates reviewable and pin third-party GitHub Actions using immutable full commit SHAs.
