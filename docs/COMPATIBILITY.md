# Compatibility and support matrix

This document separates current test evidence from intended targets. A green Linux run does not establish native behavior on other operating systems.

## Python

The project requires Python 3.11 or newer. Python 3.10 reached end of life on 2026-10-01 and is not a supported target.

| Version | Status | Evidence |
|---|---|---|
| 3.11 | Verified on the readiness revision: 62 passed | [CI matrix run](https://github.com/Loofy147/keyvault/actions/runs/40227286219) |
| 3.12 | Verified on the readiness revision: 62 passed | [CI matrix run](https://github.com/Loofy147/keyvault/actions/runs/40227286219) |
| 3.13 | Verified on the readiness revision: 62 passed | [CI matrix run](https://github.com/Loofy147/keyvault/actions/runs/40227286219) |
| 3.14 | Verified on the readiness revision: 62 passed | [CI matrix run](https://github.com/Loofy147/keyvault/actions/runs/40227286219) |
| 3.10 and earlier | Unsupported | End-of-life / below declared floor |

The supported range must be reviewed when dependencies or Python lifecycle status changes. Python 3.15 is not yet in the declared matrix.

## Operating systems

| OS / environment | Current evidence | Support status |
|---|---|---|
| Linux, Python 3.12, file-cache test mode | MCP stdio integration and regression tests | Partial evidence only |
| Linux desktop Secret Service | Native backend selected by code; test double does not prove integration | Not yet verified |
| Linux headless/no D-Bus | Expected to fail closed unless file backend is explicitly enabled | Needs native failure-path test |
| macOS / Keychain | Native backend selected by code | Not yet verified |
| Windows / Credential Locker | Native backend selected by code | Not yet verified |

## MCP clients

| Client | Status |
|---|---|
| MCP Python SDK stdio client | Integration tests exist |
| Claude Desktop | Not yet verified |
| Cursor | Not yet verified |
| Other clients | Not yet verified |

Before claiming client compatibility, record client version, OS, transport, configuration snippet, startup behavior, lock/expiry behavior and evidence of no secret disclosure.

## Release policy

Do not label an operating system, runtime or MCP host “supported” based on code inspection alone. Require reproducible tests on that environment and keep the evidence linked to the exact commit.
