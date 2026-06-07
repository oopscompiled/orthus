# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.x (pre-release) | Active development |

## Reporting a Vulnerability

**Email:** security@orthus.dev
**Response SLA:** 48 hours acknowledgement, 7 days triage

Please **do not** open public GitHub issues for security vulnerabilities.

## Scope

In scope for responsible disclosure:
- Rules bypass (false negative on known attack patterns)
- Signature verification bypass in rules bundle loading
- Supply-chain vulnerabilities in rules update mechanism
- Decision engine logic errors that cause systematic allow/block failures

Out of scope:
- Theoretical attacks without proof of concept
- Issues in third-party dependencies (report to them directly)

## Recognition

We credit researchers in CHANGELOG unless anonymity is requested.
