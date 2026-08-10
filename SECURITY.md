# Security Policy

> How AumOS handles vulnerability reports, CVEs, and coordinated disclosure.
> Adopted verbatim from `docs/cross-cutting/14-security-disclosure-policy.md`.

## Reporting a Vulnerability

### Private Disclosure (Preferred)

Email: **security@warrantor.dev** (PGP key: published at `https://warrantor.dev/security/pgp-key.asc`).

**Do NOT open a public GitHub issue for security vulnerabilities.**

Include:
- Component name and version (e.g. `aumos-trust-core 1.0.0`)
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (optional)
- Your name/handle for credit (optional)

### GitHub Security Advisory

Use the "Security" tab → "Report a vulnerability" feature. This creates a private advisory visible
only to maintainers.

## Response SLAs

| Severity | Acknowledgement | Initial Assessment | Fix / Mitigation | Public Disclosure |
|----------|-----------------|-------------------|-------------------|-------------------|
| **Critical** (RCE, auth bypass, signature forgery, data exposure) | 4 hours | 24 hours | 7 days | 30 days |
| **High** (privilege escalation, DoS, sandbox bypass) | 8 hours | 72 hours | 30 days | 60 days |
| **Medium** (info disclosure, check bypass) | 24 hours | 7 days | 90 days | 120 days |
| **Low** (hardening, best practice) | 72 hours | 14 days | Next release | 180 days |

## Coordinated Disclosure

We follow **90-day disclosure** (Google Project Zero standard): reporter reports → we acknowledge
within SLA → we develop fix → fix released → public disclosure after fix is widely deployed (or
90 days, whichever is sooner). Extensions granted for good cause.

## Security-Critical Components

These components get the strictest review and the fastest SLA treatment (per
`docs/02-architecture.md` §5 — the trusted core boundary):

- T1 trust-core (sign / verify / canonical)
- R2 eval-guard (sandbox boundary attestation)
- R3 kill-switch (execution layer)
- R4 credential-vault (credential brokering)
- C1-1 nvtrust-bridge (attestation verification)
- All eBPF components (R7 egress-filter, S6 exfil-guard — Wave 6)

## Contacts

- **General security:** security@warrantor.dev
- **Critical incidents:** security-critical@warrantor.dev (paged 24/7 once the on-call rotation is live)
- **PGP key:** https://warrantor.dev/security/pgp-key.asc

## What We Promise

- We will acknowledge every report within the SLA.
- We will credit reporters (unless they prefer anonymity).
- We will not take legal action against good-faith reporters.
- We will work with reporters on coordinated disclosure.
- We will be transparent about timelines and any delays.
