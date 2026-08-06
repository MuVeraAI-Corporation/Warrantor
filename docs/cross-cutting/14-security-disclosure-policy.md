# Security Disclosure Policy

> How DefStack handles vulnerability reports, CVEs, and coordinated disclosure.

## Reporting a Vulnerability

### Private Disclosure (Preferred)

Email: **security@defstack.org** (PGP key: `security@defstack.org`.pub)

**Do NOT open a public GitHub issue for security vulnerabilities.**

Include:
- Component name and version
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (optional)
- Your name/handle for credit (optional)

### GitHub Security Advisory

For components hosted on GitHub, use the "Security" tab → "Report a vulnerability" feature. This creates a private advisory visible only to maintainers.

### Bug Bounty (Planned Q2 2027)

We plan to launch a bug bounty program on HackerOne by Q2 2027 (post-Series A). Until then, we credit reporters in release notes and provide DefStack swag.

## Response SLAs

| Severity | Acknowledgement | Initial Assessment | Fix / Mitigation | Public Disclosure |
|----------|----------------|-------------------|-------------------|-------------------|
| **Critical** (RCE, auth bypass, data exposure) | 4 hours | 24 hours | 7 days | 30 days |
| **High** (privilege escalation, DoS) | 8 hours | 72 hours | 30 days | 60 days |
| **Medium** (info disclosure, bypass) | 24 hours | 7 days | 90 days | 120 days |
| **Low** (hardening, best practice) | 72 hours | 14 days | Next release | 180 days |

## CVE Assignment

DefStack is a **CNA (CVE Numbering Authority)** candidate (apply by M9). Until then:
- Request CVEs through MITRE: https://cveform.mitre.org
- For critical issues, request expedited assignment

## Coordinated Disclosure

We follow **90-day disclosure** (Google Project Zero standard):
- Reporter reports vulnerability
- We acknowledge within SLA
- We develop fix
- Fix released
- Public disclosure after fix is widely deployed (or 90 days, whichever is sooner)
- Extensions granted for good cause (e.g., complex fix requiring major version)

## Fix Backporting

| Version | Support Status | Backport Window |
|---------|---------------|-----------------|
| Current major (v1.x) | Active | All fixes backported |
| Previous major (v0.x) | Maintenance | Critical/High only |
| Older | End of life | No backports; upgrade required |

## Security Advisories

All advisories published to:
1. GitHub Security Advisories (per-repo)
2. defstack.org/security/advisories
3. oss-security mailing list (for Critical/High)
4. NVD (after CVE assignment)

## Incident Response

For critical vulnerabilities with active exploitation:

1. **War room activated** within 4 hours
2. **Patch developed** within 24 hours (critical) or 72 hours (high)
3. **Out-of-band release** — do not wait for scheduled release
4. **Customer notification** — email all known affected users
5. **Public advisory** — within 24 hours of fix release
6. **Post-mortem** — within 7 days, published publicly

## Security Contacts

- **General security:** security@defstack.org
- **Critical incidents:** security-critical@defstack.org (paged 24/7)
- **PGP key:** https://defstack.org/security/pgp-key.asc
- **Security team lead:** CISO (to be hired by M6)

## What We Promise

- We will acknowledge every report within the SLA
- We will credit reporters (unless they prefer anonymity)
- We will not take legal action against good-faith reporters
- We will work with reporters on coordinated disclosure
- We will be transparent about timelines and any delays
