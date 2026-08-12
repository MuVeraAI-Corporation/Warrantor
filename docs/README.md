# Documentation

There are over 200 files here. Most of them are design history, and you almost certainly do not need
them. This page exists so you can find the handful that matter to you and ignore the rest.

## Start with these five

| Document | What it answers |
|---|---|
| [**Integrations inventory**](integrations-inventory.html) | What actually connects to what — measured from source, with a column for whether anything *calls* it |
| [**OSS readiness**](oss-readiness.html) | Where this repository is not yet ready to be depended on, and what is being done about it |
| [**Non-developer platform**](non-developer-platform.html) | What people who *oversee* agents need, and what exists for them today |
| [**Publishing runbook**](publishing-runbook.md) | How releases work, and what is still blocked |
| [**Research portfolio**](research-portfolio.html) | Six paper briefs, five whitepapers, and the OSAA benchmark suite — with the experiments each still needs |

The first two are deliberately unflattering. A newcomer who finds a gap themselves trusts the project
less than one we told first.

## By what you are doing

**Understanding the architecture**
- [02-architecture.md](02-architecture.md) — how the pieces fit
- [01-vision-and-portfolio.md](01-vision-and-portfolio.md) — what the platform is for
- [cross-cutting/19-inter-component-protocol.md](cross-cutting/19-inter-component-protocol.md) — how components talk

**Working on security-sensitive code**
- [cross-cutting/21-threat-model.md](cross-cutting/21-threat-model.md) — read before touching authority, crypto or staging
- [cross-cutting/20-error-code-registry.md](cross-cutting/20-error-code-registry.md)
- The two-reviewer rule for these areas is in [GOVERNANCE.md](../GOVERNANCE.md)

**Compliance, audit and risk**
- [cross-cutting/13-compliance-frameworks.md](cross-cutting/13-compliance-frameworks.md) — framework
  mapping, ordered by primary market: US interagency MRM (OCC 2026-13 / Fed SR 26-2), RBI FREE-AI and
  DPDP, SDAIA and DIFC Reg 10, then international and EU. GCC entries await primary-text confirmation.
- [non-developer-platform.html](non-developer-platform.html) — the roles, workflows and evidence

**Contributing**
- [CONTRIBUTING.md](../CONTRIBUTING.md) · [GOVERNANCE.md](../GOVERNANCE.md) · [SUPPORT.md](../SUPPORT.md)
- [rfcs/](rfcs/) — one RFC per component, 131 of them. Find the one for the component you are
  changing; it states what the component is *for*, which is usually more useful than the code.

## The rest, and why it is here

| Directory | What it is | Read it if… |
|---|---|---|
| `rfcs/` | 131 per-component design documents | You are working on that component |
| `html/` | 84 rendered reports and analyses | You are looking for a specific past analysis |
| `cross-cutting/` | Threat model, compliance, protocols, error registry | You are working across components |
| `implementation/` | Tracker state and catalogue | You want the machine-readable status |
| `source-matrix/` | Provenance of the component catalogue | You are tracing why a component exists |
| `decisions/` | *(empty)* | — |
| `wave-*-*.md` | Historical verification reports per delivery wave | Rarely. This is a record of what was checked when |
| `00-reconciliation-matrix.md` | How four earlier strategy portfolios became one catalogue | You are a maintainer wondering why the naming is inconsistent |

## Honest notes about these docs

**They are not uniformly current.** The RFCs describe intended designs, and some components have
moved on while others were never built. Where a document and the code disagree, the code is the
truth — and the [integrations inventory](integrations-inventory.html) is the reconciliation between
them, because it was produced by measuring rather than by reading.

**Naming is inconsistent.** *AumOS*, *DefStack* and *Warrantor* all appear and all mean the same
project. The consolidation onto Warrantor is in progress.

**`decisions/` is empty.** Architecture decision records were planned and not written. The reasoning
that would have gone there is mostly in commit messages and in the RFCs.
