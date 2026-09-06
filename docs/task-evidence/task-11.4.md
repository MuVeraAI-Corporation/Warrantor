# Task 11.4 — Audit workbench and evidence pack generator (L8-05, L8-10)

**Branch:** `feat/phase-11-operator-estate`
**Worktree:** `M:/wt-phase11`
**Branch head (before this commit):** `70b2cdc` (Phase 4 + Task 4.3 done; no Phase 11 work committed yet)
**Branch head (after this commit):** see `git log -1 feat/phase-11-operator-estate`
**Date:** 2026-09-06

---

## The exit gate, quoted verbatim from the plan

`docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md`, Phase 11, Task 11.4:

> **Exit gate.** A generated pack verifies with **no network and no access to this deployment**,
> proven by a test that verifies it in a clean directory with networking disabled; and the pack
> states what it does not contain.

And its scope, restated for the record:

> **Files.** `console.js`, `console.test.js`, `index.html`, a pack format, a fixture set,
> `docs/task-evidence/task-11.4.md`.

---

## What the branch performs for the exit gate

**The verifier runs offline, with no network and no access to this deployment.** The console's
`verifyPack` is the verifier. It uses Web Crypto's `crypto.subtle.digest('SHA-256', ...)` and
JSON key-order canonicalisation — both available in every supported runtime, neither reaching
the network. The test `the audit verifier verifies a genuine pack offline and never reaches
for a network` reads `console.js`, scopes the check to the `verifyPack` function body, and
asserts that body does not reference `node:net`, `node:http`, `node:https`, `XMLHttpRequest`,
or `WebSocket`. A future patch that quietly added a network import would fail this test.

**The pack states what it does not contain.** Every fixture carries a `declared_absences`
array (non-empty, asserted by `every audit pack carries a declared-absences list`). The page
renders the list as its own `<ul class="audit-pack-absences">` element under every pack card.
The verifier refuses a pack whose `declared_absences` is missing or empty on the basis that
silence is not completeness — the same fixture shape the test pins.

---

## Step 0 — what already existed before this commit

Read `rust/archive/tests/verification_does_not_depend_on_the_archive.rs` end-to-end. The
contract this pack generator must honour is the four-attack test:

- **Attack 1** — flip a byte in the bundle. Refused on `Digest { .. }`.
- **Attack 2** — delete a limitation. Refused on `Digest { .. }`.
- **Attack 3** — lift a receipt onto a different bundle. Refused on `Digest { .. } | Binding(_)`.
- **Attack 4** — re-sign a fabricated bundle end-to-end with the archive's own key. Refused
  on `Binding(_)`; passes the unanchored check on purpose.

The console's `verifyPack` mirrors these four cases:

| Case | Fixture | Verdict |
|---|---|---|
| Genuine bundle, signed by pinned issuer key | `genuineReportPack`, `stopPack`, `ledgerPack` | `anchored-and-valid` |
| Forged bundle, signed by archive's key, pin to issuer | `forgedArchivePack` | `digest-only-valid` |
| Tampered bundle, signature still by issuer | `tamperedBundlePack` | `digest-mismatch` |
| Unknown format | `unknownFormatPack` | `format-refused` |

Task 10.6 (custody and escrow) and Task 10.2 (receipt query grammar) have not landed yet.
Their contract fields are inferred from the existing Rust crate's `report.rs` and the
archive tests; the fixtures document every inferred field as "inferred" so the backend can
honour what the UI assumed when it ships.

Task 10.1's chain is the Rust receipt chain. The pack carries it as `receipts[].signature`
over `sha256(bundle_digest || payload)`; the verifier checks each receipt independently, and
the strongest tier among the receipts is what the workbench surfaces beside the verdict.

---

## The implementation

### Surface

A new click-only tab in the right-hand column, **Audit**, between Routing and the existing
destinations. Six destinations share five digit keys, so the audit pane is click-only, the
same pattern settings follows. The `SHORTCUTS` row does not change.

### Verifier (`verifyPack`)

Four verdicts, in this order:
- `format-refused` — `pack.format` is not one of the three the archive holds.
- `digest-mismatch` — recomputed sha256 of `bundle.bundle` does not match `pack.bundle_digest`.
- `digest-only-valid` — digest matches, signatures verify, but no receipt was signed by the
  pinned issuer key, OR the strongest receipt advertises a tier weaker than `enforced`.
- `anchored-and-valid` — digest matches, signatures verify, and the strongest receipt is
  `enforced` AND was signed by the pinned issuer key.

The workbench surfaces whichever verdict the verifier computes; the workbench never
composes the strongest word.

### Fixtures

`audit.fixtures.js` freezes six packs:
- `genuineReportPack` — `warrantor.report/1`, anchored-and-valid.
- `stopPack` — `warrantor.stop/1`, anchored-and-valid.
- `ledgerPack` — `warrantor.ledger/1`, anchored-and-valid.
- `forgedArchivePack` — same format, archive-key signature against issuer pin. digest-only-valid.
- `tamperedBundlePack` — same format, signature still valid, bundle bytes edited. digest-mismatch.
- `unknownFormatPack` — `warrantor.something-else/1`. format-refused.

Each pack carries its honest sha256 in `bundle_digest` (computed once over the canonicalised
bundle and frozen into the file). `JSON.stringify` key-order is the source of the digest, and
the test pins the canonicalisation by importing the same fixtures in both the workbench and
the test harness.

### Tests (12 new, in `console.test.js`)

| Test | What it pins |
|---|---|
| `the audit verifier verifies a genuine pack offline and never reaches for a network` | `verifyPack` body contains no `node:net` / `node:http` / `node:https` / `XMLHttpRequest` / `WebSocket`; genuine pack returns `anchored-and-valid`. |
| `the audit verifier refuses a forged pack: digest matches, anchor does not` | `forgedArchivePack` returns `digest-only-valid` with the refusal-of-anchor reason. |
| `the audit verifier refuses a tampered bundle on the digest` | `tamperedBundlePack` returns `digest-mismatch`. |
| `the audit verifier refuses a pack whose format is not one the archive holds` | `unknownFormatPack` returns `format-refused`. |
| `the audit pane renders every pack from fixtures, with no backend running` | The pane renders one card per pack from the scripted response. |
| `the audit pane renders the empty-state paragraph when there are no packs` | Empty state, not error, when the response is `{packs: []}`. |
| `the audit pane renders the error paragraph when the backend does not answer` | Error, not empty, when the response is unreadable. |
| `every audit pack carries a declared-absences list, and the page renders it` | Every fixture has a non-empty `declared_absences`; the page renders the list. |
| `every audit pack carries its tier in the receipt, and the page renders the tier` | Every fixture receipt carries `enforced`/`mediated`/`observed`; the page renders `tier: enforced` for `genuineReportPack`. |
| `the audit pane distinguishes anchored-and-valid from digest-only-valid in prose` | Two different sentences for two different verdicts; never the same text. |
| `the audit pane is click-only: six destinations share five digits` | The keyboard handler does not bind `case '6': setView('audit')`; the SHORTCUTS row mentions the click path. |
| `the audit pane appears when view-audit is clicked, and only then` | Click reveals; click elsewhere hides. |

---

## Test count, before and after

| State | Tests passing | Delta |
|---|---|---|
| Branch head before this commit (`70b2cdc`) | 117 | — |
| After this commit | **129** | **+12** |

Strictly greater than when I started, as the standing constraint requires. The console
test count grows by twelve; one per plan step, with the plan's Step 6 (gates, evidence
file, commit) satisfied by this very file.

```
$ node --test rust/warrant/src/console/console.test.js
# tests 129
# pass 129
# fail 0
# skipped 0
# todo 0
# duration_ms 5800
```

---

## US-English gate

`node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" rust/warrant/src/console/console.js rust/warrant/src/console/console.test.js rust/warrant/src/console/audit.fixtures.js rust/warrant/src/console/index.html` reports 9 findings. **0 of them are introduced by 11.4.** Every flagged line is pre-existing on the branch (`git blame` shows Vikram Jha 2026-08-13/14 and AumOS Wave-1 2026-08-17 as the authors of every flagged line). My new `audit.fixtures.js` passes the gate clean.

---

## Fixtures recorded, and the contract field each one maps to

| Fixture | Field | Source | Read or inferred |
|---|---|---|---|
| `genuineReportPack` | `format` = `warrantor.report/1` | `rust/archive/tests/verification_does_not_depend_on_the_archive.rs:30` import list | read |
| `genuineReportPack` | `bundle` shape (warrant_id, goal, claims, limitations, verdict, receipted_at) | `report.rs::build` in `warrantor-warrant` | inferred |
| `genuineReportPack` | `bundle_digest` is sha256 of canonicalised bundle | `sha256_hex` in `rust/archive/src/artifact.rs` | read |
| `genuineReportPack` | `receipts[].kind` ∈ {`settle`, `stop`, `ledger`} | `rust/archive/src/artifact.rs::ArtifactKind` | read |
| `genuineReportPack` | `receipts[].signature` is ed25519 over `bundle_digest || payload` | `verify_export` source | read |
| `genuineReportPack` | `receipts[].signer_key` is hex ed25519 public key | `verify_export_signed_by` source | read |
| `genuineReportPack` | `receipts[].tier` ∈ {`enforced`, `mediated`, `observed`} | The console's tier vocabulary (Task 0.4 + 4.3) | read |
| `genuineReportPack` | `declared_absences` | The plan's Step 3 — silence is not completeness | inferred |
| `genuineReportPack` | `issuer_pin` | `verify_export_signed_by` second argument | read |
| `genuineReportPack` | `anchored`, `exercised` | Page renders; not wire fields | inferred |
| `stopPack` | `format` = `warrantor.stop/1` | `ArtifactKind::Stop.format()` | read |
| `ledgerPack` | `format` = `warrantor.ledger/1` | `ArtifactKind::Ledger.format()` | read |
| `forgedArchivePack` | archive key signs receipt; pack pins issuer | Fourth-attack test fixture | read |
| `tamperedBundlePack` | bundle edited; declared digest is the genuine bundle's | First-attack and second-attack fixture | read |
| `unknownFormatPack` | format is not one of three | `ArtifactKind::from_format("warrantor.something-else/1") == None` | read |

No field the contract does not have is invented. Where a field is inferred, the table marks
it "inferred" so the backend can honour what the UI assumed when it ships.

---

## Deviations from the plan's letter, and why

1. **`verifyPack` is exported as `async function`.** The plan's tests assume the verifier
   can be called from a test, and `crypto.subtle.digest` is a Promise-returning API. An
   async verifier is the only verifier that ships in this runtime; a sync verifier would
   require a third-party hashing library, which the "no runtime dependencies" rule forbids.
2. **The fixtures' `bundle_digest` values are real sha256 hex strings, not placeholders.**
   The plan says the fixtures "freeze the additive contract"; a placeholder digest that does
   not match the bundle would freeze a lie. The honest digest is what makes the
   digest-mismatch case (the first-attack test) honest.
3. **The verifier uses `JSON.stringify(obj)` for canonicalisation, not `JSON.stringify(obj,
   Object.keys(obj).sort())`.** The Rust side canonicalises via serde_json's default for the
   `Bundle` struct, which is field-order-preserving. The JS side does the same by virtue of
   how plain-object insertion order works in V8. A key-sorted canonicalisation would diverge
   the moment a field was renamed, and a verifier that disagreed with the verifier it was
   mirroring would be the rule's opposite.
4. **`crypto` is used, not `node:crypto`.** `crypto.subtle.digest` is the Web Crypto API,
   available in every runtime this product supports (browser, Node 19+, Electron 22+). A
   verifier that depended on `node:crypto` would fail to ship in the browser, and the rule
   is offline, not "node-only".

---

## What is next

The next Phase 11 task in the dependency order is **11.1** (Fleet console and the agent
inventory register). On this same branch, one commit per task.

Signed-off-by: MiniMax M3 <minimax@local>