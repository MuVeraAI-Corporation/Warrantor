### Task 14.9: Public fact/claim/unknown ledger with versioned corrections; bilingual evidence (L10-14, L10-10)

**Anchor.** Both catalog items are `status=none`. Quoted verbatim from the master blueprint,
`docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html:5412` and `:5362`:

```html
<article class="item" id="L10-14" data-stratum="L10" data-plane="G" data-status="none"
         data-novelty="novel" data-wave="W3" data-loop="L6">
<article class="item" id="L10-10" data-stratum="L10" data-plane="G" data-status="none"
         data-novelty="core" data-wave="W3" data-loop="L2">
```

L10-14's `what` clause, line 5416, is the specification and the last sentence of it is the part that
makes this task uncomfortable:

> A public, signed ledger for an incident that separates what is established, what is claimed and
> what is unknown, with versioned corrections that never overwrite an earlier entry. The same
> discipline this document applies to its sources, published as a machine-readable artifact.

Its verification clause, line 5419: *"A correction appends a new version that cites the superseded
entry; the ledger's head is anchored in the transparency log; a third party verifies any entry's
history offline."* L10-10's verification clause, line 5369, is the one that decides the bilingual
half: *"A localized pack verifies against the same receipt digests as the source-language pack; a
mismatch between the two renders as a defect, not a translation note."*

`status=none` is correct for the ledger. It is **not** correct for the mechanism. Three
fact-with-a-number gates already exist on `origin/main` and this task federates them rather than
inventing a fourth: the wiring census, the invariant ledger, and the invariant ratchet. The one
genuinely new thing here is the correction chain.

**Premise contradicted — the seed is right about the disease and wrong about one number, and Step 0
found three live instances of the exact defect this ledger exists to catch.** `premise_contradicted`
is set for the seed's Step 5 arithmetic ("five known corrections" is an undercount — there are eight
by the end of Step 0) and, more importantly, because the seed treats the repository's overstated
claims as *historical*. They are not. Three are on `origin/main` at `e4b5f10` right now:

1. **`docs/W1-delivery-gaps.md:1096` publishes a stale count.** It says `Sixty-one checks pass.
   Nineteen fail, across eleven invariants.` The corpus reports 65 passing and the ratchet's
   recorded floor is 65. This is precisely the class of defect `readme_renders` was written to
   refuse, in a document that has no such assertion on it.
2. **`docs/W1-delivery-gaps.md:1109` contradicts `evidence/invariants.json` and contradicts
   line 1024 of its own file.** The Tier 5 table calls I-07 `orphaned`; the honest summary at
   line 1024 lists I-07 among the `partial` invariants; the ledger says `"status": "partial"`. The
   corpus's own `#[ignore]` reason string at
   `rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs:159` also says `orphaned`.
   `tools/ci/check_invariants.py` passes anyway, because it never compares a ledger status against
   the corpus text that motivated it.
3. **`README.md:192` publishes a capability claim that `docs/W1-delivery-gaps.md` §0.1 retracted.**
   The row reads `| MCP — transport, control and agent endpoints | **Works.** Upstream forwarding
   not implemented yet |`, while §0.1 records the forwarding as fixed and
   `rust/warrant/src/upstream.rs` is tracked on `origin/main` with `--upstream` referenced in five
   source files. The retraction was written into the gaps document and never propagated to the
   surface a reader meets first.

Each of these is a rendered number or a rendered status with no assertion tying it to the record it
cites. That is the whole of this task.

**Step 0.** Run every command, in this order, from a read-only worktree at `refs/remotes/origin/main`.
Paste the output verbatim into `docs/task-evidence/task-14.9.md`. Read in full, before writing
anything: `docs/W1-delivery-gaps.md` (**1,127 lines**), `evidence/invariants.json` (**129 lines**),
`evidence/wiring-coverage.json` (**39 lines**), `tools/ci/invariant-ratchet.json` (**8 lines**),
`tools/ci/wiring_census.py` (**206 lines**), `tools/ci/check_invariants.py` (**200 lines**),
`tools/ci/check_invariant_ratchet.py` (**204 lines**), and `docs/02-architecture.md` §3
(**lines 149–171**, the I-01..I-12 table with its 12 rows).

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git worktree add --detach M:/wt-x-149 refs/remotes/origin/main
cd M:/wt-x-149 && export CARGO_TARGET_DIR=M:/wt-x-149-target
git log --oneline -1 refs/remotes/origin/main
git ls-tree -d --name-only refs/remotes/origin/main rust/ | wc -l
python tools/ci/wiring_census.py
python tools/ci/check_invariants.py
python tools/ci/check_invariant_ratchet.py
```

The real output, captured 2026-09-05:

```
$ git log --oneline -1 refs/remotes/origin/main
e4b5f10 Merge branch 'feat/invariant-ledger'

$ git ls-tree -d --name-only refs/remotes/origin/main rust/ | wc -l
39

$ python tools/ci/wiring_census.py
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1

$ python tools/ci/check_invariant_ratchet.py
    Finished `test` profile [unoptimized + debuginfo] target(s) in 5m 52s
     Running tests\invariants\main.rs (M:/wt-x-149-target\debug\deps\invariants-78c32a98a7af8d1d.exe)
invariant ratchet: ok (65 passing at floor 65, 19 recorded findings at ceiling 19)
```

Then the three discrepancy captures. These are the seed entries, so they go in the evidence file as
commands, not as prose:

```
$ grep -n "Sixty-one checks pass" docs/W1-delivery-gaps.md
1096:Sixty-one checks pass. Nineteen fail, across eleven invariants. I-02 — no authority expansion — is

$ python -c "import json;print([i['status'] for i in json.load(open('evidence/invariants.json'))['invariants'] if i['id']=='I-07'])"
['partial']

$ grep -n 'ignore = "I-07' rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs
159:#[ignore = "I-07 orphaned: the product never issues a pre-commit receipt (Task 1.1 / Task 2.3, 2026-09-02)"]

$ sed -n 192p README.md
| MCP — transport, control and agent endpoints | **Works.** Upstream forwarding not implemented yet |

$ git ls-tree --name-only refs/remotes/origin/main rust/warrant/src/ | grep upstream
rust/warrant/src/upstream.rs
```

And the inventory of published surfaces, which is what the ledger has to cover. There are four
classes and they are not equally correctable:

```
$ sed -n '188,197p' README.md            # the status table: 9 rows, 4 carrying numbers
$ grep -c '^| \*\*I-' docs/02-architecture.md
12
$ ls docs/content-program/submission/*.md
docs/content-program/submission/P1-reproducibility-floor-anon.md
docs/content-program/submission/P2-input-variation-defense-anon.md
docs/content-program/submission/P3-position-not-length-anon.md
docs/content-program/submission/P6-composition-independence-anon.md
docs/content-program/submission/P8-quantization-equivalence-anon.md
docs/content-program/submission/README.md
$ ls rust/warrant/src/console/          # the console's rendered guarantees
```

Five papers. **A paper is append-only by publication, not by policy** — which is why the seed's
non-goal about not editing published papers is a constraint on this task's design and not a
courtesy: a paper claim gets a ledger entry with a correction, and the paper text is never touched.

**Non-goals.**

1. **Not the public offline verify page — Task 14.3 (GLM) owns it** (L10-18, L10-15, plan line
   20497). Task 14.3 builds a page that verifies a bundle from a file with no network. This task
   produces a checked-in ledger and a CI gate; it renders no verifier UI and ships no HTML. If both
   land, 14.3's page may read `evidence/claims.json` — but this task must not assume it will, and
   must not build a page in anticipation. 14.3 has not landed.
2. **Not the parity promotion gate — Task 12.3 owns it** (L9-03, L9-08, plan line 19872). A stale
   *rendered* number is this task's business; whether a model or build is good enough to promote is
   12.3's, and the two must not share a threshold file. This task's gate has no promote/reject
   verdict and no parity baseline. 12.3 has not landed.
3. **Not the control ownership register — Task 13.8 (GLM) owns it** (L11-14, L11-15, plan line
   20380). Every ledger entry needs a named falsifier; it does **not** get a named owner, a
   retirement path, or a review cadence. Those are 13.8's fields and duplicating them here produces
   two registers that disagree about who owns a control. 13.8 has not landed.
4. **Not the trust center UI — Task 11.9 owns it** (L8-06, L8-28, plan line 19643). Nothing here
   renders into a portal.
5. **Not the standards crosswalk — Task 14.4 owns it** (L10-17, plan line 20534). The false
   standards claim in this repository's history is a *seed correction* in this ledger, not a
   re-litigation of the crosswalk.
6. **Not marketing copy, and not a translation service.** See Step 9: claim bodies are not machine
   translated in this task, and the ledger says so about itself.

**Files.**

| Path | New? | What it is |
|---|---|---|
| `evidence/claims.json` | new | The ledger. Format `warrantor.claim-ledger/1` |
| `tools/ci/check_claims.py` | new | The gate: falsifier required, renderings recomputed, corrections append-only |
| `tools/ci/test_check_claims.py` | new | pytest for the gate, refusal tests each paired with an allowed control |
| `tools/ci/claim_locales.json` | new | The reviewed label vocabulary for the localized view. Scaffolding only |
| `docs/public-claims.md` | new, generated | The rendered English view |
| `docs/public-claims.ar.md` | new, generated | The rendered Arabic view, same digests |
| `docs/W1-delivery-gaps.md` | edit | Three corrections; §5.1's count and I-07's row |
| `README.md` | edit | The stale MCP row, plus one claim-ledger row |
| `.github/workflows/ci.yml` | edit | Two steps in the existing `Documentation and tracker contracts` job |
| `docs/task-evidence/task-14.9.md` | new | Step 0 output, every gate's output, and what this task did not do |

No new Rust crate, no new Python package, no new workspace member.

**Consumes / Produces.**

*Consumes — all four exist on `origin/main` and are read, not modified:*

```python
def readme_renders(readme: Path, result: WiringCensus) -> bool:   # tools/ci/wiring_census.py:150
def load_floor(path: Path) -> int:                                # tools/ci/wiring_census.py:141
def load_baseline(path: Path) -> Baseline:                         # tools/ci/check_invariant_ratchet.py:59
ALLOWED_STATUSES = frozenset({"enforced", "partial", "orphaned", "unimplemented"})
                                                                   # tools/ci/check_invariants.py:24
```

`readme_renders` is the pattern this whole task generalizes. Its body, `tools/ci/wiring_census.py:150–154`:

```python
def readme_renders(readme: Path, result: WiringCensus) -> bool:
    """True when the README status table shows the current number."""

    expected = f"reachable from the CLI | **{result.reachable} of {result.total}**"
    return expected in readme.read_text(encoding="utf-8")
```

A literal string, computed from the measurement, asserted present in the prose. Called at
`wiring_census.py:196` and failing the build at `:201`. That assertion refused a merge in this
program when the README row went stale. Every published number in the claim ledger gets the same
treatment, with one addition: the expected string is computed from a **named record file and a JSON
pointer stored in the ledger**, not from a fresh measurement, so a claim can cite a record without
the gate needing to be able to re-measure it.

*Also consumed:* `LedgerIssue` at `tools/ci/check_invariants.py:47` and `check_ledger(repository_root,
ledger) -> list[LedgerIssue]` at `:158`. The new checker mirrors that shape — a frozen dataclass of
issues, all printed, exit 1 if any — because a second issue-reporting convention in the same CI job
is a needless divergence.

*Produces — none of these exist yet:*

```python
@dataclass(frozen=True)
class ClaimIssue:                                   # tools/ci/check_claims.py
    claim: str
    message: str

def load_ledger(path: Path) -> dict[str, object]: ...
def expected_rendering(repository_root: Path, claim: dict[str, object]) -> str: ...
def renders(repository_root: Path, surface: str, expected: str) -> bool: ...
def state_digest(claim_id: str, version: int, status: str, text: str) -> str: ...
def history_digest(claim: dict[str, object]) -> str: ...
def check_append_only(previous: dict[str, object], current: dict[str, object]) -> list[ClaimIssue]: ...
def check_claim(repository_root: Path, claim: dict[str, object]) -> list[ClaimIssue]: ...
def render_view(ledger: dict[str, object], locale: str, labels: dict[str, str]) -> str: ...
def main(argv: list[str] | None = None) -> int: ...
```

*Depends on tasks that have not landed:* none. Every consumed symbol is on `origin/main` at
`e4b5f10`. This task is buildable today, which is unusual in Phase 14 and is the reason it can run
early. Every crate it names — none — is therefore absent-crate-proof; there is no `cargo` call in
this task at all except the two assertion runs in Step 10, both against crates that exist
(`warrantor-warrant`).

**Bound strength. Tier C — Observed, with one narrow Tier B property, and the difference must be
stated in the product text rather than left to a reader.**

A ledger enforces nothing about the world. It cannot make a claim true, cannot detect that a claim
became false, and cannot stop anyone publishing a claim outside it. Its status entries are labels
applied by whoever wrote them.

The one real property is narrower than "a correction cannot be silent", and the narrower sentence is
the one that ships. **What is enforced: a commit that changes a published claim's text or status
without appending a correction that retains the previous text is refused by
`tools/ci/check_claims.py`, and a commit that removes a correction present in the parent commit is
refused by the same checker.** That is a chokepoint bound — Tier B — and here is what escapes it,
stated as it will appear in `docs/public-claims.md` and in `README.md`:

> **What this ledger does not cover.** The gate refuses a *merge*, not an edit: the rewrite lands in
> a working tree before anything refuses it, and a clone taken from that tree carries the rewrite.
> It holds only where the checker runs and is a required check — a branch with checks disabled, a
> direct push to a repository without the workflow, or a fork are all outside it. Rewriting the
> commit the checker compares against, by force-push or by rebase, defeats the comparison; the
> per-entry `history_digest` and the ledger's `head_digest` let anyone holding an earlier copy detect
> that, and prove nothing to anyone who does not hold one. Nothing here is anchored in a
> transparency log, notarized, or countersigned, so an entry's history is verifiable offline against
> *a copy you already trust* and against nothing else. And no status in this ledger is evidence
> about the world: `fact` means "recomputed from a named record in this repository", not "true".

That paragraph is not optional prose. Step 8 writes it, and Step 3's checker refuses a ledger whose
`bound_statement` field is missing or does not appear verbatim in both rendered views — because an
honest limitation that is not rendered is not published.

**No new trust root.** L10-14's verification clause asks for the head to be *"anchored in the
transparency log"*. There is no transparency log on `origin/main`, no anchoring service, and this
task must not stand one up. The weaker local thing is built instead: a per-entry hash chain and a
ledger head digest, both recomputed by the checker from the file itself. What it establishes: any
removal or mutation of a retained correction changes `head_digest`, so two parties comparing heads
disagree. What it does **not** establish: that the head is the latest one, that no history was
rewritten before you cloned, or that any third party without a prior copy can distinguish a
rewritten chain from an honest one. Anchoring is L10-14's remainder and Step 12 hands it forward
rather than pretending it is done.

**The orphan count does not move.** This task adds no Rust crate, so `9 of 39 crates reachable ...
over 17 path edges` must read identically before and after. Step 10 asserts it rather than assuming
it.

**Exit gate.** `python tools/ci/check_claims.py` prints one summary line and exits 0 — with every
`fact` entry's expected rendering recomputed from its cited record and found verbatim in every
surface it names, every entry carrying a non-empty falsifier, the correction chain verified against
`git show HEAD:evidence/claims.json`, and both rendered views carrying byte-identical `head_digest`
lines; and, in the same run, `python -m pytest tools/ci/test_check_claims.py -q -p no:cacheprovider`
passes with every refusal test paired with its allowed control.

---

- [ ] **Step 1 — Worktree, Step 0 captured verbatim, and the concurrency check.**
  `git worktree add M:/wt-14.9 -b feat/public-claim-ledger refs/remotes/origin/main` and
  `export CARGO_TARGET_DIR=M:/wt-14.9-target`. Do **not** work in the shared checkout: it carries
  roughly forty untracked crates `origin/main` does not have, and a ledger seeded from a working
  tree would cite files that do not exist on the branch it gates.

```bash
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git worktree add M:/wt-14.9 -b feat/public-claim-ledger refs/remotes/origin/main
cd M:/wt-14.9 && export CARGO_TARGET_DIR=M:/wt-14.9-target
git worktree list                      # other lanes hold worktrees; do not touch theirs
git ls-tree -d --name-only HEAD rust/ | wc -l   # must print 39
```

  Write `docs/task-evidence/task-14.9.md` first, with the Step 0 block pasted verbatim including
  the three discrepancy greps. *Test intent:* none yet — this step exists so that every later step
  has a fixed baseline to diff against, and so the discrepancies are on record before any file is
  edited. A correction ledger whose own first three entries were discovered *after* the fix would
  be indistinguishable from a rewrite.

- [ ] **Step 2 — Failing test first: a claim with no named falsifier is refused, with its allowed
  control.** Write `tools/ci/test_check_claims.py` before `check_claims.py` exists. Two tests, and
  the second is the reason the first means anything: a checker that refuses every entry passes a
  one-sided test and proves nothing.

```python
"""Tests for tools/ci/check_claims.py — the public claim ledger checker."""

from __future__ import annotations

from pathlib import Path

from check_claims import ClaimIssue, check_claim

def a_fact(**overrides: object) -> dict[str, object]:
    """A minimal well-formed `fact` entry; overrides break exactly one thing."""
    claim = {
        "id": "CL-001",
        "status": "fact",
        "version": 1,
        "text": "9 of 39 crates reachable",
        "falsifier": {
            "who": "anyone with a clone",
            "how": "python tools/ci/wiring_census.py disagrees with the rendered number",
        },
        "derived_from": {"record": "evidence/wiring-coverage.json", "pointers": ["/reachable", "/total"]},
        "template": "{0} of {1} crates reachable",
        "surfaces": ["docs/public-claims.md"],
        "corrections": [],
    }
    claim.update(overrides)
    return claim

def test_a_claim_with_no_falsifier_is_refused(tmp_path: Path) -> None:
    issues = check_claim(tmp_path, a_fact(falsifier={}))
    assert [i.message for i in issues] == [
        "no falsifier: an entry must name who could show it false and how"
    ]

def test_a_claim_with_an_empty_how_is_refused(tmp_path: Path) -> None:
    broken = a_fact(falsifier={"who": "a reviewer", "how": "   "})
    assert any("falsifier.how" in i.message for i in check_claim(tmp_path, broken))

def test_the_allowed_control_a_well_formed_claim_raises_no_falsifier_issue(tmp_path: Path) -> None:
    """The control. Without this, a checker that refuses everything passes the two above."""
    issues = check_claim(tmp_path, a_fact())
    assert not [i for i in issues if "falsifier" in i.message], issues
```

  *Test intent:* the falsifier is the field that separates this ledger from a features list. An
  entry no one could disprove is not a claim, it is a slogan, and the checker refuses it by name.
  Run and watch the import fail; that is the red.

- [ ] **Step 3 — The ledger, the four seed facts, and the render assertion generalized.** Write
  `evidence/claims.json` with format `warrantor.claim-ledger/1` and four `fact` entries, each
  deriving its rendering from a record that already exists. This is where a rendered number gets
  tied to its record, as required.

```json
{
  "format": "warrantor.claim-ledger/1",
  "recorded": "2026-09-05",
  "bound_statement": "The gate refuses a merge, not an edit ...",
  "head_digest": "sha256:<recomputed by tools/ci/check_claims.py --write>",
  "claims": [
    {
      "id": "CL-001",
      "status": "fact",
      "version": 1,
      "text": "9 of 39 Rust workspace crates are reachable from the warrantor binary over 17 path edges.",
      "derived_from": {"record": "evidence/wiring-coverage.json",
                       "pointers": ["/reachable", "/total", "/edges"]},
      "template": "{0} of {1} Rust workspace crates are reachable from the warrantor binary over {2} path edges.",
      "surfaces": ["docs/public-claims.md", "docs/public-claims.ar.md"],
      "falsifier": {"who": "anyone with a clone",
                    "how": "python tools/ci/wiring_census.py prints a different triple"},
      "corrections": []
    },
    {
      "id": "CL-002",
      "status": "fact",
      "version": 1,
      "text": "The invariant attack corpus reports 65 passing checks and 19 recorded findings.",
      "derived_from": {"record": "tools/ci/invariant-ratchet.json",
                       "pointers": ["/passing_floor", "/ignored_ceiling"]},
      "template": "reports {0} passing checks and {1} recorded findings",
      "surfaces": ["docs/W1-delivery-gaps.md", "docs/public-claims.md", "docs/public-claims.ar.md"],
      "falsifier": {"who": "anyone who can run cargo",
                    "how": "python tools/ci/check_invariant_ratchet.py prints different counts"},
      "corrections": []
    },
    {
      "id": "CL-003",
      "status": "fact",
      "version": 1,
      "text": "Of the twelve formal invariants: enforced=2, partial=7, orphaned=2, unimplemented=1.",
      "derived_from": {"record": "evidence/invariants.json", "pointers": ["/invariants"]},
      "template": "enforced={0}, partial={1}, orphaned={2}, unimplemented={3}",
      "surfaces": ["docs/public-claims.md", "docs/public-claims.ar.md"],
      "falsifier": {"who": "anyone with a clone",
                    "how": "python tools/ci/check_invariants.py prints a different census"},
      "corrections": []
    },
    {
      "id": "CL-004",
      "status": "fact",
      "version": 1,
      "text": "I-07 (evidence precedes commitment) is partial.",
      "derived_from": {"record": "evidence/invariants.json", "pointers": ["/invariants/6/status"]},
      "template": "I-07 (evidence precedes commitment) is {0}.",
      "surfaces": ["docs/W1-delivery-gaps.md", "docs/public-claims.md", "docs/public-claims.ar.md"],
      "falsifier": {"who": "anyone with a clone",
                    "how": "evidence/invariants.json gives I-07 a different status"},
      "corrections": []
    }
  ]
}
```

  Then implement `expected_rendering` and `renders` in `check_claims.py`, mirroring
  `readme_renders` exactly — resolve each JSON pointer against the cited record, format the
  template, and assert the literal string is present in every named surface:

```python
def expected_rendering(repository_root: Path, claim: dict[str, object]) -> str:
    """The literal string this claim must render as, computed from its cited record."""
    source = cast(dict[str, object], claim["derived_from"])
    record = json.loads((repository_root / str(source["record"])).read_text(encoding="utf-8"))
    values = [resolve_pointer(record, pointer) for pointer in cast(list[str], source["pointers"])]
    return str(claim["template"]).format(*values)

def renders(repository_root: Path, surface: str, expected: str) -> bool:
    """True when the surface contains the expected string verbatim."""
    return expected in (repository_root / surface).read_text(encoding="utf-8")
```

  *Test intent:* CL-002 and CL-004 name `docs/W1-delivery-gaps.md` as a surface, so the checker
  fails on `origin/main` as written — CL-002's expected string is absent because line 1096 says
  `Sixty-one`, and CL-004's is absent because line 1109 says `orphaned`. **That failure is the
  proof the gate has teeth on a real defect, and it must be captured in the evidence file before
  Step 8 fixes it.** CL-003's `/invariants` pointer resolves to a list, so `resolve_pointer` must
  support a census reduction; keep that reduction in the checker, not in the ledger, so a claim
  cannot smuggle in a computation.

- [ ] **Step 4 — Failing test: a stale rendering is refused, with its allowed control.** Add to
  `tools/ci/test_check_claims.py`:

```python
RECORD = '{"format": "warrantor.wiring-coverage/1", "reachable": 9, "total": 39, "edges": 17}'

def fake_tree(tmp_path: Path, surface_text: str) -> Path:
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "wiring-coverage.json").write_text(RECORD, encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "public-claims.md").write_text(surface_text, encoding="utf-8")
    return tmp_path

def test_a_stale_rendering_is_refused(tmp_path: Path) -> None:
    tree = fake_tree(tmp_path, "the census says 8 of 39 crates reachable\n")
    issues = check_claim(tree, a_fact())
    assert any("does not render" in i.message for i in issues), issues
    assert any("docs/public-claims.md" in i.message for i in issues), issues

def test_the_allowed_control_a_current_rendering_passes(tmp_path: Path) -> None:
    """The control: the same claim against a surface that does show the number."""
    tree = fake_tree(tmp_path, "the census says 9 of 39 crates reachable\n")
    assert check_claim(tree, a_fact()) == []

def test_a_number_changed_in_the_record_alone_is_refused(tmp_path: Path) -> None:
    """The direction that matters: the record moves, the prose does not."""
    tree = fake_tree(tmp_path, "the census says 9 of 39 crates reachable\n")
    (tree / "evidence" / "wiring-coverage.json").write_text(
        RECORD.replace('"reachable": 9', '"reachable": 10'), encoding="utf-8")
    assert any("does not render" in i.message for i in check_claim(tree, a_fact()))
```

  *Test intent:* three cases, one of which is the allowed control, and the third is the one that
  actually happened in this program — a measurement improved, its record was updated, and the prose
  citing it was not. `wiring_census.py` catches that for one row in one file. This catches it for
  every entry on every surface the ledger names.

- [ ] **Step 5 — Failing test: a silent correction is refused; the superseded text is retained with
  its date.** This is the hardest requirement and it needs a state digest, not just a field
  presence check. Implement:

```python
def state_digest(claim_id: str, version: int, status: str, text: str) -> str:
    """A digest over one version of one claim. Canonical, so two clones agree."""
    canonical = json.dumps(
        {"id": claim_id, "version": version, "status": status, "text": text},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
```

  and require, for every entry: `version == len(corrections) + 1`; each `corrections[i]` carries
  `version == i + 1`, a `date`, a `reason`, `superseded_text`, `superseded_status`, and a
  `supersedes_digest` equal to `state_digest(id, i + 1, superseded_status, superseded_text)`; and
  dates never move backward. The tests:

```python
def a_corrected(**overrides: object) -> dict[str, object]:
    """An entry at version 2 whose one correction retains version 1 verbatim."""
    prior_text = "I-07 (evidence precedes commitment) is orphaned."
    claim = a_fact(
        id="CL-004", version=2, text="I-07 (evidence precedes commitment) is partial.",
        template="I-07 (evidence precedes commitment) is {0}.",
        corrections=[{
            "version": 1, "date": "2026-09-05",
            "reason": "the ledger and the gaps table disagreed; evidence/invariants.json is the record",
            "superseded_status": "fact", "superseded_text": prior_text,
            "supersedes_digest": state_digest("CL-004", 1, "fact", prior_text),
        }],
    )
    claim.update(overrides)
    return claim

def test_a_silent_rewrite_is_refused(tmp_path: Path) -> None:
    """Text changed, version bumped, nothing retained. This is the defect."""
    silent = a_corrected(corrections=[])
    assert any("version 2 with 0 corrections" in i.message for i in check_claim(tmp_path, silent))

def test_a_correction_that_misquotes_the_superseded_text_is_refused(tmp_path: Path) -> None:
    """A retained text that does not hash to its own digest is a rewritten history."""
    tampered = a_corrected()
    cast(list, tampered["corrections"])[0]["superseded_text"] = "I-07 is fine."
    assert any("supersedes_digest" in i.message for i in check_claim(tmp_path, tampered))

def test_a_correction_with_no_date_is_refused(tmp_path: Path) -> None:
    undated = a_corrected()
    del cast(list, undated["corrections"])[0]["date"]
    assert any("date" in i.message for i in check_claim(tmp_path, undated))

def test_the_allowed_control_a_properly_versioned_correction_passes(tmp_path: Path) -> None:
    """The control: a correction done right is accepted, so the refusals above are not universal."""
    tree = fake_tree(tmp_path, "I-07 (evidence precedes commitment) is partial.\n")
    claim = a_corrected(derived_from={"record": "evidence/wiring-coverage.json", "pointers": []},
                        template="I-07 (evidence precedes commitment) is partial.")
    assert check_claim(tree, claim) == []
```

  *Test intent:* a correction is an addition, never a rewrite. The digest is what makes the
  retention load-bearing rather than decorative: a `superseded_text` field alone can be edited to
  say something more flattering, and `supersedes_digest` refuses that. Note what is *not* claimed —
  the digest is unsigned and local, and Step 8's bound paragraph says so.

- [ ] **Step 6 — Failing test: a removed correction is refused, checked against the parent commit.**
  The digest chain makes a mutation detectable; only a comparison against history makes a *deletion*
  detectable, because a shortened chain can be internally consistent. Implement `history_digest`
  as a fold, put the fold of folds in `head_digest`, and add the ratchet:

```python
def history_digest(claim: dict[str, object]) -> str:
    """Fold the whole history into one digest, so dropping the last correction changes it."""
    accumulator = hashlib.sha256(str(claim["id"]).encode("utf-8")).hexdigest()
    for correction in cast(list[dict[str, object]], claim["corrections"]):
        accumulator = hashlib.sha256(
            (accumulator + str(correction["supersedes_digest"])).encode("utf-8")
        ).hexdigest()
    current = state_digest(str(claim["id"]), int(cast(int, claim["version"])),
                           str(claim["status"]), str(claim["text"]))
    return "sha256:" + hashlib.sha256((accumulator + current).encode("utf-8")).hexdigest()

def check_append_only(previous: dict[str, object], current: dict[str, object]) -> list[ClaimIssue]:
    """Every claim and every correction in the parent commit must still be present, verbatim."""
    issues: list[ClaimIssue] = []
    old = {str(c["id"]): c for c in cast(list[dict[str, object]], previous["claims"])}
    new = {str(c["id"]): c for c in cast(list[dict[str, object]], current["claims"])}
    for claim_id, before in old.items():
        after = new.get(claim_id)
        if after is None:
            issues.append(ClaimIssue(claim_id, "removed from the ledger; entries are append-only"))
            continue
        if int(cast(int, after["version"])) < int(cast(int, before["version"])):
            issues.append(ClaimIssue(claim_id, "version fell; a claim version may only rise"))
        kept = cast(list[dict[str, object]], after["corrections"])
        for index, correction in enumerate(cast(list[dict[str, object]], before["corrections"])):
            if index >= len(kept) or kept[index] != correction:
                issues.append(ClaimIssue(
                    claim_id,
                    f"correction {index + 1} was removed or altered; a retraction is retained, "
                    f"never deleted",
                ))
    return issues
```

  The parent ledger comes from `git show HEAD:evidence/claims.json` — absent on the first commit,
  which the checker treats as an empty ledger and says so in its output rather than silently
  skipping. The test:

```python
def test_removing_a_correction_is_refused(tmp_path: Path) -> None:
    before = {"claims": [a_corrected()]}
    after = {"claims": [a_corrected(version=1, corrections=[],
                                    text="I-07 (evidence precedes commitment) is orphaned.")]}
    messages = [i.message for i in check_append_only(before, after)]
    assert any("was removed or altered" in m for m in messages), messages
    assert any("version fell" in m for m in messages), messages

def test_deleting_a_whole_claim_is_refused(tmp_path: Path) -> None:
    issues = check_append_only({"claims": [a_corrected()]}, {"claims": []})
    assert [i.message for i in issues] == ["removed from the ledger; entries are append-only"]

def test_the_allowed_control_appending_a_correction_passes(tmp_path: Path) -> None:
    """The control: growth is allowed, which is the whole point of an append-only ledger."""
    before = {"claims": [a_fact(id="CL-004")]}
    assert check_append_only(before, {"claims": [a_corrected()]}) == []
```

  *Test intent:* three cases, the third an allowed control that keeps the gate from being a freeze.
  Also assert that `head_digest` changes between the two states, so an offline holder of the earlier
  copy can see it without git — and record in the evidence file that this is detection by
  *comparison*, not prevention.

- [ ] **Step 7 — Seed the ledger with this program's own corrections, by name and date. Eight, not
  five.** A correction ledger that starts empty is not credible, and this repository's record is
  the strongest thing it can put in the first entry. Five come from the seed's anchor and are
  historical; three were found in Step 0 and are live on `origin/main`. Each becomes a `claim`
  entry at version 2 with one retained correction, or an `unknown` entry where the current status is
  genuinely open:

  | Entry | The superseded claim | Why it was wrong |
  |---|---|---|
  | CL-002 | 61 passing checks | The corpus reports 65; the prose was never re-derived |
  | CL-004 | I-07 is orphaned | `evidence/invariants.json` says partial, and so does line 1024 |
  | CL-005 | Upstream forwarding not implemented | `rust/warrant/src/upstream.rs` is tracked; §0.1 records the fix |
  | CL-006 | A standards claim propagated to four artifacts before verification | Published across four surfaces, verified on none |
  | CL-007 | A bound labeled "enforced" that was contained at settle time | A settle-time containment is Observed, never Enforced |
  | CL-008 | An error message naming `--upstream`, a flag that did not exist | A claim in an error string with no mechanism behind it |
  | CL-009 | A hand-counted routing table, wrong in two documents | Two documents, one wrong count, no gate between them |
  | CL-010 | A status board reporting two finished tasks as never started | It matched a branch convention the plan did not use |

  CL-006 through CL-010 have no live surface to render into, so they carry `"surfaces": []` and the
  checker must accept an empty surface list for a historical entry while still requiring the
  falsifier and the retained text. CL-007 is the entry this task cannot get wrong: its correction
  text states that a bound contained at settle time is **Observed**, and that no `netns`, `seccomp`
  or firewall enforcement exists in this repository, so containment composes with an external
  sandbox. *Test intent:* add a test that an entry with `status` in `{claim, unknown}` and a
  non-empty `surfaces` list still gets its rendering checked — a `claim` is not exempt from being
  quoted accurately just because it is not a `fact`.

- [ ] **Step 8 — Fix the three live defects as versioned corrections, not silent edits.** In one
  commit, and in this order, so the gate is red before it is green:

```bash
python tools/ci/check_claims.py            # RED: CL-002 and CL-004 do not render
# then edit, then:
python tools/ci/check_claims.py            # green
```

  `docs/W1-delivery-gaps.md:1096` becomes the current count with the previous one retained in the
  ledger, not deleted from history. `docs/W1-delivery-gaps.md:1109`'s I-07 row becomes `partial`,
  matching line 1024 and the ledger. `README.md:192`'s MCP row states what §0.1 actually records,
  and gains a one-line pointer to `docs/public-claims.md`. Add the `bound_statement` paragraph from
  **Bound strength** verbatim to both rendered views and to a short block in `README.md`, and have
  the checker assert its presence — an honest limitation that is not rendered is not published.

  One thing to leave alone and record instead: the `#[ignore]` reason at
  `rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs:159` also says `orphaned`.
  Editing a reason string is not weakening an assertion, but it *is* touching the corpus from a docs
  task, and the corpus is the instrument. Add a ledger entry noting the disagreement, with its
  falsifier being the grep, and hand the string change to whichever task next touches I-07 (Task 1.1
  or Task 2.3). *Test intent:* the fix and the record land together, so nobody can read the fixed
  prose without also being able to read what it used to say.

- [ ] **Step 9 — Bilingual rendering: two views, one record, and no translated quotations.** Generate
  `docs/public-claims.md` and `docs/public-claims.ar.md` from `evidence/claims.json` with
  `python tools/ci/check_claims.py --write`, mirroring `wiring_census.py --write` at
  `tools/ci/wiring_census.py:178–183`. `tools/ci/claim_locales.json` holds a reviewed label
  vocabulary — the three status names, the column headers, the correction-history heading, the bound
  paragraph — and nothing else.

```python
def render_view(ledger: dict[str, object], locale: str, labels: dict[str, str]) -> str:
    """One rendered view. Claim bodies and quotations are never translated."""
    lines = [f"# {labels['title']}", "", f"`head_digest` {ledger['head_digest']}", "",
             labels["bound_statement"], ""]
    for claim in cast(list[dict[str, object]], ledger["claims"]):
        lines += [f"## {claim['id']} — {labels[str(claim['status'])]}", "",
                  f"> {claim['text']}   <!-- source language: en; not translated -->", ""]
        for correction in cast(list[dict[str, object]], claim["corrections"]):
            lines += [f"- {labels['superseded']} v{correction['version']} "
                      f"({correction['date']}): {correction['reason']}",
                      f"  > {correction['superseded_text']}", ""]
    return "\n".join(lines) + "\n"
```

  Three rules the checker enforces, each answering L10-10's own verification sentence:

  1. **Both views carry a byte-identical `head_digest` line.** A mismatch is reported as
     `head_digest differs between views; this is a defect, not a translation note` — the catalog
     item's phrasing, because it is the right phrasing.
  2. **Claim text and `superseded_text` are byte-identical in both views**, marked with their source
     language. Translating a quotation manufactures a claim nobody made; translating a *correction's*
     superseded text would be worse, because it rewrites a retraction.
  3. **Only labels are localized in this task, and the ledger says so about itself.** Add
     `CL-011`, `status: "unknown"`, text: *"Whether an Arabic-reading supervisor can act on this
     ledger is unknown: only its labels are localized, and no Arabic-reading reviewer has read it."*
     Falsifier: an Arabic-reading reviewer says otherwise. That entry is the honest form of L10-10 at
     this stage and it is more useful than a machine-translated view that reads fluent and asserts
     something unverified.

  *Test intent:* a test that mutates one view's `head_digest` and asserts the checker refuses, paired
  with the allowed control of two views generated from the same ledger passing; and a test that a
  view whose quotation text differs from the ledger's is refused.

- [ ] **Step 10 — Assess the invariant corpus honestly, and expect to convert nothing.** Content
  rule 6 asks whether this task can convert a recorded violation. Read all nineteen and the answer
  is no: every one of them names a missing runtime mechanism, and not one is about documentation.
  The two nearest are:

```
rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs:159
#[ignore = "I-07 orphaned: the product never issues a pre-commit receipt (Task 1.1 / Task 2.3, 2026-09-02)"]

rust/warrant/tests/invariants/i11_self_change_is_governed.rs:97
#[ignore = "I-11 unimplemented at the broker: three DenyReason variants are rendered and never constructed (Task 2.5, 2026-09-02)"]
```

  I-07's finding is that no pre-commit receipt is ever issued; a ledger does not issue one. I-11's is
  that three `DenyReason` variants are rendered to users and constructed by no decision — the closest
  thing in the corpus to a claim-without-a-mechanism, and still a Rust wiring fix owned by Task 2.5.
  **Do not raise `passing_floor` and do not lower `ignored_ceiling`.** Assert instead that nothing
  moved, and paste both into the evidence file:

```bash
python tools/ci/check_invariant_ratchet.py
# must print exactly: invariant ratchet: ok (65 passing at floor 65, 19 recorded findings at ceiling 19)
python tools/ci/wiring_census.py
# must print exactly: wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges
```

  *Test intent:* this task adds no crate, so the orphan count must not move, and it earns no
  invariant, so the ratchet must not move. A docs task that appeared to improve either number would
  be the exact defect the ledger is for. Record the assessment in the evidence file as a decision,
  not an omission.

- [ ] **Step 11 — Gates for every language touched, the CI wiring, and `git commit -s`.** Python and
  documentation only, so run the gates for those two and nothing else — but run all of them, since a
  gate for a language you touched is not optional:

```bash
python -m pytest tools/ci/test_check_claims.py -q -p no:cacheprovider
python tools/ci/check_claims.py
python tools/ci/check_docs.py                 # local links in the two new docs must resolve
python tools/ci/check_invariants.py
python -m pytest tools/ci/test_check_invariants.py -q -p no:cacheprovider
python -m pip install --disable-pip-version-check "ruff==0.12.0"
python -m ruff check tools/ci/check_claims.py tools/ci/test_check_claims.py
python -m ruff format --check tools/ci/check_claims.py tools/ci/test_check_claims.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
     docs/public-claims.md README.md docs/W1-delivery-gaps.md
```

  The US-English run has expected carve-outs to leave alone: verbatim quotations of existing repo
  text keep their source spelling and are flagged rather than edited, and the checker's two standing
  false positives — the plural of *analysis* and the third-person verb form of *forward* — are
  correct as written wherever they occur. Read the full output; the tail can hide a `FAIL`.
  Then add two steps to the existing `Documentation and tracker contracts` job in
  `.github/workflows/ci.yml` — after `Check the invariant ledger against the tree` at line 383 —
  running `python tools/ci/check_claims.py` and
  `python -m pytest tools/ci/test_check_claims.py -q -p no:cacheprovider`. That job needs a full
  fetch for `git show HEAD:evidence/claims.json` to resolve; if its checkout is shallow, the checker
  must say `no parent ledger; append-only check skipped` **and exit non-zero in CI**, because a
  skipped ratchet that reports success is how a silent removal would land. Commit with
  `git commit -s` (the DCO job at line 15 fails without the trailer). *Test intent:* every gate that
  could see this change does see it, and the append-only check cannot be silently disabled by an
  environment that happens to lack history.

- [ ] **Step 12 — Hand forward what this task deliberately did not do.** Write these into
  `docs/task-evidence/task-14.9.md` under a heading, and into `docs/public-claims.md` as `unknown`
  entries with falsifiers, so the remainder is published rather than remembered:

  1. **No anchoring.** L10-14 asks for the head to be anchored in a transparency log. There is none,
     and this task built the weaker local chain instead. What is missing is precisely the property
     that lets a stranger verify history; name it as open and point at whichever task owns the log.
  2. **No signature.** L10-14 says "signed ledger". `head_digest` is a hash, not a signature: it
     binds content to itself and binds nothing to a signer.
  3. **Claim bodies are not translated** and no Arabic-reading reviewer has read the localized view.
     CL-011 carries this; it stays `unknown` until a reviewer falsifies it.
  4. **The papers are covered by reference only.** Five papers under
     `docs/content-program/submission/` publish claims this ledger records but cannot re-derive,
     because their numbers come from runs that are not committed records. Those entries are `claim`,
     not `fact`, and their falsifier is a re-run — which is the honest label and also an argument for
     committing the run records that Task 14.2's harness would produce.
  5. **The corpus reason string at `i07_...rs:159` still says `orphaned`.** Left to Task 1.1 or 2.3
     on purpose; recorded here so it is not lost.
