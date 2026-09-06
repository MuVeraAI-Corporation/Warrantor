#!/usr/bin/env python3
"""Gate for the public claim ledger at evidence/claims.json.

This repository's recurring defect is not broken code. It is a sentence that was true when it was
written, published beside a number nobody re-derived. `wiring_census.py:150` refuses one instance of
that -- one README row, tied to one measurement -- and that single assertion has refused a merge
here. This file generalizes the idiom: every published number in the ledger names the record it came
from and the surfaces it appears on, and the checker recomputes it and looks for the literal string.

Three things it does that the census does not:

* **A falsifier is required.** An entry no one could disprove is not a claim, it is a slogan. The
  field names who could show it false and how, and an entry without one is refused by name.
* **A correction appends, never overwrites.** Changing a published entry's text or status requires
  appending a correction that retains the previous text, and `supersedes_digest` makes the retention
  load-bearing: a retained text edited to say something more flattering no longer hashes to its own
  digest. Removing a correction the parent revision carried is refused by comparison against it.
* **Two rendered views, one record.** The English and Arabic views must carry a byte-identical
  `head_digest` line and byte-identical quotations, because a localized pack that disagrees with the
  source-language pack is a defect and not a translation note.

What it does NOT do, stated here because the same paragraph is rendered into both published views
and the checker refuses a ledger that omits it: it refuses a merge, not an edit; it holds only where
it runs as a required check; `head_digest` is a hash and not a signature; nothing is anchored in a
transparency log; and `fact` means "recomputed from a named record here", never "true".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LEDGER_RELATIVE_PATH = Path("evidence") / "claims.json"
LOCALES_RELATIVE_PATH = Path("tools") / "ci" / "claim_locales.json"
LEDGER_FORMAT = "warrantor.claim-ledger/1"
LOCALES_FORMAT = "warrantor.claim-locales/1"

# Three statuses, and the distinction between them is the whole point of the artifact.
#
# `fact`    -- recomputed from a named record in this repository by this checker. Not "true".
# `claim`   -- asserted by this project and not recomputable here; its falsifier says how to check.
# `unknown` -- an open question this project has not answered, published rather than omitted.
ALLOWED_STATUSES = frozenset({"fact", "claim", "unknown"})

# The rendered views. The keys are the locale ids `claim_locales.json` must carry.
VIEWS: dict[str, Path] = {
    "en": Path("docs") / "public-claims.md",
    "ar": Path("docs") / "public-claims.ar.md",
}
SOURCE_LANGUAGE = "en"

# Marks every line whose content is quoted from the ledger rather than localized. `check_views`
# compares these across locales, which is what makes "quotations are never translated" checkable.
QUOTE_MARKER = ">"


@dataclass(frozen=True)
class ClaimIssue:
    """One reason the ledger is refused."""

    claim: str
    message: str


# --- records and reductions ---------------------------------------------------------------------


def resolve_pointer(document: object, pointer: str) -> object:
    """Resolve an RFC 6901 JSON pointer against a parsed record."""

    if pointer in {"", "/"}:
        return document
    if not pointer.startswith("/"):
        raise KeyError(f"pointer {pointer!r} must begin with '/'")
    current = document
    for raw in pointer.lstrip("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict):
            current = current[token]
        else:
            raise KeyError(f"pointer {pointer!r} does not resolve in this record")
    return current


# The order `check_invariants.py` prints its census in, which is `sorted(ALLOWED_STATUSES)` there.
# Spelled out rather than derived, because this tuple also fixes the order of a rendered template's
# arguments, and a set iteration order is the wrong thing to hang a published sentence on.
INVARIANT_STATUS_ORDER = ("enforced", "partial", "orphaned", "unimplemented")
CORPUS_SUITE_GLOB = "i??_*.rs"


def invariant_status_census(record: Path) -> list[object]:
    """Counts of each invariant status in `evidence/invariants.json`, in template order."""

    document = json.loads(record.read_text(encoding="utf-8"))
    entries = cast(list[dict[str, object]], document["invariants"])
    counted = Counter(str(entry["status"]) for entry in entries)
    return [counted[status] for status in INVARIANT_STATUS_ORDER]


def wiring_reachability(record: Path) -> list[object]:
    """Reachable, total, ORPHANED and edges from the wiring record.

    The orphan count is a subtraction, and a template cannot subtract. Doing it here rather than
    letting the ledger carry a pre-computed `28` is the whole point: `readme_renders` gates one
    rendering of this number in the README status table, and a SECOND rendering of the same number
    in the same file -- "9 of 39 crates link into the warrantor binary ... names the other 30" --
    went stale anyway, because nothing recomputed it.
    """

    document = json.loads(record.read_text(encoding="utf-8"))
    reachable = int(cast(int, document["reachable"]))
    total = int(cast(int, document["total"]))
    return [reachable, total, total - reachable, int(cast(int, document["edges"]))]


def corpus_finding_census(record: Path) -> list[object]:
    """How many invariant suites hold a recorded finding, and which hold none.

    Counts SUITES carrying at least one `#[ignore` line, not the attributes themselves. The corpus
    already gates the attribute count from Rust, in
    `rust/warrant/tests/invariants/adversary/mod.rs`'s `ignore_attributes_in_the_corpus`, and this
    is a different question -- so this is not a second reader of that rule.
    """

    with_findings: list[str] = []
    without: list[str] = []
    for suite in sorted(record.glob(CORPUS_SUITE_GLOB)):
        ignores = sum(
            1
            for line in suite.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.lstrip().startswith("#[ignore")
        )
        identifier = f"I-{suite.name[1:3]}"
        (with_findings if ignores else without).append(identifier)
    if len(without) > 1:
        named = ", ".join(without[:-1]) + " and " + without[-1]
    else:
        named = "".join(without)
    return [len(with_findings), len(with_findings) + len(without), named]


# Named reductions the ledger may SELECT but not define. A claim carries a name from this table and
# nothing else, so an entry cannot smuggle in a computation of its own.
REDUCTIONS = {
    "invariant_status_census": invariant_status_census,
    "corpus_finding_census": corpus_finding_census,
    "wiring_reachability": wiring_reachability,
}


def expected_rendering(repository_root: Path, claim: dict[str, object]) -> str:
    """The literal string this claim must render as, computed from its cited record."""

    source = cast(dict[str, object], claim["derived_from"])
    record = repository_root / str(source["record"])
    reduction = source.get("reduce")
    if reduction is not None:
        values = REDUCTIONS[str(reduction)](record)
    else:
        document = json.loads(record.read_text(encoding="utf-8"))
        values = [resolve_pointer(document, str(p)) for p in cast(list[str], source["pointers"])]
    return str(claim["template"]).format(*values)


def unwrapped(text: str) -> str:
    """One line, single-spaced. Line wrapping is not a truth claim.

    `readme_renders` compares a literal substring against the raw file, which works only because the
    row it gates happens to be one very long line. Every prose surface in this repository wraps at
    about 100 columns, and a paragraph carrying a derived sentence will wrap somewhere inside it --
    so a strict substring test would refuse the honest document and pass only if the author kept the
    sentence on one line forever. That is a gate people learn to route around. Collapsing runs of
    whitespace accepts everything the strict form accepts and additionally survives a re-wrap; it
    does NOT let a sentence match across a table-cell boundary, because `|` is not whitespace.
    """

    return " ".join(text.split())


def contains_rendering(haystack: str, expected: str) -> bool:
    """True when `expected` appears in `haystack`, ignoring only how the lines are broken."""

    return unwrapped(expected) in unwrapped(haystack)


def renders(repository_root: Path, surface: str, expected: str) -> bool:
    """True when the surface contains the expected string, up to line wrapping."""

    path = repository_root / surface
    if not path.is_file():
        return False
    return contains_rendering(path.read_text(encoding="utf-8"), expected)


# --- digests ------------------------------------------------------------------------------------


def state_digest(claim_id: str, version: int, status: str, text: str) -> str:
    """A digest over one version of one claim. Canonical, so two clones agree."""

    canonical = json.dumps(
        {"id": claim_id, "version": version, "status": status, "text": text},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def history_digest(claim: dict[str, object]) -> str:
    """Fold the whole history into one digest, so dropping the last correction changes it."""

    accumulator = hashlib.sha256(str(claim["id"]).encode("utf-8")).hexdigest()
    for correction in cast(list[dict[str, object]], claim["corrections"]):
        accumulator = hashlib.sha256(
            (accumulator + str(correction.get("supersedes_digest", ""))).encode("utf-8")
        ).hexdigest()
    current = state_digest(
        str(claim["id"]),
        int(cast(int, claim["version"])),
        str(claim["status"]),
        str(claim["text"]),
    )
    return "sha256:" + hashlib.sha256((accumulator + current).encode("utf-8")).hexdigest()


def head_digest(ledger: dict[str, object]) -> str:
    """Fold every entry's history into one head, seeded with the published limitation.

    `bound_statement` is folded in on purpose: softening the paragraph that says what this gate does
    not cover would otherwise leave the head unchanged, and that paragraph is the most tempting
    thing in the file to quietly improve.
    """

    accumulator = hashlib.sha256(
        (str(ledger.get("format", "")) + str(ledger.get("bound_statement", ""))).encode("utf-8")
    ).hexdigest()
    for claim in cast(list[dict[str, object]], ledger["claims"]):
        accumulator = hashlib.sha256(
            (accumulator + history_digest(claim)).encode("utf-8")
        ).hexdigest()
    return "sha256:" + accumulator


# --- per-entry checks ---------------------------------------------------------------------------


def check_falsifier(claim_id: str, claim: dict[str, object]) -> list[ClaimIssue]:
    """An entry must name who could show it false and how."""

    falsifier = claim.get("falsifier")
    if not isinstance(falsifier, dict) or not falsifier:
        return [
            ClaimIssue(claim_id, "no falsifier: an entry must name who could show it false and how")
        ]
    issues: list[ClaimIssue] = []
    for field in ("who", "how"):
        value = falsifier.get(field)
        if not isinstance(value, str) or not value.strip():
            issues.append(ClaimIssue(claim_id, f"falsifier.{field} is empty"))
    return issues


def check_corrections(claim_id: str, claim: dict[str, object]) -> list[ClaimIssue]:
    """A correction is an addition, never a rewrite."""

    corrections = claim.get("corrections")
    if not isinstance(corrections, list):
        return [ClaimIssue(claim_id, "corrections must be a list")]
    entries = cast(list[dict[str, object]], corrections)
    version = claim.get("version")
    if not isinstance(version, int) or version < 1:
        return [ClaimIssue(claim_id, "version must be an integer of at least 1")]
    issues: list[ClaimIssue] = []
    if version != len(entries) + 1:
        issues.append(
            ClaimIssue(
                claim_id,
                f"version {version} with {len(entries)} corrections: a published entry's text or "
                f"status may only change by appending a correction that retains the previous text",
            )
        )
    previous_date = ""
    for index, correction in enumerate(entries):
        ordinal = index + 1
        if correction.get("version") != ordinal:
            issues.append(
                ClaimIssue(claim_id, f"correction {ordinal} must carry version {ordinal}")
            )
        date = correction.get("date")
        if not isinstance(date, str) or not date.strip():
            issues.append(ClaimIssue(claim_id, f"correction {ordinal} has no date"))
            date = ""
        elif date < previous_date:
            issues.append(
                ClaimIssue(
                    claim_id, f"correction {ordinal} date moves backward from {previous_date}"
                )
            )
        previous_date = max(previous_date, date)
        reason = correction.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            issues.append(ClaimIssue(claim_id, f"correction {ordinal} has no reason"))
        superseded_text = correction.get("superseded_text")
        superseded_status = correction.get("superseded_status")
        if not isinstance(superseded_text, str) or not superseded_text.strip():
            issues.append(ClaimIssue(claim_id, f"correction {ordinal} retains no superseded_text"))
            continue
        if superseded_status not in ALLOWED_STATUSES:
            issues.append(
                ClaimIssue(
                    claim_id,
                    f"correction {ordinal} superseded_status {superseded_status!r} not in "
                    f"{sorted(ALLOWED_STATUSES)}",
                )
            )
            continue
        expected = state_digest(claim_id, ordinal, str(superseded_status), superseded_text)
        if correction.get("supersedes_digest") != expected:
            issues.append(
                ClaimIssue(
                    claim_id,
                    f"correction {ordinal} supersedes_digest does not match the text it retains; "
                    f"a retained text that no longer hashes to its own digest is a rewritten "
                    f"history, expected {expected}",
                )
            )
    return issues


def check_claim(repository_root: Path, claim: dict[str, object]) -> list[ClaimIssue]:
    """Validate one ledger entry against the records and surfaces it names."""

    claim_id = str(claim.get("id", "<missing id>"))
    issues: list[ClaimIssue] = []
    status = claim.get("status")
    if status not in ALLOWED_STATUSES:
        issues.append(ClaimIssue(claim_id, f"status {status!r} not in {sorted(ALLOWED_STATUSES)}"))
    text = claim.get("text")
    if not isinstance(text, str) or not text.strip():
        issues.append(ClaimIssue(claim_id, "text is empty"))
        text = ""
    issues.extend(check_falsifier(claim_id, claim))
    issues.extend(check_corrections(claim_id, claim))

    source = claim.get("derived_from")
    has_record = isinstance(source, dict) and bool(source.get("record"))
    if status == "fact" and not has_record:
        issues.append(
            ClaimIssue(
                claim_id,
                "fact needs derived_from with a record: `fact` means recomputed from a named "
                "record in this repository, and an entry with no record cannot be recomputed",
            )
        )
    expected: str | None = text
    if has_record:
        try:
            expected = expected_rendering(repository_root, claim)
        except (OSError, KeyError, IndexError, ValueError) as error:
            issues.append(
                ClaimIssue(
                    claim_id, f"derived_from does not resolve: {type(error).__name__}: {error}"
                )
            )
            expected = None
        else:
            if not contains_rendering(text, expected):
                issues.append(
                    ClaimIssue(
                        claim_id,
                        f"text does not contain the rendering derived from its record: "
                        f"expected {expected!r}",
                    )
                )
    if expected is None:
        return issues
    surfaces = claim.get("surfaces")
    if not isinstance(surfaces, list):
        return [*issues, ClaimIssue(claim_id, "surfaces must be a list")]
    for surface in cast(list[str], surfaces):
        if not renders(repository_root, str(surface), expected):
            issues.append(
                ClaimIssue(
                    claim_id, f"does not render in {surface}: expected {expected!r} verbatim"
                )
            )
    return issues


# --- the ledger, and the parent revision --------------------------------------------------------


def load_ledger(path: Path) -> dict[str, object]:
    """Read one ledger, refusing an unversioned or malformed one."""

    document = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    if document.get("format") != LEDGER_FORMAT:
        raise ValueError(f"{path}: format {document.get('format')!r} is not {LEDGER_FORMAT}")
    return document


def load_locales(path: Path) -> dict[str, dict[str, str]]:
    """Read the reviewed label vocabulary, one table per locale."""

    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("format") != LOCALES_FORMAT:
        raise ValueError(f"{path}: format {document.get('format')!r} is not {LOCALES_FORMAT}")
    return cast(dict[str, dict[str, str]], document["locales"])


def check_bound_statement(repository_root: Path, ledger: dict[str, object]) -> list[ClaimIssue]:
    """The published limitation must appear verbatim on every surface that claims to carry it.

    Listed in the ledger rather than hardcoded to the two views, because the README carries it too
    and a limitation published in one place and summarized more kindly in another is the defect this
    whole file exists to refuse.
    """

    bound = ledger.get("bound_statement")
    if not isinstance(bound, str) or not bound.strip():
        return [
            ClaimIssue(
                "ledger",
                "bound_statement is missing: an honest limitation that is not rendered is not "
                "published",
            )
        ]
    surfaces = ledger.get("bound_surfaces")
    if not isinstance(surfaces, list) or not surfaces:
        return [
            ClaimIssue(
                "ledger",
                "bound_surfaces must name at least one surface the limitation is published on",
            )
        ]
    return [
        ClaimIssue(
            "ledger",
            f"bound_statement does not appear verbatim in {surface}; an honest limitation that is "
            f"not rendered is not published",
        )
        for surface in cast(list[str], surfaces)
        if not renders(repository_root, str(surface), bound)
    ]


def check_ledger(repository_root: Path, ledger: dict[str, object]) -> list[ClaimIssue]:
    """Validate the whole ledger: format, the published limitation, the head, then each entry."""

    issues: list[ClaimIssue] = []
    if ledger.get("format") != LEDGER_FORMAT:
        issues.append(ClaimIssue("ledger", f"format must be {LEDGER_FORMAT!r}"))
    issues.extend(check_bound_statement(repository_root, ledger))
    claims = ledger.get("claims")
    if not isinstance(claims, list):
        return [*issues, ClaimIssue("ledger", "claims must be a list")]
    entries = cast(list[dict[str, object]], claims)
    seen: set[str] = set()
    for entry in entries:
        identifier = str(entry.get("id"))
        if identifier in seen:
            issues.append(ClaimIssue("ledger", f"duplicate id {identifier}"))
        seen.add(identifier)
    recomputed = head_digest(ledger)
    if ledger.get("head_digest") != recomputed:
        issues.append(
            ClaimIssue(
                "ledger",
                f"head_digest is stale: recorded {ledger.get('head_digest')}, recomputed "
                f"{recomputed}; run `python tools/ci/check_claims.py --write`",
            )
        )
    for entry in entries:
        issues.extend(check_claim(repository_root, entry))
    return issues


def check_append_only(previous: dict[str, object], current: dict[str, object]) -> list[ClaimIssue]:
    """Every claim and every correction in the parent revision must still be present, verbatim."""

    issues: list[ClaimIssue] = []
    old = {str(c["id"]): c for c in cast(list[dict[str, object]], previous["claims"])}
    new = {str(c["id"]): c for c in cast(list[dict[str, object]], current["claims"])}
    for claim_id, before in old.items():
        after = new.get(claim_id)
        if after is None:
            issues.append(ClaimIssue(claim_id, "removed from the ledger; entries are append-only"))
            continue
        # `.get` with a default rather than indexing: a malformed entry is already reported by
        # `check_claim`, and a traceback here would bury that message under a stack trace.
        if int(cast(int, after.get("version", 0))) < int(cast(int, before.get("version", 0))):
            issues.append(ClaimIssue(claim_id, "version fell; a claim version may only rise"))
        kept = cast(list[dict[str, object]], after.get("corrections", []))
        for index, correction in enumerate(
            cast(list[dict[str, object]], before.get("corrections", []))
        ):
            if index >= len(kept) or kept[index] != correction:
                issues.append(
                    ClaimIssue(
                        claim_id,
                        f"correction {index + 1} was removed or altered; a retraction is "
                        f"retained, never deleted",
                    )
                )
    return issues


def parent_ledger(repository_root: Path, ref: str) -> dict[str, object] | None:
    """The ledger as of `ref`; None when `ref` predates the file, raising when `ref` is unreachable.

    The distinction is load-bearing. A ref that exists and simply has no ledger yet is the first
    revision of the file, and there is nothing to compare. A ref that cannot be resolved means the
    checkout has no history -- and a comparison that reports success because it could not run is
    how a silent removal would land.
    """

    resolved = subprocess.run(
        ["git", "rev-parse", "--verify", f"{ref}^{{commit}}"],
        cwd=repository_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if resolved.returncode != 0:
        raise LookupError(
            f"cannot resolve {ref!r}: the append-only comparison has no history to read. A shallow "
            f"or historyless checkout must fail this gate rather than skip it."
        )
    shown = subprocess.run(
        ["git", "show", f"{ref}:{LEDGER_RELATIVE_PATH.as_posix()}"],
        cwd=repository_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if shown.returncode != 0:
        return None
    return cast(dict[str, object], json.loads(shown.stdout))


# --- the rendered views -------------------------------------------------------------------------


def quoted_lines(view: str) -> list[str]:
    """Every line quoted from the ledger, in order, with its indent and marker stripped."""

    return [
        line.strip().lstrip(QUOTE_MARKER).strip()
        for line in view.splitlines()
        if line.strip().startswith(QUOTE_MARKER)
    ]


def write_lf(path: Path, text: str) -> None:
    """Write a generated artifact with LF endings on every platform."""

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def head_digest_line(ledger_head: str) -> str:
    """The one line both views must carry byte for byte."""

    return f"`head_digest` {ledger_head}"


def render_view(ledger: dict[str, object], locale: str, labels: dict[str, str]) -> str:
    """One rendered view. Claim bodies and quotations are never translated."""

    marker = f"<!-- source language: {SOURCE_LANGUAGE}; not translated -->"
    lines = [
        "<!-- Generated by tools/ci/check_claims.py --write. Do not edit by hand. -->",
        f"# {labels['title']}",
        "",
        f"*{labels['locale_note']}*",
        "",
        head_digest_line(str(ledger["head_digest"])),
        "",
        f"## {labels['bound_heading']}",
        "",
        marker,
        "",
        f"> {ledger['bound_statement']}",
        "",
        f"## {labels['claims_heading']}",
        "",
    ]
    for claim in cast(list[dict[str, object]], ledger["claims"]):
        falsifier = cast(dict[str, str], claim["falsifier"])
        lines += [
            f"### {claim['id']} — {labels[str(claim['status'])]}",
            "",
            marker,
            "",
            f"> {claim['text']}",
            "",
            f"- {labels['falsifier']}: {falsifier['who']}",
            f"  > {falsifier['how']}",
            "",
        ]
        corrections = cast(list[dict[str, object]], claim["corrections"])
        if corrections:
            lines += [f"{labels['history_heading']}", ""]
        for correction in corrections:
            lines += [
                f"- {labels['superseded']} v{correction['version']} ({correction['date']}): "
                f"{correction['reason']}",
                f"  > {correction['superseded_text']}",
                "",
            ]
    return "\n".join(lines) + "\n"


def check_views(views: dict[str, str]) -> list[ClaimIssue]:
    """Both views must agree on the head digest and on every quotation."""

    issues: list[ClaimIssue] = []
    locales = sorted(views)
    reference = locales[0]
    reference_quotes = quoted_lines(views[reference])
    reference_head = next(
        (line for line in views[reference].splitlines() if line.startswith("`head_digest`")), ""
    )
    for locale in locales[1:]:
        head = next(
            (line for line in views[locale].splitlines() if line.startswith("`head_digest`")), ""
        )
        if head != reference_head:
            issues.append(
                ClaimIssue(
                    "views",
                    f"head_digest differs between views ({reference} vs {locale}); this is a "
                    f"defect, not a translation note",
                )
            )
        quotes = quoted_lines(views[locale])
        if quotes != reference_quotes:
            differing = next(
                (
                    (index, left, right)
                    for index, (left, right) in enumerate(zip(reference_quotes, quotes))
                    if left != right
                ),
                None,
            )
            detail = (
                f"first difference at quotation {differing[0] + 1}: "
                f"{differing[1]!r} vs {differing[2]!r}"
                if differing is not None
                else f"{len(reference_quotes)} quotations in {reference}, {len(quotes)} in {locale}"
            )
            issues.append(
                ClaimIssue(
                    "views",
                    f"quoted text differs between views ({reference} vs {locale}); a translated "
                    f"quotation manufactures a claim nobody made. {detail}",
                )
            )
    return issues


def check_rendered_views(
    repository_root: Path, ledger: dict[str, object], locales: dict[str, dict[str, str]]
) -> list[ClaimIssue]:
    """The committed views must be what `--write` produces, and must agree with each other."""

    issues: list[ClaimIssue] = []
    on_disk: dict[str, str] = {}
    for locale, relative in VIEWS.items():
        if locale not in locales:
            issues.append(
                ClaimIssue("views", f"{LOCALES_RELATIVE_PATH.as_posix()} has no {locale} labels")
            )
            continue
        path = repository_root / relative
        if not path.is_file():
            issues.append(ClaimIssue("views", f"{relative.as_posix()} is missing"))
            continue
        text = path.read_text(encoding="utf-8")
        on_disk[locale] = text
        if text != render_view(ledger, locale, locales[locale]):
            issues.append(
                ClaimIssue(
                    "views",
                    f"{relative.as_posix()} is not what the ledger renders to; run "
                    f"`python tools/ci/check_claims.py --write`",
                )
            )
    if len(on_disk) > 1:
        issues.extend(check_views(on_disk))
    return issues


# --- entry point --------------------------------------------------------------------------------


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=REPOSITORY_ROOT / LEDGER_RELATIVE_PATH)
    parser.add_argument("--locales", type=Path, default=REPOSITORY_ROOT / LOCALES_RELATIVE_PATH)
    parser.add_argument(
        "--parent-ref",
        default="HEAD",
        help=(
            "the revision the append-only comparison reads the previous ledger from. Default HEAD, "
            "which is the parent revision for an uncommitted working tree; CI must pass the base "
            "of the branch, because in a clean checkout HEAD is the commit under test and "
            "comparing a commit against itself is a gate that never runs."
        ),
    )
    parser.add_argument(
        "--write", action="store_true", help="rewrite the head digest and both rendered views"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Recompute, then either record or gate."""

    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    repository_root = arguments.ledger.resolve().parents[1]
    ledger = load_ledger(arguments.ledger)
    locales = load_locales(arguments.locales)

    if arguments.write:
        ledger["head_digest"] = head_digest(ledger)
        # newline="\n" on every write: `write_text` translates "\n" to os.linesep, so the same
        # command run on Windows and on Linux would otherwise emit different bytes for the same
        # ledger. Reading normalizes, so this is not what makes the comparison work -- it is what
        # keeps a committed generated artifact from carrying the author's platform.
        write_lf(arguments.ledger, json.dumps(ledger, indent=2, ensure_ascii=False) + "\n")
        for locale, relative in VIEWS.items():
            write_lf(repository_root / relative, render_view(ledger, locale, locales[locale]))
            print(f"rendered: {relative.as_posix()}")
        print(f"claim ledger: head_digest {ledger['head_digest']}")
        return 0

    issues = check_ledger(repository_root, ledger)
    issues.extend(check_rendered_views(repository_root, ledger, locales))
    try:
        previous = parent_ledger(repository_root, arguments.parent_ref)
    except LookupError as error:
        print(f"::error::{LEDGER_RELATIVE_PATH.as_posix()}: {error}")
        return 1
    if previous is None:
        print(
            f"no parent ledger at {arguments.parent_ref}; the append-only comparison has nothing "
            f"to compare, because that revision does not carry the file"
        )
    else:
        issues.extend(check_append_only(previous, ledger))

    for issue in issues:
        print(f"::error::{LEDGER_RELATIVE_PATH.as_posix()}: {issue.claim}: {issue.message}")
    if issues:
        print(f"claim ledger: {len(issues)} issue(s); refusing")
        return 1
    entries = cast(list[dict[str, object]], ledger["claims"])
    counted = Counter(str(entry["status"]) for entry in entries)
    summary = ", ".join(f"{status}={counted[status]}" for status in sorted(ALLOWED_STATUSES))
    corrections = sum(len(cast(list[object], entry["corrections"])) for entry in entries)
    print(
        f"claim ledger: {len(entries)} claims; {summary}; {corrections} retained corrections; "
        f"head {ledger['head_digest']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
