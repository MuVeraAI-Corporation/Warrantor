#!/usr/bin/env python3
"""Fail-closed checker for the invariant ledger at evidence/invariants.json.

The ledger is the honest label for I-01..I-12. Every entry names the tests that
observe a refusal; this checker refuses a ledger whose tests do not exist, whose
statements drift from docs/02-architecture.md, or whose status disagrees with
where its evidence lives.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LEDGER_RELATIVE_PATH = Path("evidence") / "invariants.json"
ARCHITECTURE_RELATIVE_PATH = Path("docs") / "02-architecture.md"
LEDGER_FORMAT = "warrantor.invariant-ledger/1"
ALLOWED_STATUSES = frozenset({"enforced", "partial", "orphaned", "unimplemented"})
EXPECTED_IDS = tuple(f"I-{number:02d}" for number in range(1, 13))
# The crate directories the `warrantor` binary links: rust/warrant/Cargo.toml path
# dependencies plus warrant itself. Task 0.3's census will replace this constant.
WARRANT_REACHABLE_CRATES = frozenset(
    {
        "warrant",
        "trust-core",
        "authority-spec",
        "evidence",
        "notary",
        "egress",
        "containment-conformance",
        "spend",
    }
)
TEST_REFERENCE = re.compile(
    r"^(?P<file>rust/[A-Za-z0-9_./-]+\.rs)::(?P<name>[A-Za-z_][A-Za-z0-9_]*)$"
)
DOC_ROW = re.compile(r"^\| \*\*(?P<id>I-\d{2})\*\* \| (?P<statement>.+?) \| [^|]+ \|$")


@dataclass(frozen=True)
class LedgerIssue:
    """One reason the ledger is refused."""

    invariant: str
    message: str


def doc_statements(architecture_doc: Path) -> dict[str, str]:
    """Read the I-xx rows of the architecture table; bold markers are stripped."""

    statements: dict[str, str] = {}
    for line in architecture_doc.read_text(encoding="utf-8").splitlines():
        match = DOC_ROW.match(line)
        if match:
            statements[match.group("id")] = match.group("statement").replace("**", "")
    return statements


def cited_test_exists(repository_root: Path, reference: str) -> bool:
    """True when `<file>::<name>` names a `fn` whose attribute block contains `#[test]`."""

    match = TEST_REFERENCE.match(reference)
    if match is None:
        return False
    source = repository_root / match.group("file")
    if not source.is_file():
        return False
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    signature = re.compile(rf"^\s*(pub\s+)?fn\s+{re.escape(match.group('name'))}\s*[(<]")
    return any(
        signature.match(line) and has_test_attribute(lines, index)
        for index, line in enumerate(lines)
    )


def has_test_attribute(lines: list[str], index: int) -> bool:
    """Walk upward from the `fn` line through its attributes and comments only.

    Stopping at the first line that is neither an attribute, a comment nor blank is
    what keeps a `#[test]` on the previous function from leaking onto a helper.
    """

    cursor = index - 1
    while cursor >= 0:
        previous = lines[cursor].strip()
        if previous == "#[test]":
            return True
        if previous.startswith(("#[", "//")) or not previous:
            cursor -= 1
            continue
        return False
    return False


def symbol_exists(repository_root: Path, crate: str, symbol: str) -> bool:
    """True when the symbol's last path segment occurs as a token in rust/<crate>/**/*.rs."""

    crate_root = repository_root / "rust" / crate
    if not crate_root.is_dir():
        return False
    identifier = symbol.rsplit("::", 1)[-1]
    token = re.compile(rf"\b{re.escape(identifier)}\b")
    return any(
        token.search(path.read_text(encoding="utf-8", errors="replace"))
        for path in crate_root.rglob("*.rs")
    )


def check_entry(
    repository_root: Path, entry: dict[str, object], statements: dict[str, str]
) -> list[LedgerIssue]:
    """Validate one invariant entry against the tree and the architecture table."""

    invariant = str(entry.get("id", "<missing id>"))
    issues: list[LedgerIssue] = []
    status = entry.get("status")
    if status not in ALLOWED_STATUSES:
        issues.append(
            LedgerIssue(invariant, f"status {status!r} not in {sorted(ALLOWED_STATUSES)}")
        )
    expected = statements.get(invariant)
    if expected is None:
        issues.append(LedgerIssue(invariant, "no row in docs/02-architecture.md section 3"))
    elif entry.get("statement") != expected:
        issues.append(LedgerIssue(invariant, "statement drifted from docs/02-architecture.md"))
    enforced_by = entry.get("enforced_by")
    if not isinstance(enforced_by, list):
        return [*issues, LedgerIssue(invariant, "enforced_by must be a list")]
    if status == "unimplemented" and enforced_by:
        issues.append(LedgerIssue(invariant, "unimplemented must list no enforcement"))
    if status != "unimplemented" and not enforced_by:
        issues.append(LedgerIssue(invariant, f"{status} needs at least one enforced_by entry"))
    linked: list[bool] = []
    for record in cast(list[dict[str, object]], enforced_by):
        crate = str(record.get("crate", ""))
        symbol = str(record.get("symbol", ""))
        test = str(record.get("test", ""))
        if not symbol_exists(repository_root, crate, symbol):
            issues.append(LedgerIssue(invariant, f"symbol {symbol!r} not found under rust/{crate}"))
        if not cited_test_exists(repository_root, test):
            issues.append(LedgerIssue(invariant, f"test {test!r} does not exist"))
        linked.append(crate in WARRANT_REACHABLE_CRATES)
    if status == "orphaned" and any(linked):
        issues.append(
            LedgerIssue(invariant, "orphaned but cites a crate the warrantor binary links")
        )
    if status in {"enforced", "partial"} and linked and not any(linked):
        issues.append(LedgerIssue(invariant, f"{status} but no cited crate is linked by warrantor"))
    return issues


def check_ledger(repository_root: Path, ledger: dict[str, object]) -> list[LedgerIssue]:
    """Validate the whole ledger: format, the twelve ids in order, then each entry."""

    issues: list[LedgerIssue] = []
    if ledger.get("format") != LEDGER_FORMAT:
        issues.append(LedgerIssue("ledger", f"format must be {LEDGER_FORMAT!r}"))
    invariants = ledger.get("invariants")
    if not isinstance(invariants, list):
        return [*issues, LedgerIssue("ledger", "invariants must be a list")]
    entries = cast(list[dict[str, object]], invariants)
    identifiers = tuple(str(item.get("id")) for item in entries)
    if identifiers != EXPECTED_IDS:
        issues.append(LedgerIssue("ledger", f"ids must be exactly {list(EXPECTED_IDS)} in order"))
    statements = doc_statements(repository_root / ARCHITECTURE_RELATIVE_PATH)
    for item in entries:
        issues.extend(check_entry(repository_root, item, statements))
    return issues


def main() -> int:
    """Exit 1 with every issue printed, or 0 with the status census."""

    ledger_path = REPOSITORY_ROOT / LEDGER_RELATIVE_PATH
    ledger = cast(dict[str, object], json.loads(ledger_path.read_text(encoding="utf-8")))
    issues = check_ledger(REPOSITORY_ROOT, ledger)
    for issue in issues:
        print(f"{LEDGER_RELATIVE_PATH.as_posix()}: {issue.invariant}: {issue.message}")
    if issues:
        print(f"invariant ledger: {len(issues)} issue(s); refusing")
        return 1
    entries = cast(list[dict[str, object]], ledger["invariants"])
    census = Counter(str(item["status"]) for item in entries)
    summary = ", ".join(f"{status}={census[status]}" for status in sorted(ALLOWED_STATUSES))
    print(f"invariant ledger: {len(entries)} invariants; {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
