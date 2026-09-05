"""Tests for tools/ci/check_invariants.py — the invariant ledger checker."""

from __future__ import annotations

import json
from pathlib import Path

from check_invariants import (
    LEDGER_FORMAT,
    REPOSITORY_ROOT,
    check_entry,
    check_ledger,
    cited_test_exists,
    doc_statements,
    symbol_exists,
)

DOC_TABLE = """## 3. The 12 Formal Invariants (I-01 … I-12)

| ID | Invariant | Enforced primarily by |
|---|---|---|
| **I-01** | **No active identity, no action.** Every action carries an SVID. | I1 |
"""

NOTARY_SOURCE = """pub enum Gate { Identity }
#[cfg(test)]
mod tests {
    #[test]
    fn gate2_identity_revoked_svid_denies() {}
    fn helper_not_a_test() {}
}
"""


def fake_repository(tmp_path: Path) -> Path:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "02-architecture.md").write_text(DOC_TABLE, encoding="utf-8")
    source = tmp_path / "rust" / "notary" / "src"
    source.mkdir(parents=True)
    (source / "lib.rs").write_text(NOTARY_SOURCE, encoding="utf-8")
    return tmp_path


def test_doc_statements_strip_bold_markers(tmp_path: Path) -> None:
    repository = fake_repository(tmp_path)
    assert doc_statements(repository / "docs" / "02-architecture.md") == {
        "I-01": "No active identity, no action. Every action carries an SVID."
    }


def test_cited_test_exists_requires_the_test_attribute(tmp_path: Path) -> None:
    repository = fake_repository(tmp_path)
    assert cited_test_exists(
        repository, "rust/notary/src/lib.rs::gate2_identity_revoked_svid_denies"
    )
    assert not cited_test_exists(repository, "rust/notary/src/lib.rs::helper_not_a_test")
    assert not cited_test_exists(repository, "rust/notary/src/lib.rs::absent")
    assert not cited_test_exists(
        repository, "rust/nowhere/src/lib.rs::gate2_identity_revoked_svid_denies"
    )
    assert not cited_test_exists(repository, "not a reference")


def test_symbol_exists_finds_the_last_path_segment(tmp_path: Path) -> None:
    repository = fake_repository(tmp_path)
    assert symbol_exists(repository, "notary", "warrantor_notary::Gate::Identity")
    assert not symbol_exists(repository, "notary", "warrantor_notary::Gate::Nowhere")
    assert not symbol_exists(repository, "nowhere", "warrantor_notary::Gate::Identity")


def entry(status: str, enforced_by: list[dict[str, object]]) -> dict[str, object]:
    return {
        "id": "I-01",
        "statement": "No active identity, no action. Every action carries an SVID.",
        "enforced_by": enforced_by,
        "status": status,
    }


GOOD_RECORD: dict[str, object] = {
    "crate": "notary",
    "symbol": "warrantor_notary::Gate::Identity",
    "test": "rust/notary/src/lib.rs::gate2_identity_revoked_svid_denies",
}


def test_unimplemented_cites_nothing_and_every_other_status_cites_something(
    tmp_path: Path,
) -> None:
    repository = fake_repository(tmp_path)
    statements = doc_statements(repository / "docs" / "02-architecture.md")
    assert check_entry(repository, entry("partial", [GOOD_RECORD]), statements) == []
    assert check_entry(repository, entry("unimplemented", []), statements) == []
    messages = [
        issue.message
        for issue in check_entry(repository, entry("unimplemented", [GOOD_RECORD]), statements)
    ]
    assert messages == ["unimplemented must list no enforcement"]
    messages = [
        issue.message for issue in check_entry(repository, entry("enforced", []), statements)
    ]
    assert messages == ["enforced needs at least one enforced_by entry"]


def test_orphaned_may_not_cite_a_crate_the_binary_links(tmp_path: Path) -> None:
    repository = fake_repository(tmp_path)
    statements = doc_statements(repository / "docs" / "02-architecture.md")
    messages = [
        issue.message
        for issue in check_entry(repository, entry("orphaned", [GOOD_RECORD]), statements)
    ]
    assert messages == ["orphaned but cites a crate the warrantor binary links"]


def test_a_missing_test_or_symbol_or_drifted_statement_is_refused(tmp_path: Path) -> None:
    repository = fake_repository(tmp_path)
    statements = doc_statements(repository / "docs" / "02-architecture.md")
    bad_record: dict[str, object] = {
        "crate": "notary",
        "symbol": "warrantor_notary::Gate::Nowhere",
        "test": "rust/notary/src/lib.rs::absent",
    }
    drifted = entry("partial", [bad_record])
    drifted["statement"] = "No active identity, no action."
    messages = sorted(issue.message for issue in check_entry(repository, drifted, statements))
    assert messages == [
        "statement drifted from docs/02-architecture.md",
        "symbol 'warrantor_notary::Gate::Nowhere' not found under rust/notary",
        "test 'rust/notary/src/lib.rs::absent' does not exist",
    ]


def test_ledger_requires_the_versioned_format_and_all_twelve_ids(tmp_path: Path) -> None:
    repository = fake_repository(tmp_path)
    ledger: dict[str, object] = {"format": "warrantor.invariant-ledger/2", "invariants": []}
    messages = [issue.message for issue in check_ledger(repository, ledger)]
    assert messages[0] == f"format must be {LEDGER_FORMAT!r}"
    assert messages[1].startswith("ids must be exactly ['I-01', 'I-02'")


def test_the_real_ledger_passes() -> None:
    ledger_path = REPOSITORY_ROOT / "evidence" / "invariants.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert check_ledger(REPOSITORY_ROOT, ledger) == []
