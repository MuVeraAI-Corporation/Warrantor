"""Tests for data_provenance_kit: lineage tracking, digests, JSON-LD export, CLI."""

from __future__ import annotations

import json

import pytest

from data_provenance_kit import Dataset, SourceType, TransformationType, snapshot_digest
from data_provenance_kit.cli import main


def sample_rows() -> list[dict]:
    return [
        {"id": 1, "text": "hello", "email": "alice@example.com"},
        {"id": 2, "text": "world", "email": "bob@example.com"},
        {"id": 1, "text": "hello", "email": "alice@example.com"},  # exact duplicate of row 1
        {"id": 4, "text": "private", "email": "carol@example.com"},
    ]


def test_source_node_records_initial_state() -> None:
    ds = Dataset.from_source(sample_rows(), SourceType.LOCAL, "file:///data.jsonl")
    assert len(ds.nodes) == 1
    assert ds.nodes[0].transformation is TransformationType.SOURCE
    assert ds.nodes[0].row_count_after == 4
    assert ds.nodes[0].digest_after is not None


def test_filter_records_row_count_delta() -> None:
    ds = Dataset.from_source(sample_rows(), SourceType.LOCAL, "file:///x")
    ds.filter(lambda r: r["id"] % 2 == 0, detail="even-ids-only")
    assert len(ds.nodes) == 2
    f = ds.nodes[1]
    assert f.transformation is TransformationType.FILTER
    assert f.row_count_before == 4
    assert f.row_count_after == 2
    assert f.parents == [ds.nodes[0].id]


def test_dedup_collapses_identical_rows() -> None:
    ds = Dataset.from_source(sample_rows(), SourceType.LOCAL, "file:///x")
    ds.dedup()
    assert len(ds.rows) == 3  # row 3 was a dup of row 1
    last = ds.nodes[-1]
    assert last.transformation is TransformationType.DEDUP
    assert last.row_count_after == 3


def test_pii_redact_records_redaction_node() -> None:
    ds = Dataset.from_source(sample_rows(), SourceType.LOCAL, "file:///x")
    ds.pii_redact(lambda r: {**r, "email": "(redacted)"}, detail="email-redact")
    last = ds.nodes[-1]
    assert last.transformation is TransformationType.PII_REDACT
    assert all(r["email"] == "(redacted)" for r in ds.rows)


def test_concat_creates_two_parent_node() -> None:
    ds1 = Dataset.from_source([{"a": 1}], SourceType.LOCAL, "file:///x")
    ds2 = Dataset.from_source([{"a": 2}, {"a": 3}], SourceType.LOCAL, "file:///y")
    ds1.concat(ds2, detail="merge")
    last = ds1.nodes[-1]
    assert last.transformation is TransformationType.CONCAT
    assert len(last.parents) == 2
    assert ds1.nodes[0].id in last.parents
    assert ds2.current_node_id in last.parents
    assert len(ds1.rows) == 3


def test_map_records_per_row_transform() -> None:
    ds = Dataset.from_source([{"x": 1}], SourceType.LOCAL, "file:///x")
    ds.map(lambda r: {**r, "y": r["x"] * 2})
    assert ds.rows[0]["y"] == 2
    assert ds.nodes[-1].transformation is TransformationType.MAP


def test_snapshot_digest_is_order_independent() -> None:
    a = [{"x": 1}, {"x": 2}]
    b = [{"x": 2}, {"x": 1}]
    assert snapshot_digest(a) == snapshot_digest(b)


def test_snapshot_digest_changes_on_content_change() -> None:
    a = [{"x": 1}]
    b = [{"x": 2}]
    assert snapshot_digest(a) != snapshot_digest(b)


def test_jsonld_export_has_graph_and_head() -> None:
    ds = Dataset.from_source(sample_rows(), SourceType.LOCAL, "file:///x")
    ds.dedup().filter(lambda r: True)
    out = ds.to_jsonld()
    assert out["@graph"][0]["@type"] == "aumos:source"
    assert len(out["@graph"]) == 3
    assert out["aumos:head_node"].endswith(ds.current_node_id)
    assert out["aumos:final_row_count"] == len(ds.rows)


def test_custom_records_arbitrary_transform() -> None:
    ds = Dataset.from_source([{"x": 1}], SourceType.LOCAL, "file:///x")
    ds.custom(lambda rows: [*rows, {"x": 99}], detail="append-marker", operator="script:foo.py")
    last = ds.nodes[-1]
    assert last.transformation is TransformationType.CUSTOM
    assert last.operator == "script:foo.py"
    assert len(ds.rows) == 2


def test_cli_emits_jsonld(tmp_path, capsys: pytest.CaptureFixture[str]) -> int | None:
    p = tmp_path / "in.jsonl"
    p.write_text('{"id":1,"text":"a"}\n{"id":2,"text":"b"}\n', encoding="utf-8")
    rc = main(["--input", str(p), "--source-uri", "file:///in.jsonl", "--operator", "test"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["@graph"][0]["@type"] == "aumos:source"
    assert out["aumos:final_row_count"] == 2
    return rc
