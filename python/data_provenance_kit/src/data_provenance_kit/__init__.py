"""AumOS data-provenance-kit (S5) — dataset lineage tracker.

A ``Dataset`` class that wraps HF Datasets / S3 / local sources and records every transformation
(filter, map, shard, concat, dedup) as a node in a directed lineage graph. Exports signed
JSON-LD so a downstream model SBOM (S4) can reference the exact dataset lineage (EU AI Act
Article 55 §2: training-data summary).

See ``docs/rfcs/S5-data-provenance-kit.md``.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class SourceType(str, Enum):
    """Where the dataset originated."""

    LOCAL = "local"
    HF_HUB = "hf_hub"
    S3 = "s3"
    GCS = "gcs"
    DERIVED = "derived"  # produced by a transformation of another dataset


class TransformationType(str, Enum):
    """The kinds of transformations recorded as lineage nodes."""

    SOURCE = "source"  # the initial ingestion
    FILTER = "filter"  # row filtering
    MAP = "map"  # per-row transformation
    SHARD = "shard"  # sharding / splitting
    CONCAT = "concat"  # concatenation of multiple parents
    DEDUP = "dedup"  # deduplication
    PII_REDACT = "pii_redact"  # PII redaction (per cross-cutting 17)
    LICENSE_FILTER = "license_filter"
    CUSTOM = "custom"


@dataclass
class LineageNode:
    """One node in the lineage graph — a single transformation event."""

    id: str
    transformation: TransformationType
    parents: list[str]  # parent node ids
    detail: str  # human-readable description of the transform
    row_count_before: int | None = None
    row_count_after: int | None = None
    digest_before: str | None = None  # sha256 of the input snapshot
    digest_after: str | None = None  # sha256 of the output snapshot
    operator: str = "unknown"  # who/what performed the transform (SPIFFE ID, username, script)
    recorded_at: str = ""  # ISO 8601

    def to_dict(self) -> dict[str, Any]:
        return {
            "@id": f"aumos:dataset:{self.id}",
            "@type": f"aumos:{self.transformation.value}",
            "aumos:parents": [f"aumos:dataset:{p}" for p in self.parents],
            "aumos:detail": self.detail,
            "aumos:row_count_before": self.row_count_before,
            "aumos:row_count_after": self.row_count_after,
            "aumos:digest_before": self.digest_before,
            "aumos:digest_after": self.digest_after,
            "aumos:operator": self.operator,
            "aumos:recorded_at": self.recorded_at,
        }


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def snapshot_digest(rows: list[dict[str, Any]]) -> str:
    """Stable SHA-256 over a list of rows. Rows are sorted by JSON-canonical form before
    hashing, so row-order doesn't change the digest (dedup/concat-friendly)."""
    canon = json.dumps(sorted(rows, key=json.dumps), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


class Dataset:
    """A provenance-tracking dataset. Wraps a list of rows and records every transformation."""

    def __init__(self, rows: list[dict[str, Any]], source_node: LineageNode) -> None:
        self.rows: list[dict[str, Any]] = list(rows)
        self.nodes: list[LineageNode] = [source_node]
        self._current = source_node.id
        source_node.row_count_after = len(self.rows)
        source_node.digest_after = snapshot_digest(self.rows)

    @classmethod
    def from_source(
        cls,
        rows: list[dict[str, Any]],
        source_type: SourceType,
        source_uri: str,
        operator: str = "unknown",
    ) -> Dataset:
        """Construct a Dataset from an external source. Records the initial ``source`` node."""
        node = LineageNode(
            id=str(uuid.uuid4()),
            transformation=TransformationType.SOURCE,
            parents=[],
            detail=f"loaded from {source_type.value}:{source_uri}",
            row_count_before=0,
            operator=operator,
            recorded_at=_utcnow_iso(),
        )
        # Stash the source URI in the detail; full source metadata goes via from_dict.
        return cls(rows, node)

    def _record(
        self,
        transformation: TransformationType,
        detail: str,
        new_rows: list[dict[str, Any]],
        operator: str | None = None,
        extra_parents: list[str] | None = None,
    ) -> Dataset:
        before_digest = snapshot_digest(self.rows)
        before_count = len(self.rows)
        parents = [self._current, *(extra_parents or [])]
        node = LineageNode(
            id=str(uuid.uuid4()),
            transformation=transformation,
            parents=parents,
            detail=detail,
            row_count_before=before_count,
            row_count_after=len(new_rows),
            digest_before=before_digest,
            digest_after=snapshot_digest(new_rows),
            operator=operator or "unknown",
            recorded_at=_utcnow_iso(),
        )
        self.nodes.append(node)
        self.rows = new_rows
        self._current = node.id
        return self

    def filter(self, predicate: Callable[[dict[str, Any]], bool], detail: str = "") -> Dataset:
        """Filter rows by ``predicate``. Records a ``filter`` node."""
        kept = [r for r in self.rows if predicate(r)]
        return self._record(TransformationType.FILTER, detail or "filter", kept)

    def map(self, fn: Callable[[dict[str, Any]], dict[str, Any]], detail: str = "") -> Dataset:
        """Apply ``fn`` to every row. Records a ``map`` node."""
        mapped = [fn(r) for r in self.rows]
        return self._record(TransformationType.MAP, detail or "map", mapped)

    def dedup(self, detail: str = "") -> Dataset:
        """Deduplicate rows (by JSON-canonical form). Records a ``dedup`` node."""
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for r in self.rows:
            key = json.dumps(r, sort_keys=True, separators=(",", ":"))
            if key not in seen:
                seen.add(key)
                out.append(r)
        return self._record(TransformationType.DEDUP, detail or "dedup", out)

    def pii_redact(
        self, redactor: Callable[[dict[str, Any]], dict[str, Any]], detail: str = ""
    ) -> Dataset:
        """Apply a PII-redaction transform. Records a ``pii_redact`` node per cross-cutting 17."""
        out = [redactor(r) for r in self.rows]
        return self._record(TransformationType.PII_REDACT, detail or "pii_redact", out)

    def concat(self, other: Dataset, detail: str = "") -> Dataset:
        """Concatenate ``other`` onto the end of this dataset. Records a ``concat`` node with
        two parents (the current node of self and the current node of other)."""
        combined = [*self.rows, *other.rows]
        return self._record(
            TransformationType.CONCAT,
            detail or f"concat({len(other.rows)} rows)",
            combined,
            extra_parents=[other._current],
        )

    def custom(
        self,
        fn: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
        detail: str,
        operator: str | None = None,
    ) -> Dataset:
        """Apply an arbitrary transformation. Records a ``custom`` node with the supplied detail."""
        out = fn(self.rows)
        return self._record(TransformationType.CUSTOM, detail, out, operator=operator)

    @property
    def current_node_id(self) -> str:
        """The id of the most recent (current head) lineage node."""
        return self._current

    def to_jsonld(self) -> dict[str, Any]:
        """Export the full lineage graph as signed JSON-LD (signature added by T1 trust-core in
        production; this method produces the canonical JSON-LD that gets signed)."""
        return {
            "@context": {
                "aumos": "https://muveraai.com/vocab/dataset#",
                "@vocab": "https://muveraai.com/vocab/dataset#",
            },
            "@graph": [n.to_dict() for n in self.nodes],
            "aumos:final_row_count": len(self.rows),
            "aumos:final_digest": snapshot_digest(self.rows),
            "aumos:head_node": f"aumos:dataset:{self._current}",
        }


__all__ = [
    "Dataset",
    "LineageNode",
    "SourceType",
    "TransformationType",
    "snapshot_digest",
]
