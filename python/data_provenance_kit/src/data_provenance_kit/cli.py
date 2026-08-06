"""``data-provenance`` CLI — export lineage as signed JSON-LD from a JSONL input."""

from __future__ import annotations

import argparse
import json
import sys

from data_provenance_kit import Dataset, SourceType, snapshot_digest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="data-provenance",
        description="Load a JSONL dataset, compute a snapshot digest, and emit a lineage JSON-LD node.",
    )
    p.add_argument("--input", required=True, help="Path to JSONL file (one JSON object per line).")
    p.add_argument("--source-type", choices=[s.value for s in SourceType], default=SourceType.LOCAL.value)
    p.add_argument("--source-uri", required=True, help="Source URI (e.g. hf_hub://dataset/c4).")
    p.add_argument("--operator", default="cli", help="Who/what loaded the dataset.")
    args = p.parse_args(argv)

    rows: list[dict] = []
    try:
        with open(args.input, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except OSError as e:
        print(f"data-provenance: read {args.input}: {e}", file=sys.stderr)
        return 2

    ds = Dataset.from_source(
        rows,
        SourceType(args.source_type),
        args.source_uri,
        operator=args.operator,
    )
    jsonld = ds.to_jsonld()
    # Add the high-level digest for easy SBOM/S4 reference.
    jsonld["aumos:initial_digest"] = snapshot_digest(rows)
    json.dump(jsonld, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
