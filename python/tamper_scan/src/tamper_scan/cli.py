"""``tamper-scan`` CLI — scan a JSON file of tensors for tampering."""

from __future__ import annotations

import argparse
import json
import sys

from tamper_scan import scan


def _load_tensors(path: str) -> dict[str, list[float]]:
    """Load a JSON file mapping tensor_name → flat list of float weights."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object of tensor_name → weights[]")
    return {k: [float(w) for w in v] for k, v in data.items()}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="tamper-scan",
        description="Scan model tensors for tampering (weight/backdoor/pruning/fine-tune).",
    )
    p.add_argument("--subject", required=True, help="JSON file of subject tensors.")
    p.add_argument("--baseline", default=None, help="JSON file of trusted baseline tensors (optional).")
    args = p.parse_args(argv)

    try:
        subject = _load_tensors(args.subject)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"tamper-scan: load subject: {e}", file=sys.stderr)
        return 2

    baseline: dict[str, list[float]] | None = None
    if args.baseline:
        try:
            baseline = _load_tensors(args.baseline)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"tamper-scan: load baseline: {e}", file=sys.stderr)
            return 2

    report = scan(baseline, subject)
    json.dump(report.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    # Exit non-zero if any HIGH/CRITICAL findings.
    return 1 if report.critical_or_high else 0


if __name__ == "__main__":
    sys.exit(main())
