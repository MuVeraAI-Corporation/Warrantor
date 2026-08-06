"""``safe-eval`` CLI — run a YAML pipeline against a target."""

from __future__ import annotations

import argparse
import json
import sys

from safe_eval import parse_pipeline_yaml, run_pipeline, to_veb


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="safe-eval", description="Run a YAML eval pipeline against a target.")
    p.add_argument("--pipeline", required=True, help="Path to a YAML pipeline file.")
    p.add_argument("--veb", action="store_true", help="Emit a Verifiable Evaluation Bundle (P8 VEB).")
    args = p.parse_args(argv)

    try:
        with open(args.pipeline, encoding="utf-8") as f:
            yaml_text = f.read()
    except OSError as e:
        print(f"safe-eval: read pipeline: {e}", file=sys.stderr)
        return 2

    try:
        spec = parse_pipeline_yaml(yaml_text)
    except (ValueError, RuntimeError) as e:
        print(f"safe-eval: parse pipeline: {e}", file=sys.stderr)
        return 2

    result = run_pipeline(spec)
    out = to_veb(result) if args.veb else result.to_dict()
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
