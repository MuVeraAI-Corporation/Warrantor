"""``model-sbom`` CLI entrypoint.

Usage:
    model-sbom --name my-model --architecture transformer-decoder --parameters 7000000000 \\
        --training-data dataset://pile --license Apache-2.0 --format cyclonedx > sbom.json
"""

from __future__ import annotations

import argparse
import json
import sys

from model_sbom import Dependency, ModelInfo, SbomFormat, SbomInput, generate


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="model-sbom",
        description="Generate a Model SBOM (CycloneDX or SPDX with AI extensions).",
    )
    p.add_argument("--name", required=True, help="Model name.")
    p.add_argument(
        "--architecture", required=True, help="Model architecture (e.g. transformer-decoder)."
    )
    p.add_argument("--parameters", required=True, type=int, help="Total parameter count.")
    p.add_argument(
        "--training-data", action="append", default=[], help="Training dataset URI (repeatable)."
    )
    p.add_argument("--base-model", default=None, help="Parent model URI (for fine-tunes).")
    p.add_argument(
        "--evaluations", action="append", default=[], help="Evaluation reference (repeatable)."
    )
    p.add_argument("--license", default=None, help="SPDX license identifier.")
    p.add_argument("--digest", default=None, help="Content digest of the weights (sha256 hex).")
    p.add_argument("--supplier", default="did:web:warrantor.dev", help="Supplier identity.")
    p.add_argument(
        "--format",
        choices=[f.value for f in SbomFormat],
        default=SbomFormat.CYCLONEDX.value,
        help="SBOM format (default: cyclonedx).",
    )
    p.add_argument(
        "--dep",
        action="append",
        default=[],
        metavar="NAME@VERSION",
        help="Software dependency (repeatable; format NAME@VERSION).",
    )
    args = p.parse_args(argv)

    deps: list[Dependency] = []
    for d in args.dep:
        if "@" not in d:
            print(f"model-sbom: --dep must be NAME@VERSION, got {d!r}", file=sys.stderr)
            return 2
        name, version = d.rsplit("@", 1)
        deps.append(Dependency(name=name, version=version))

    info = ModelInfo(
        name=args.name,
        architecture=args.architecture,
        parameters=args.parameters,
        training_data=args.training_data,
        base_model=args.base_model,
        evaluations=args.evaluations,
        license=args.license,
        digest=args.digest,
    )
    sbom = generate(SbomInput(model=info, dependencies=deps, supplier=args.supplier), args.format)
    json.dump(sbom, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
