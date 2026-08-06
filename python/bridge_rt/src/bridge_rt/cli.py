"""``bridge-rt`` CLI — probe backend availability and run a one-shot generate."""

from __future__ import annotations

import argparse
import json
import sys

from bridge_rt import Backend, Bridge, GenerateRequest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bridge-rt", description="Unified inference backend abstraction.")
    sub = p.add_subparsers(dest="cmd", required=True)

    probe = sub.add_parser("probe", help="List backends and their availability.")
    probe.add_argument("--json", action="store_true", help="Emit JSON.")

    gen = sub.add_parser("generate", help="Run a one-shot generate against the best backend.")
    gen.add_argument("--model", required=True)
    gen.add_argument("--prompt", required=True)
    gen.add_argument("--max-tokens", type=int, default=128)
    gen.add_argument("--force", choices=[b.value for b in Backend], default=None)

    args = p.parse_args(argv)
    bridge = Bridge()
    if getattr(args, "force", None):
        bridge.force(Backend(args.force))

    if args.cmd == "probe":
        rows = []
        for candidate in [Backend.TENSORRT_LLM, Backend.VLLM, Backend.OLLAMA, Backend.MOCK]:
            impl = bridge.registry.get(candidate)
            if impl is None:
                continue
            avail = impl.is_available()
            ver = impl.version() if avail else ""
            rows.append({"backend": candidate.value, "available": avail, "version": ver})
        if args.json:
            json.dump(rows, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            print(f"{'backend':<15} {'available':<10} version")
            for r in rows:
                print(f"{r['backend']:<15} {str(r['available']):<10} {r['version']}")
        return 0

    if args.cmd == "generate":
        try:
            resp = bridge.generate(GenerateRequest(model=args.model, prompt=args.prompt, max_tokens=args.max_tokens))
        except RuntimeError as e:
            print(f"bridge-rt: {e}", file=sys.stderr)
            return 1
        json.dump({
            "text": resp.text,
            "backend": resp.backend.value,
            "backend_version": resp.backend_version,
            "sampler_type_adapted": resp.sampler_type_adapted,
        }, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
