#!/usr/bin/env python3
"""Derive the egress path's common-mode independence from the sources, and gate every rendered copy.

The number this measures is the one L2-03 asks for: how many *independent* controls stand between a
supervised agent and a destination its warrant permits. The answer on this tree is one, and the
value of computing it here rather than asserting it in prose is that the computation reads the two
conditions that produce it. The day either condition changes, this script's answer changes with it
and every document that published the old answer fails the build.

It measures from the sources alone — no cargo, no network — for the same reason
`tools/ci/wiring_census.py` does: a gate that needs a toolchain is a gate that gets skipped.

Usage:
    python tools/ci/network_independence.py            # gate: exit 1 on any disagreement
    python tools/ci/network_independence.py --write     # record the current measurement
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RECORD_PATH = REPOSITORY_ROOT / "evidence" / "network-independence.json"
RECORD_FORMAT = "warrantor.network-independence/1"

# The axes, in the order `rust/warrant/src/egress.rs::INDEPENDENCE_AXES` lists them. Kept in step by
# `axes_match_the_rust_constant` below rather than by anybody remembering.
AXES = (
    "enforcement_point",
    "policy_engine",
    "address_floor",
    "configuration_source",
    "credential",
    "telemetry_path",
    "clock",
    "dns_resolution",
)

# Every probe is (axis, path, needle, why). A probe that stops finding its needle means the mechanism
# behind the axis moved, and the whole record is then unsafe to publish -- so a missing needle is a
# hard failure and never a silently different answer.
#
# These are the load-bearing facts. Each one is a sentence in
# `docs/05-network-common-mode-analysis.md` that would otherwise be prose nobody checks.
PROBES = (
    (
        "configuration_source",
        "rust/warrant/src/sandbox.rs",
        "if bounds.egress_hosts.is_empty() {",
        "the netns is emitted only for an EMPTY egress bound; this is half of the anti-correlation",
    ),
    (
        "configuration_source",
        "rust/warrant/src/egress.rs",
        "if bounds.egress_hosts.is_empty() {",
        "the broker's catalogue is absent for an empty bound; this is the other half",
    ),
    (
        "enforcement_point",
        "rust/warrant/src/sandbox.rs",
        '--unshare-net".to_string()',
        "the only netns in the repository, and it lives inside the empty-bound branch",
    ),
    (
        "address_floor",
        "rust/egress/src/lib.rs",
        "use warrantor_egress_filter::hard_deny",
        "the broker delegates its address floor to egress-filter (Task 7.1)",
    ),
    (
        "address_floor",
        "rust/egress-filter/src/lib.rs",
        "hard_deny::refuse_ip(norm)",
        "and Policy consults the SAME floor, which is why address_floor is shared",
    ),
    (
        "telemetry_path",
        "rust/warrant/src/proxy.rs",
        "secondary_refusals: BTreeMap<(String, String), crate::egress::SecondaryRefusal>",
        "the second engine's refusals are a second map in the SAME process, not a second sink",
    ),
    (
        "clock",
        "rust/warrant/src/egress.rs",
        "expires_at: bounds.expires_at",
        "one warrant deadline is copied into every catalogue entry",
    ),
    (
        "dns_resolution",
        "rust/warrant/src/egress.rs",
        "It does **not** resolve DNS",
        "neither layer resolves, so a name that resolves into a metadata range is not caught",
    ),
    (
        "policy_engine",
        "rust/warrant/Cargo.toml",
        "warrantor-egress-filter = { path = \"../egress-filter\"",
        "the second evaluator is reachable from the product at all",
    ),
    (
        "policy_engine",
        "rust/warrant/src/proxy.rs",
        "if let Some(secondary) = self.secondary.as_ref() {",
        "and it is consulted at the chokepoint, inside the existing destination loop",
    ),
)

# Which axes the layers share, and why each answer is what it is. This mirrors
# `rust/warrant/src/egress.rs::independence`; `the_gate_agrees_with_the_rust_answer` in the Rust
# suite is what keeps the two from drifting.
SHARED = {
    "enforcement_point": True,
    "policy_engine": False,  # two evaluators once egress-filter is wired
    "address_floor": True,  # both evaluators call hard_deny
    "configuration_source": True,  # one `egress_hosts` field, opposite senses
    "credential": False,  # neither holds a key: independent by absence
    "telemetry_path": True,  # both refusal maps live in one process
    "clock": True,  # one `expires_at`
    "dns_resolution": True,  # neither resolves: a shared blind spot
}

# Where the count is published, and the exact string each file must carry. Copied in shape from
# `wiring_census.readme_renders`, which has already refused a merge in this program over a stale
# README row.
RENDER_TARGETS = (
    (
        "docs/05-network-common-mode-analysis.md",
        "independent\nintercepts on a permitted host is therefore **{intercepts}**",
    ),
    (
        "README.md",
        "| Independent network intercepts on a permitted destination | **{intercepts}**",
    ),
    (
        "docs/W1-delivery-gaps.md",
        "one independent intercept, not {two_words}",
    ),
)


@dataclass(frozen=True)
class Independence:
    """One measurement of the egress path."""

    independent_intercepts_on_a_permitted_host: int
    policy_engines_on_a_permitted_host: int
    axes: list[str]
    shared_axes: list[str]
    layers_on_a_permitted_host: list[str]
    layers_on_an_empty_bound: list[str]


def read(relative: str) -> str:
    """A repository file, or a fatal error naming it."""

    path = REPOSITORY_ROOT / relative
    if not path.is_file():
        raise FileNotFoundError(f"{relative}: the record is derived from this file and it is absent")
    return path.read_text(encoding="utf-8")


def failed_probes() -> list[str]:
    """Every probe whose needle is no longer in the file it names."""

    missing = []
    for axis, relative, needle, why in PROBES:
        if needle not in read(relative):
            missing.append(f"{relative}: {needle!r} is gone ({axis}: {why})")
    return missing


def measure() -> Independence:
    """The current answer, derived from the probes above.

    `intercepts` is 1 rather than 2 because the netns branch and the catalogue branch are the SAME
    condition on the SAME field read with opposite senses: whenever a destination is permitted, only
    the proxy stands. That is not an assumption -- it is the pair of `configuration_source` probes.
    """

    # Two engines, and this is not a constant: reaching here means both `policy_engine` probes
    # passed, so the dependency edge exists AND the call site consults it. If either is removed,
    # `failed_probes` fails the run before this line and no number is published at all.
    engines = 2
    return Independence(
        independent_intercepts_on_a_permitted_host=1,
        policy_engines_on_a_permitted_host=engines,
        axes=list(AXES),
        shared_axes=[axis for axis in AXES if SHARED[axis]],
        layers_on_a_permitted_host=["mcp_proxy"],
        layers_on_an_empty_bound=["mcp_proxy", "network_namespace"],
    )


def axes_match_the_rust_constant() -> list[str]:
    """The Python axis list against `INDEPENDENCE_AXES` in the Rust source.

    Two lists of axis names in two languages is exactly the shape of a drift defect, so the Rust
    constant is the one that ships and this asserts against it rather than beside it.
    """

    source = read("rust/warrant/src/egress.rs")
    marker = "pub const INDEPENDENCE_AXES: [&str; "
    if marker not in source:
        return [f"rust/warrant/src/egress.rs: {marker!r} is gone; the axis list cannot be checked"]
    declared = source.split(marker, 1)[1]
    count = int(declared.split("]", 1)[0])
    body = declared.split("[", 1)[1].split("];", 1)[0]
    rust_axes = tuple(part.strip().strip('"') for part in body.split(",") if part.strip())
    problems = []
    if count != len(AXES):
        problems.append(
            f"rust/warrant/src/egress.rs declares {count} axes and this gate models {len(AXES)}"
        )
    if rust_axes != AXES:
        problems.append(
            f"the axis lists disagree: rust={rust_axes!r} python={AXES!r}. "
            "The Rust constant is the one that ships; make this gate follow it."
        )
    return problems


def renders_agree(record: dict) -> list[str]:
    """Every file that publishes the count must publish the recorded one."""

    wrong = []
    intercepts = record["independent_intercepts_on_a_permitted_host"]
    words = {1: "one", 2: "two", 3: "three"}
    for relative, template in RENDER_TARGETS:
        expected = template.format(
            intercepts=intercepts,
            two_words=words.get(intercepts + 1, str(intercepts + 1)),
        )
        if expected not in read(relative):
            wrong.append(f"{relative}: does not contain {expected!r}")
    return wrong


def note_accompanies_every_count(record: dict) -> list[str]:
    """A surface may print the count only alongside what the count excludes.

    The single most damaging misreading this repository can ship is a count of policy domains read
    as a count of enforcement points, so the clause that refuses that reading is required wherever
    the count appears.
    """

    del record  # the rule does not depend on the value, only on the count being present
    wrong = []
    for relative, _ in RENDER_TARGETS:
        text = read(relative)
        if "independent" not in text:
            continue
        if (
            "not a count of enforcement points" not in text
            and "INDEPENDENCE_NOTE" not in text
            and "count of policy domains, not a count of enforcement points" not in text
        ):
            wrong.append(
                f"{relative}: publishes the independence count without the clause that bounds it. "
                "Add the sentence from egress::INDEPENDENCE_NOTE, or the count reads as an "
                "enforcement count."
            )
    return wrong


def load_record(path: Path) -> dict:
    """The recorded measurement, refusing any record in an unknown format."""

    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("format") != RECORD_FORMAT:
        raise ValueError(f"{path}: format {record.get('format')!r} is not {RECORD_FORMAT}")
    return record


def write_record(path: Path, measurement: Independence) -> None:
    """Record the measurement, with the caveat inside the record."""

    payload = {
        "format": RECORD_FORMAT,
        "anchor": "L2-03 / L0-10",
        "status": "none",
        "note": (
            "The count is a count of ENFORCEMENT POINTS acting on a destination the warrant "
            "permits, not of policy engines: two engines decide and one boundary enforces. "
            "L2-03 stays status=none until a second enforcement point acts on a permitted host. "
            "See docs/05-network-common-mode-analysis.md."
        ),
        **asdict(measurement),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, default=RECORD_PATH)
    parser.add_argument("--write", action="store_true", help="rewrite the record")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Measure, then either record or gate."""

    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)

    problems = failed_probes() + axes_match_the_rust_constant()
    if problems:
        for problem in problems:
            print(f"::error::network independence: {problem}")
        print(
            "network independence: the mechanisms this record is derived from have moved. "
            "Re-read the sources and docs/05-network-common-mode-analysis.md before recording "
            "anything: a number whose derivation is stale is worse than no number."
        )
        return 1

    measurement = measure()
    print(
        f"network independence: {measurement.independent_intercepts_on_a_permitted_host} "
        f"independent intercept on a permitted destination; "
        f"{len(measurement.shared_axes)} shared axes of {len(measurement.axes)}; "
        f"{measurement.policy_engines_on_a_permitted_host} policy engines"
    )

    if arguments.write:
        write_record(arguments.record, measurement)
        print(f"network independence: recorded in {arguments.record}")
        return 0

    if not arguments.record.is_file():
        print(f"::error::{arguments.record} is absent; run with --write")
        return 1

    record = load_record(arguments.record)
    mismatches = []
    for field, value in asdict(measurement).items():
        if record.get(field) != value:
            mismatches.append(f"{field}: recorded {record.get(field)!r}, measured {value!r}")
    mismatches += renders_agree(record)
    mismatches += note_accompanies_every_count(record)

    if mismatches:
        for mismatch in mismatches:
            print(f"::error::network independence: {mismatch}")
        return 1

    print("network independence: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
