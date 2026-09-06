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

# Which axes the layers share, and why each answer is what it is, for the configuration a shipped
# run is in: one policy engine, so the `policy_engine` axis is trivially shared. This is a MIRROR of
# `rust/warrant/src/egress.rs::independence(bounds, None)`, not a derivation from it: this gate runs
# without cargo, so it cannot call the Rust function.
#
# CORRECTION (second adversarial review). This comment used to say a Rust test named
# `the_gate_agrees_with_the_rust_answer` kept the two tables from drifting. No such test existed;
# the only cross-check compared axis NAMES (`axes_match_the_rust_constant`), so a flipped answer here
# that reached the record via --write produced a publishable record disagreeing with the Rust
# answer and nothing went red. The test exists now, in rust/warrant/tests/network_independence.rs:
# it reads evidence/network-independence.json and asserts every measured field against
# `independence()` for both configurations. A flip here that reaches the record fails the Rust
# suite; one that does not reach the record fails this gate's own record comparison.
#
# The record also used to carry ONE `shared_axes` list, which was the wired configuration's answer
# (six of eight) beside an engine count that was the product's (one). One list with a footnote is
# the shape the T7 correction removed from the engine count, so the axes are split the same way.
SHARED_THE_PRODUCT_RUNS = {
    "enforcement_point": True,
    "policy_engine": True,  # one evaluator in a shipped run, so nothing to be disjoint from
    "address_floor": True,  # both evaluators call hard_deny
    "configuration_source": True,  # one `egress_hosts` field, opposite senses
    "credential": False,  # neither holds a key: independent by absence
    "telemetry_path": True,  # both refusal maps live in one process
    "clock": True,  # one `expires_at`
    "dns_resolution": True,  # neither resolves: a shared blind spot
}

# The same table once a caller wires the second engine: the one axis that moves.
SHARED_ONCE_THE_SECOND_IS_WIRED = {
    **SHARED_THE_PRODUCT_RUNS,
    "policy_engine": False,  # two evaluators once egress-filter is wired
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

# The clauses a surface must carry beside the count, and the ones it must never carry.
#
# CORRECTION (adversarial review of Task 5.4). `note_accompanies_every_count` used to decide whether a
# surface published the count by testing `"independent" not in text`, case-sensitively. README.md's
# only occurrence is the capitalized row title "Independent network intercepts ..." and it contains no
# lowercase "independent" anywhere, so README.md -- the surface most likely to be read out of context
# -- was silently skipped and could publish the bare count with no bounding clause at all. The gate's
# own negative test used a lowercase synthetic fixture, so it passed while the real surface was
# exempt. The presence heuristic is gone: RENDER_TARGETS already names every file that publishes the
# count and `renders_agree` already proves the count is in each one, so the caveat is now required of
# all of them unconditionally.
#
# The accepted clause list also used to include the bare token "INDEPENDENCE_NOTE", which made the
# whole rule satisfiable by a four-word cross-reference anywhere in the file: "See
# `INDEPENDENCE_NOTE`" appended after a thousand lines passed with every real clause stripped. Both
# required clauses must now appear within CAVEAT_WINDOW lines of the rendered count.
REQUIRED_CAVEAT_CLAUSES = (
    # What the number IS. The old wording said the opposite; see REFUSED_CAVEAT_CLAUSES.
    "is a count of enforcement points",
    # What escapes it. A count with no escape clause reads as containment.
    "passes neither",
)

# Wording that must never accompany the intercept count again.
#
# `egress::INDEPENDENCE_NOTE` shipped "The count above is a count of policy domains, not a count of
# enforcement points", and this gate forced it onto all three surfaces. Every surface publishes
# `intercepts`, and `intercepts` IS the enforcement-point count -- so the mandated caveat mislabeled
# the published number in the UNSAFE direction, telling the reader that 1 did not bound enforcement
# points when the entire finding is that exactly one enforcement point exists. The record beside it
# said the opposite in capitals. Refused here as well as in the Rust suite, because a clause pinned by
# CI in three places is a clause that comes back.
REFUSED_CAVEAT_CLAUSES = (
    "count of policy domains, not a count of enforcement points",
    # The withdrawn remedy: `sandbox::profile` omits `--unshare-net` for any warrant that permits a
    # host, which is exactly the configuration this count is about, so the "unless" invited the reader
    # to believe a boundary was one command away.
    "unless you launched the confinement profile",
)

# How far from the rendered count a required clause may sit, in lines. The refused clauses are
# refused in the same window and nowhere else, deliberately: a document that records WHY a clause was
# withdrawn has to be able to quote it, and both published documents now do. What the clause may never
# do again is sit beside the count as its label, which is the only place it did harm.
CAVEAT_WINDOW = 12

# Line anchors published in the analysis document, and the source line each one must resolve to.
#
# CORRECTION. All four `rust/warrant/src/proxy.rs` citations in docs/05 were pre-change line numbers,
# stale by exactly the lines this branch inserted above them: 227-234 was cited for the egress loop
# and lands inside `deny_secondary`, a function that did not exist when the claim was written. Every
# non-proxy citation was correct, which is the tell -- proxy.rs is the one file the branch grew.
# Nothing caught it: PROBES match strings, RENDER_TARGETS match the count, and no check read a line
# anchor. So the anchors are derived here. Each entry is (doc, source, needle, cited_template): the
# gate finds the needle's real 1-based line in the source and requires the document to carry the
# template with `{line}` filled in.
CITATIONS = (
    (
        "docs/05-network-common-mode-analysis.md",
        "rust/warrant/src/proxy.rs",
        "for destination in crate::egress::destinations_of(call) {",
        "`rust/warrant/src/proxy.rs` lines\n{line}-",
    ),
    (
        "docs/05-network-common-mode-analysis.md",
        "rust/warrant/src/proxy.rs",
        "const NEVER_IN_OBSERVE: [SideEffectClass; 2] =",
        "`NEVER_IN_OBSERVE` (`rust/warrant/src/proxy.rs` lines {line}-",
    ),
    (
        "docs/05-network-common-mode-analysis.md",
        "rust/warrant/src/proxy.rs",
        "if self.bounds.staged_classes.contains(&call.side_effect)",
        "consulted *after* the egress loop (lines {line}-",
    ),
    (
        "docs/05-network-common-mode-analysis.md",
        "rust/warrant/src/proxy.rs",
        "requests: BTreeMap<(String, String), AuthorityRequest>,",
        "`Proxy::requests` (`rust/warrant/src/proxy.rs` lines {line}-",
    ),
    (
        "docs/05-network-common-mode-analysis.md",
        "rust/warrant/src/sandbox.rs",
        "anything. Egress stays Mediated, held by the MCP proxy. To make it enforced, put a \\",
        "`rust/warrant/src/sandbox.rs` line {line} already names this remedy",
    ),
    (
        "docs/05-network-common-mode-analysis.md",
        "rust/warrant/src/egress.rs",
        "if bounds.egress_hosts.is_empty() {",
        "(`rust/warrant/src/egress.rs` lines {line}-",
    ),
    (
        "docs/05-network-common-mode-analysis.md",
        "rust/warrant/src/egress.rs",
        "expires_at: bounds.expires_at",
        "(`rust/warrant/src/egress.rs` line {line})",
    ),
)

# The cluster layer L2-03 asks for, asserted rather than described.
#
# CORRECTION. docs/05 section 7 names "a cluster layer with egress policyTypes" as exit condition 2,
# and both docs/05 and W1 3.8 carried the prose facts "There is no `deploy/k8s` directory" and "There
# is exactly one `NetworkPolicy` in the tree" -- with NOTHING checking either. The finding test that
# is supposed to go red "the day a second enforcement point lands" cannot: its predicate is closed
# over the two in-process policy engines, so no kernel or cluster layer is an input to it. Adding a
# real cluster egress NetworkPolicy left the finding test green, the corpus at 85 passed, and this
# gate publishing 1.
#
# So the cluster half of the finding gets its own assertion, which CAN go red. A NetworkPolicy that
# declares egress policyTypes is exactly exit condition 2, and its arrival must fail this build.
CLUSTER_POLICY_KIND = "kind: NetworkPolicy"
KNOWN_NETWORK_POLICIES = ("deploy/spire/trust-domain-config.yaml",)


@dataclass(frozen=True)
class Independence:
    """One measurement of the egress path."""

    independent_intercepts_on_a_permitted_host: int
    policy_engines_the_product_runs: int
    policy_engines_when_an_operator_wires_one: int
    configuration_sources_the_product_runs: list[str]
    axes: list[str]
    shared_axes_the_product_runs: list[str]
    shared_axes_once_the_second_is_wired: list[str]
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


def product_sources() -> list[Path]:
    """Every Rust file that ships in a crate, excluding integration tests.

    `rust/*/tests/**` holds the integration suites and is deliberately outside this: the question
    these answer is what the *product* does, and a test wiring something proves only that the wiring
    compiles.
    """

    return sorted((REPOSITORY_ROOT / "rust").glob("*/src/**/*.rs"))


def engines_the_product_runs() -> int:
    """How many policy engines decide a permitted destination in a shipped run.

    CORRECTION, and the reason this is derived rather than assigned. `measure` used to hardcode
    `engines = 2` and justify it as "both `policy_engine` probes passed, so the dependency edge
    exists AND the call site consults it". The call site consults the second engine only when
    `self.secondary.is_some()`, and **nothing in the product ever makes that true**: `Proxy::new`
    sets `secondary: None`, `Proxy::with_secondary_filter` has exactly one caller and it is a test,
    `SecondaryFilter::from_operator_config` has no caller at all, and `warrantor.rs` contains zero
    occurrences of `SecondaryFilter`. So the record published 2 and README published "Two policy
    engines decide a permitted destination" while every run of the shipped binary decided with one.
    The evidence file disclosed it; the two gated surfaces did not. The gate that exists to stop
    prose/code drift passed on the drifted claim.

    Derived now, from the product sources alone. The day one of them wires the engine this returns 2,
    the recorded 1 no longer matches, and whoever landed it must move the number and the prose in the
    same commit -- which is the whole point of a ratchet.
    """

    for path in product_sources():
        if ".with_secondary_filter(" in path.read_text(encoding="utf-8"):
            return 2
    return 1


def engine_words(count: int) -> str:
    """`engine decides` or `engines decide`, so a published sentence reads as one.

    Rule 2 in miniature: the number and the words around it come from the same value, rather than a
    `engine(s)` hedge that is wrong for both readings.
    """

    return "engine decides" if count == 1 else "engines decide"


def measure() -> Independence:
    """The current answer, derived from the probes above.

    `intercepts` is 1 rather than 2 because the netns branch and the catalogue branch are the SAME
    condition on the SAME field read with opposite senses: whenever a destination is permitted, only
    the proxy stands. That is not an assumption -- it is the pair of `configuration_source` probes.
    """

    running = engines_the_product_runs()
    # The engine count an operator CAN reach is 2, and that half really is derived from the probes:
    # reaching here means the dependency edge exists and the call site consults the filter when one
    # is present. What the probes never established is whether anything sets one, which is why the
    # two numbers are separate fields rather than one number with a footnote.
    return Independence(
        independent_intercepts_on_a_permitted_host=1,
        policy_engines_the_product_runs=running,
        policy_engines_when_an_operator_wires_one=2,
        # Mirrors `egress::Independence::configuration_sources` for the configuration the product
        # actually runs. The broker reads the signed warrant claims; a second source appears here
        # only once a product source wires the second engine.
        configuration_sources_the_product_runs=(
            ["warrant_claims"] if running == 1 else ["warrant_claims", "operator_file"]
        ),
        axes=list(AXES),
        shared_axes_the_product_runs=[axis for axis in AXES if SHARED_THE_PRODUCT_RUNS[axis]],
        shared_axes_once_the_second_is_wired=[
            axis for axis in AXES if SHARED_ONCE_THE_SECOND_IS_WIRED[axis]
        ],
        layers_on_a_permitted_host=["mcp_proxy"],
        layers_on_an_empty_bound=["mcp_proxy", "network_namespace"],
    )


def citations_resolve() -> list[str]:
    """Every line anchor in the analysis document, against the line it actually points at.

    A stale anchor sends a reader to the wrong code while every number on the page is right, which is
    the [[verify attribution, not just numbers]] failure. The line is found in the source and the
    document is required to cite it, so an anchor cannot rot without failing the build.
    """

    wrong = []
    for document, source, needle, template in CITATIONS:
        lines = read(source).splitlines()
        found = [index + 1 for index, line in enumerate(lines) if needle in line]
        if not found:
            wrong.append(
                f"{source}: {needle!r} is gone, so the anchor in {document} cannot be checked. "
                "Re-read the source and re-derive the citation."
            )
            continue
        if len(found) > 1:
            wrong.append(
                f"{source}: {needle!r} appears on lines {found}; a citation anchor must be unique. "
                "Narrow the needle in CITATIONS."
            )
            continue
        expected = template.format(line=found[0])
        if expected not in read(document):
            wrong.append(
                f"{document}: does not cite {source} line {found[0]} for {needle!r} "
                f"(expected {expected!r}). The code moved; re-derive the line number rather than "
                "leaving a reader to land somewhere else."
            )
    return wrong


def cluster_layer_absent() -> list[str]:
    """The cluster layer L2-03 asks for, asserted rather than described.

    docs/05 section 7 names a cluster egress policy as exit condition 2 and both published documents
    stated as fact that no such thing exists. Nothing checked it, and the finding test cannot: its
    predicate is closed over the two in-process policy engines, so no cluster or kernel layer is an
    input to it. This is the assertion that CAN go red.
    """

    wrong = []
    policies = []
    for pattern in ("*.yaml", "*.yml"):
        for path in sorted((REPOSITORY_ROOT).rglob(pattern)):
            if ".git" in path.parts or "target" in path.parts:
                continue
            if CLUSTER_POLICY_KIND in path.read_text(encoding="utf-8", errors="replace"):
                policies.append(path.relative_to(REPOSITORY_ROOT).as_posix())

    unexpected = [policy for policy in policies if policy not in KNOWN_NETWORK_POLICIES]
    if unexpected:
        wrong.append(
            f"a NetworkPolicy this analysis does not know about exists: {unexpected}. That is "
            "exit condition 2 of docs/05 section 7 -- a cluster layer. If it declares egress "
            "policyTypes it may be a second enforcement point, and the count, the record, "
            "docs/05, docs/W1-delivery-gaps.md 3.8 and the I-09 finding test all have to be "
            "re-derived rather than left publishing 1."
        )
    for known in KNOWN_NETWORK_POLICIES:
        if known not in policies:
            wrong.append(
                f"{known}: the one NetworkPolicy the analysis names is gone, so 'exactly one "
                "NetworkPolicy in the tree' is no longer the fact docs/05 states."
            )
    return wrong


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
    """A surface may print the count only alongside what the count excludes, and near it.

    Three things this used to get wrong, all of them demonstrated by command in the adversarial
    review and all of them fixed here:

    1. It decided whether a surface published the count by testing ``"independent" not in text``,
       case-sensitively. README.md's only occurrence is capitalized, so README.md was skipped
       entirely and could publish the bare count. The heuristic is gone: every RENDER_TARGET
       publishes the count by construction -- ``renders_agree`` proves it -- so every one of them
       carries the caveat, unconditionally.
    2. It accepted the bare token ``INDEPENDENCE_NOTE``, so a four-word cross-reference anywhere in
       the file satisfied the whole rule. Both required clauses must now appear, and within
       ``CAVEAT_WINDOW`` lines of the rendered count rather than anywhere in the file.
    3. The clause it required was FALSE about the number it accompanied. See
       ``REFUSED_CAVEAT_CLAUSES``, which now fails the build on that wording.
    """

    intercepts = record["independent_intercepts_on_a_permitted_host"]
    words = {1: "one", 2: "two", 3: "three"}
    wrong = []
    for relative, template in RENDER_TARGETS:
        text = read(relative)

        # Locate the rendered count, so the caveat is required beside it rather than in the file.
        rendered = template.format(
            intercepts=intercepts, two_words=words.get(intercepts + 1, str(intercepts + 1))
        )
        # Locate the WHOLE rendered string by character offset, then convert to a line. Matching on
        # its first line alone is not enough: `docs/05`'s template begins with the bare word
        # "independent", whose first occurrence in that file is 190 lines above the count.
        offset = text.find(rendered)
        if offset < 0:
            # `renders_agree` reports this; nothing to say twice.
            continue
        lines = text.splitlines()
        at = text.count("\n", 0, offset)
        window = flowed(
            "\n".join(lines[max(0, at - CAVEAT_WINDOW) : min(len(lines), at + CAVEAT_WINDOW + 1)])
        )
        for required in REQUIRED_CAVEAT_CLAUSES:
            if required not in window:
                wrong.append(
                    f"{relative}: publishes the independence count on line {at + 1} without "
                    f"{required!r} within {CAVEAT_WINDOW} lines of it. Add the clause from "
                    "egress::INDEPENDENCE_NOTE beside the count -- a bounding sentence a reader "
                    "has to go looking for does not bound anything."
                )
        for refused in REFUSED_CAVEAT_CLAUSES:
            if refused in window:
                wrong.append(
                    f"{relative}: labels the count on line {at + 1} with the withdrawn clause "
                    f"{refused!r}. Every surface here publishes the INTERCEPT count, which is the "
                    "enforcement-point count, so that wording mislabels the published number in "
                    "the unsafe direction. See egress::INDEPENDENCE_NOTE. Quoting it to record why "
                    f"it was withdrawn is fine, more than {CAVEAT_WINDOW} lines from the count."
                )
    return wrong


# Where the analysis document quotes the constant as a paragraph, and the file the constant lives in.
ANALYSIS_DOCUMENT = "docs/05-network-common-mode-analysis.md"
NOTE_SOURCE = "rust/warrant/src/egress.rs"
NOTE_MARKER = "pub const INDEPENDENCE_NOTE: &str ="


def independence_note_from_the_rust_source() -> str:
    """The value of `egress::INDEPENDENCE_NOTE`, read out of the Rust source.

    The constant is one string literal split over lines with `\\` continuations, which elide the
    newline and the next line's leading whitespace. Joining them the way rustc does gives the value
    the binary carries, so the Markdown copy can be required to be THAT rather than a paraphrase.
    """

    source = read(NOTE_SOURCE)
    if NOTE_MARKER not in source:
        raise ValueError(f"{NOTE_SOURCE}: {NOTE_MARKER!r} is gone; the note cannot be read")
    literal = source.split(NOTE_MARKER, 1)[1].split('";', 1)[0]
    pieces = []
    for line in literal.splitlines():
        stripped = line.strip()
        if stripped.startswith('"'):
            stripped = stripped[1:]
        if stripped.endswith("\\"):
            stripped = stripped[:-1]
        pieces.append(stripped)
    return "".join(pieces)


def analysis_paragraph_is_the_constant() -> list[str]:
    """`docs/05`'s "What the count excludes" paragraph must be `INDEPENDENCE_NOTE`, verbatim.

    CORRECTION (second adversarial review). The document says "This paragraph is
    `egress::INDEPENDENCE_NOTE`", and it was not: the constant was corrected and the paragraph
    drifted, so the analysis went on saying "Two policy engines decide at that one point" about a
    product that ships one. A sentence written beside a record is what this repository's Rule 2
    forbids; the paragraph is now required to be the constant's own value, read from the Rust
    source, compared flowed and with Markdown code spans removed.
    """

    expected = flowed(independence_note_from_the_rust_source())
    actual = flowed(read(ANALYSIS_DOCUMENT)).replace("`", "")
    if expected not in actual:
        return [
            f"{ANALYSIS_DOCUMENT}: the paragraph it calls egress::INDEPENDENCE_NOTE is not the "
            f"constant's value. Expected, verbatim from {NOTE_SOURCE}: {expected!r}. A paragraph "
            "that drifts from the constant is a sentence written beside the record instead of "
            "derived from it."
        ]
    return []


def flowed(text: str) -> str:
    """One line, single-spaced, with Markdown line furniture removed.

    Prose wraps, and a clause split across a line break is the same clause. Both checks above ran on
    the raw text until a correction paragraph in `docs/05-network-common-mode-analysis.md` quoted the
    withdrawn wording verbatim and the refusal did not fire -- the quote had wrapped mid-clause. That
    is evasion by accident, and the same accident would hide a required clause (it did: W1's new
    caveat wrapped between "a" and "count of enforcement points"). Blockquote markers and list
    bullets go too, so a clause inside a `>` block reads the same as one outside it.
    """

    stripped = "\n".join(
        line.lstrip().lstrip(">").lstrip().lstrip("-*").lstrip() for line in text.splitlines()
    )
    return " ".join(stripped.split())


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
            "permits, not of policy engines. "
            f"{measurement.policy_engines_the_product_runs} policy "
            f"{engine_words(measurement.policy_engines_the_product_runs)} in a shipped run and "
            f"{measurement.policy_engines_when_an_operator_wires_one} "
            f"{engine_words(measurement.policy_engines_when_an_operator_wires_one)} once an "
            "operator wires the second; either way one boundary enforces. "
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

    problems = (
        failed_probes() + axes_match_the_rust_constant() + citations_resolve() + cluster_layer_absent()
    )
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
        f"{len(measurement.shared_axes_the_product_runs)} shared axes of "
        f"{len(measurement.axes)} in the product, "
        f"{len(measurement.shared_axes_once_the_second_is_wired)} once the second engine is wired; "
        f"{measurement.policy_engines_the_product_runs} policy "
        f"{engine_words(measurement.policy_engines_the_product_runs)} in the product, "
        f"{measurement.policy_engines_when_an_operator_wires_one} once an operator wires the second"
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
    mismatches += analysis_paragraph_is_the_constant()

    if mismatches:
        for mismatch in mismatches:
            print(f"::error::network independence: {mismatch}")
        return 1

    print("network independence: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
