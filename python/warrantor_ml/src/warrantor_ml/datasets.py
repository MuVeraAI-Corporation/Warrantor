"""Declarative dataset registry for guard-model training and evaluation.

Every corpus this pipeline may touch is declared here as immutable data: repository id,
licence, the terms actually clicked through to obtain it, gating, splits, and the local cache
path. Nothing in this module performs I/O at import time -- importing it is free, offline, and
side-effect-free. Downloads happen only inside :func:`ensure_available`, and only when called.

That is not a stylistic preference. Both primary corpora are gated behind Hugging Face
click-through terms, so an import-time fetch would turn ``import warrantor_ml.datasets`` into a
network call that fails with HTTP 401 on any machine without credentials -- including CI.

The licence fields are load-bearing. ``model_sbom.ModelInfo.training_data`` is a bare
``list[str]`` with no licence slot, so per-dataset licensing has nowhere to live in the SBOM.
It lives here, and :mod:`warrantor_ml.model_card` copies it into the AIBOM as a required field.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Literal

__all__ = [
    "REGISTRY",
    "DatasetAccessError",
    "DatasetSpec",
    "PreflightReport",
    "SplitSpec",
    "UnknownDatasetError",
    "cache_root",
    "dataset_paths",
    "ensure_available",
    "get_dataset",
    "list_datasets",
    "main",
    "preflight",
]

CacheEnvVar = "WARRANTOR_ML_CACHE"
TokenEnvVars = ("HF_TOKEN", "HUGGINGFACE_HUB_TOKEN", "HUGGING_FACE_HUB_TOKEN")

GateKind = Literal["none", "auto", "manual"]
CommercialUse = Literal["permitted", "restricted-by-click-through", "prohibited", "unverified"]


class UnknownDatasetError(KeyError):
    """Raised when a dataset id is not in the registry."""


class DatasetAccessError(RuntimeError):
    """Raised when a gated dataset cannot be fetched, with the exact manual unblock steps."""


@dataclass(frozen=True)
class SplitSpec:
    """One split of a dataset as published on the Hub."""

    name: str
    remote_path: str
    rows: int
    approx_bytes: int


@dataclass(frozen=True)
class DatasetSpec:
    """Everything known about a corpus before a single byte is downloaded.

    ``commercial_use`` is deliberately separate from ``licence``. ExpGuardMix is CC-BY-4.0,
    which permits commercial use, but the gate form you must accept to obtain the file says
    "solely for research purposes". The click-through is the agreement that was actually
    signed, and it is narrower than the licence. Recording only the SPDX identifier would hide
    exactly the constraint that matters.
    """

    dataset_id: str
    title: str
    purpose: str
    licence: str
    licence_url: str
    gated: bool
    gate_kind: GateKind
    redistributable: bool
    commercial_use: CommercialUse
    terms_note: str
    terms_read_on: date
    total_rows: int
    splits: tuple[SplitSpec, ...]
    homepage: str
    citation: str
    revision: str = "main"
    attribution_required: bool = True
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def requires_credentials(self) -> bool:
        """Whether a Hugging Face read token is needed to fetch this corpus."""

        return self.gated

    def split(self, name: str) -> SplitSpec:
        """Look up one split by name."""

        for candidate in self.splits:
            if candidate.name == name:
                return candidate
        available = ", ".join(item.name for item in self.splits)
        raise UnknownDatasetError(f"{self.dataset_id}: no split {name!r} (have: {available})")


# ---------------------------------------------------------------------------
# The registry itself. Figures verified against the Hub, not recalled.
# ---------------------------------------------------------------------------

_WILDGUARDMIX = DatasetSpec(
    dataset_id="wildguardmix",
    title="WildGuardMix",
    purpose="general-safety",
    licence="ODC-By-1.0",
    licence_url="https://opendatacommons.org/licenses/by/1-0/",
    gated=True,
    gate_kind="auto",
    redistributable=False,
    commercial_use="restricted-by-click-through",
    terms_note=(
        "ODC-By governs the DATABASE, not the underlying content, and is not a code licence. "
        "Access additionally requires accepting AI2's responsible-use terms on the Hub gate "
        "form. Attribution to AI2 is mandatory in any derived artifact."
    ),
    terms_read_on=date(2026, 8, 12),
    total_rows=88_484,
    splits=(
        SplitSpec("train", "train/wildguard_train.parquet", 86_759, 53_740_000),
        SplitSpec("test", "test/wildguard_test.parquet", 1_725, 2_260_000),
    ),
    homepage="https://huggingface.co/datasets/allenai/wildguardmix",
    citation="Han et al., WildGuard: Open One-Stop Moderation Tools for Safety Risks, "
    "Jailbreaks, and Refusals of LLMs (2024).",
    notes=(
        "Row count is 88,484 total (86,759 train + 1,725 test), NOT the 92K figure that "
        "circulated in early planning. The Hub size_categories tag (10K<n<100K) corroborates "
        "~88K. Do not let 92K reach a public claim or a licence document.",
        "Composition: 87% synthetic, 11% in-the-wild user-LLM interactions, 2% "
        "annotator-written. 13 risk categories.",
        "Gate is auto-approved on submit -- no human reviewer -- but still requires a "
        "logged-in account, an accepted form, and a read token on the machine.",
    ),
)

_EXPGUARDMIX = DatasetSpec(
    dataset_id="expguardmix",
    title="ExpGuardMix",
    purpose="domain-specialised (finance / healthcare / law)",
    licence="CC-BY-4.0",
    licence_url="https://creativecommons.org/licenses/by/4.0/",
    gated=True,
    gate_kind="auto",
    redistributable=True,
    commercial_use="restricted-by-click-through",
    terms_note=(
        "LEGAL CONFLICT, UNRESOLVED. The licence is CC-BY-4.0 and permits commercial use, but "
        "the gate form requires affirming 'I agree to use this dataset solely for research "
        "purposes to advance AI safety and not for malicious use'. The click-through is what "
        "was actually agreed and it is narrower than the licence. Training a commercially "
        "shipped vertical pack on this corpus is NOT cleared by 'it's CC-BY'. Route past "
        "counsel before the finance/healthcare/law packs depend on it."
    ),
    terms_read_on=date(2026, 8, 12),
    total_rows=58_928,
    splits=(
        SplitSpec("train", "expguardtrain.parquet", 56_653, 20_890_000),
        SplitSpec("test", "expguardtest.parquet", 2_275, 1_530_000),
    ),
    homepage="https://huggingface.co/datasets/6rightjade/expguardmix",
    citation="ExpGuard: LLM Content Moderation in Specialized Domains, arXiv:2603.02588, "
    "ICLR 2026 (main conference track).",
    notes=(
        "Corpus was GENERATED WITH GPT-4o (pipeline: Wikipedia terminology mining -> Wikidata "
        "filtering + human verification -> GPT-4o generation). Any Model BOM for an artifact "
        "trained on this must record a closed-frontier-model dependency in the data lineage, "
        "even though no frontier API is called at training time.",
        "ExpGuardTest is 2,275 expert-validated examples. English only.",
        "Three of the four planned vertical packs -- finance, healthcare, law -- map directly "
        "onto its domains.",
    ),
)

_HALO_GUARD_BENCH = DatasetSpec(
    dataset_id="halo-guard-bench",
    title="halo-guard-bench",
    purpose="eval-only companion to the HaloGuard multilingual candidate",
    licence="unverified",
    licence_url="https://huggingface.co/datasets/astroware/halo-guard-bench",
    gated=False,
    gate_kind="none",
    redistributable=False,
    commercial_use="unverified",
    terms_note=(
        "Licence not verified in detail; deprioritised along with HaloGuard itself. Vendor-"
        "published benchmark for a vendor-published model -- treat with the scepticism due "
        "anyone grading their own homework. Eval-only, behind the blind parity gate."
    ),
    terms_read_on=date(2026, 8, 12),
    total_rows=0,
    splits=(),
    homepage="https://huggingface.co/datasets/astroware/halo-guard-bench",
    citation="Self-published; no peer-reviewed paper, no linked technical report.",
    notes=(
        "Do NOT put on the critical path. HaloGuard is prompt-side only (it does not read "
        "model responses), publisher provenance is unknown, and release cadence looks like a "
        "hobby project.",
    ),
)

_LOCAL_SMOKE = DatasetSpec(
    dataset_id="local-smoke",
    title="Local smoke set",
    purpose="offline harness smoke test -- hand-written, ships in-repo",
    licence="Apache-2.0",
    licence_url="https://www.apache.org/licenses/LICENSE-2.0",
    gated=False,
    gate_kind="none",
    redistributable=True,
    commercial_use="permitted",
    terms_note="Written by Warrantor contributors for pipeline smoke testing. No third-party "
    "content, no scraped text.",
    terms_read_on=date(2026, 8, 12),
    total_rows=0,
    splits=(),
    homepage="https://github.com/muveraai/warrantor",
    citation="n/a",
    notes=(
        "Exists so `evaluate` has something to run against with zero downloads and zero "
        "credentials. It is far too small to support any claim about model quality.",
    ),
)

REGISTRY: dict[str, DatasetSpec] = {
    spec.dataset_id: spec for spec in (_WILDGUARDMIX, _EXPGUARDMIX, _HALO_GUARD_BENCH, _LOCAL_SMOKE)
}


def list_datasets() -> tuple[DatasetSpec, ...]:
    """Every registered dataset, in stable id order."""

    return tuple(REGISTRY[key] for key in sorted(REGISTRY))


def get_dataset(dataset_id: str) -> DatasetSpec:
    """Look up one dataset spec by id."""

    try:
        return REGISTRY[dataset_id]
    except KeyError as error:
        known = ", ".join(sorted(REGISTRY))
        raise UnknownDatasetError(f"unknown dataset {dataset_id!r}; registered: {known}") from error


def cache_root(override: Path | None = None) -> Path:
    """Resolve the local cache root without creating it.

    Precedence: explicit argument, then ``$WARRANTOR_ML_CACHE``, then
    ``~/.cache/warrantor-ml``. Nothing is written until a download actually runs.
    """

    if override is not None:
        return override
    from_env = os.environ.get(CacheEnvVar)
    if from_env:
        return Path(from_env)
    return Path.home() / ".cache" / "warrantor-ml"


def dataset_paths(spec: DatasetSpec, override: Path | None = None) -> dict[str, Path]:
    """Where each split of ``spec`` would land on disk. Pure path arithmetic."""

    base = cache_root(override) / "datasets" / spec.dataset_id / spec.revision
    return {split.name: base / Path(split.remote_path).name for split in spec.splits}


def _available_token() -> str | None:
    """The first Hugging Face read token present in the environment, if any."""

    for variable in TokenEnvVars:
        value = os.environ.get(variable)
        if value:
            return value
    return None


@dataclass(frozen=True)
class PreflightReport:
    """The result of checking whether a dataset could be fetched. Performs no network I/O."""

    dataset_id: str
    gated: bool
    credentials_present: bool
    cached_splits: tuple[str, ...]
    missing_splits: tuple[str, ...]
    blockers: tuple[str, ...]

    @property
    def ready(self) -> bool:
        """Whether :func:`ensure_available` would succeed without manual intervention."""

        return not self.blockers and not self.missing_splits


def preflight(spec: DatasetSpec, cache_override: Path | None = None) -> PreflightReport:
    """Report what stands between the caller and a usable local copy. Offline and pure."""

    paths = dataset_paths(spec, cache_override)
    cached = tuple(name for name, path in paths.items() if path.is_file())
    missing = tuple(name for name in paths if name not in cached)
    blockers: list[str] = []
    token_present = _available_token() is not None
    if spec.gated and not token_present and missing:
        blockers.append(
            f"{spec.dataset_id} is gated ({spec.gate_kind}) and no Hugging Face read token is "
            f"set in {' / '.join(TokenEnvVars)}"
        )
    if not spec.splits:
        blockers.append(f"{spec.dataset_id} declares no downloadable splits")
    return PreflightReport(
        dataset_id=spec.dataset_id,
        gated=spec.gated,
        credentials_present=token_present,
        cached_splits=cached,
        missing_splits=missing,
        blockers=tuple(blockers),
    )


def _gate_instructions(spec: DatasetSpec) -> str:
    """The manual, unscriptable steps that unblock a gated corpus."""

    return "\n".join(
        (
            f"{spec.dataset_id} ({spec.title}) is gated and cannot be fetched anonymously.",
            "This is a MANUAL human step. It cannot be scripted around, and it costs nothing.",
            "",
            f"  1. Sign in to Hugging Face and open {spec.homepage}",
            f"  2. Accept the access form (gate kind: {spec.gate_kind} -- auto-approved on "
            "submit, no human reviewer, no waiting period).",
            "  3. Create a READ token at https://huggingface.co/settings/tokens",
            f"  4. Export it as {TokenEnvVars[0]} in this shell, or run `hf auth login`.",
            "",
            f"Licence: {spec.licence} ({spec.licence_url})",
            f"Terms actually agreed: {spec.terms_note}",
        )
    )


def ensure_available(
    spec: DatasetSpec,
    splits: tuple[str, ...] | None = None,
    cache_override: Path | None = None,
    allow_download: bool = True,
) -> dict[str, Path]:
    """Return local paths for the requested splits, downloading only if needed.

    Downloads on demand and never at import. Raises :class:`DatasetAccessError` with the exact
    manual unblock steps rather than emitting a confusing HTTP 401 traceback.
    """

    wanted = splits if splits is not None else tuple(item.name for item in spec.splits)
    if not spec.splits:
        raise DatasetAccessError(
            f"{spec.dataset_id} declares no downloadable splits; it is a reference entry only"
        )
    paths = dataset_paths(spec, cache_override)
    for name in wanted:
        spec.split(name)  # raises UnknownDatasetError for a bad split name

    resolved: dict[str, Path] = {}
    to_fetch: list[str] = []
    for name in wanted:
        if paths[name].is_file():
            resolved[name] = paths[name]
        else:
            to_fetch.append(name)

    if not to_fetch:
        return resolved
    if not allow_download:
        missing = ", ".join(to_fetch)
        raise DatasetAccessError(
            f"{spec.dataset_id}: splits not cached ({missing}) and downloading is disabled"
        )
    if spec.gated and _available_token() is None:
        raise DatasetAccessError(_gate_instructions(spec))

    try:
        from huggingface_hub import hf_hub_download
    except ImportError as error:  # pragma: no cover - depends on optional extra
        raise DatasetAccessError(
            f"{spec.dataset_id}: huggingface-hub is not installed. "
            "Install the optional extra: pip install -e '.[hub]'"
        ) from error

    hub_id = _hub_repo_id(spec)
    destination_root = next(iter(paths.values())).parent
    destination_root.mkdir(parents=True, exist_ok=True)
    for name in to_fetch:  # pragma: no cover - network path
        split = spec.split(name)
        downloaded = hf_hub_download(
            repo_id=hub_id,
            filename=split.remote_path,
            repo_type="dataset",
            revision=spec.revision,
            token=_available_token(),
        )
        target = paths[name]
        target.write_bytes(Path(downloaded).read_bytes())
        resolved[name] = target
    return resolved


_HUB_REPO_IDS = {
    "wildguardmix": "allenai/wildguardmix",
    "expguardmix": "6rightjade/expguardmix",
    "halo-guard-bench": "astroware/halo-guard-bench",
}


def _hub_repo_id(spec: DatasetSpec) -> str:
    """The Hub repo id for a spec, or a clear failure for in-repo corpora."""

    try:
        return _HUB_REPO_IDS[spec.dataset_id]
    except KeyError as error:
        raise DatasetAccessError(
            f"{spec.dataset_id} is not a Hub dataset and has no remote to download from"
        ) from error


def _spec_to_dict(spec: DatasetSpec) -> dict[str, object]:
    """Serialise a spec for the CLI and for the AIBOM dataset-licence table."""

    return {
        "dataset_id": spec.dataset_id,
        "title": spec.title,
        "purpose": spec.purpose,
        "licence": spec.licence,
        "licence_url": spec.licence_url,
        "gated": spec.gated,
        "gate_kind": spec.gate_kind,
        "redistributable": spec.redistributable,
        "commercial_use": spec.commercial_use,
        "attribution_required": spec.attribution_required,
        "terms_note": spec.terms_note,
        "terms_read_on": spec.terms_read_on.isoformat(),
        "revision": spec.revision,
        "total_rows": spec.total_rows,
        "splits": [
            {
                "name": split.name,
                "remote_path": split.remote_path,
                "rows": split.rows,
                "approx_bytes": split.approx_bytes,
            }
            for split in spec.splits
        ],
        "homepage": spec.homepage,
        "citation": spec.citation,
        "notes": list(spec.notes),
    }


def build_parser() -> argparse.ArgumentParser:
    """CLI for inspecting the registry and preflighting access."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-datasets",
        description="Inspect the guard-model dataset registry. Read-only unless --fetch.",
    )
    parser.add_argument("--dataset", help="restrict to one dataset id")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="report what blocks access (offline; no network calls)",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="download missing splits (requires credentials for gated corpora)",
    )
    parser.add_argument("--cache", type=Path, help="override the local cache root")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``warrantor-ml-datasets``."""

    arguments = build_parser().parse_args(argv)
    specs = (get_dataset(arguments.dataset),) if arguments.dataset else list_datasets()

    if arguments.fetch:
        for spec in specs:
            try:
                resolved = ensure_available(spec, cache_override=arguments.cache)
            except DatasetAccessError as error:
                print(f"[BLOCKED] {spec.dataset_id}\n{error}\n", file=sys.stderr)
                return 1
            for name, path in sorted(resolved.items()):
                print(f"[ok] {spec.dataset_id}:{name} -> {path}")
        return 0

    if arguments.preflight:
        reports = [preflight(spec, arguments.cache) for spec in specs]
        if arguments.json:
            print(
                json.dumps(
                    [
                        {
                            "dataset_id": report.dataset_id,
                            "gated": report.gated,
                            "credentials_present": report.credentials_present,
                            "cached_splits": list(report.cached_splits),
                            "missing_splits": list(report.missing_splits),
                            "blockers": list(report.blockers),
                            "ready": report.ready,
                        }
                        for report in reports
                    ],
                    indent=2,
                )
            )
        else:
            for report in reports:
                marker = "ready" if report.ready else "BLOCKED"
                print(f"[{marker:7}] {report.dataset_id}")
                for blocker in report.blockers:
                    print(f"          {blocker}")
        return 0 if all(report.ready for report in reports) else 1

    if arguments.json:
        print(json.dumps([_spec_to_dict(spec) for spec in specs], indent=2))
        return 0
    for spec in specs:
        gate = f"gated:{spec.gate_kind}" if spec.gated else "ungated"
        print(f"{spec.dataset_id:18} {spec.licence:14} {gate:12} rows={spec.total_rows}")
        print(f"  commercial use: {spec.commercial_use}")
        print(f"  {spec.terms_note}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
