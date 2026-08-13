"""Registry integrity, path arithmetic, and the promise that nothing downloads at import."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from warrantor_ml import datasets


def test_import_performs_no_network_io() -> None:
    """Importing the module must not touch the network, disk cache, or credentials.

    Run in a subprocess with urlopen and socket.socket poisoned. If the import path ever grows
    an eager download, this fails immediately rather than in CI on a machine with no token.
    """

    program = (
        "import socket, urllib.request, sys\n"
        "def boom(*a, **k):\n"
        "    raise AssertionError('network I/O at import time')\n"
        "socket.socket = boom\n"
        "urllib.request.urlopen = boom\n"
        "import warrantor_ml.datasets as d\n"
        "assert len(d.REGISTRY) >= 3\n"
        "print('clean')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "clean" in completed.stdout


def test_registry_contains_the_planned_corpora() -> None:
    ids = {spec.dataset_id for spec in datasets.list_datasets()}
    assert {"wildguardmix", "expguardmix"} <= ids


def test_list_datasets_is_sorted_and_stable() -> None:
    ids = [spec.dataset_id for spec in datasets.list_datasets()]
    assert ids == sorted(ids)
    assert ids == [spec.dataset_id for spec in datasets.list_datasets()]


def test_wildguardmix_row_count_is_the_corrected_figure() -> None:
    """The plan said 92K. The published figures are 86,759 + 1,725 = 88,484."""

    spec = datasets.get_dataset("wildguardmix")
    assert spec.total_rows == 88_484
    assert spec.split("train").rows == 86_759
    assert spec.split("test").rows == 1_725
    assert sum(split.rows for split in spec.splits) == spec.total_rows


def test_expguardmix_records_the_licence_versus_click_through_conflict() -> None:
    spec = datasets.get_dataset("expguardmix")
    assert spec.licence == "CC-BY-4.0"
    # CC-BY permits commercial use; the gate form does not. The registry must not flatten that.
    assert spec.commercial_use == "restricted-by-click-through"
    assert "research purposes" in spec.terms_note
    assert spec.total_rows == 58_928


def test_both_primary_corpora_are_flagged_gated() -> None:
    for dataset_id in ("wildguardmix", "expguardmix"):
        spec = datasets.get_dataset(dataset_id)
        assert spec.gated is True
        assert spec.gate_kind == "auto"
        assert spec.requires_credentials is True


def test_every_spec_declares_its_licensing_posture() -> None:
    for spec in datasets.list_datasets():
        assert spec.licence
        assert spec.licence_url
        assert spec.terms_note
        assert spec.terms_read_on is not None
        assert spec.commercial_use in {
            "permitted",
            "restricted-by-click-through",
            "prohibited",
            "unverified",
        }


def test_unknown_dataset_lists_what_is_registered() -> None:
    with pytest.raises(datasets.UnknownDatasetError) as excinfo:
        datasets.get_dataset("nope")
    assert "wildguardmix" in str(excinfo.value)


def test_unknown_split_is_rejected() -> None:
    with pytest.raises(datasets.UnknownDatasetError, match="no split"):
        datasets.get_dataset("wildguardmix").split("validation")


def test_cache_root_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(datasets.CacheEnvVar, raising=False)
    assert datasets.cache_root(tmp_path) == tmp_path
    monkeypatch.setenv(datasets.CacheEnvVar, str(tmp_path / "from-env"))
    assert datasets.cache_root() == tmp_path / "from-env"
    assert datasets.cache_root(tmp_path) == tmp_path


def test_dataset_paths_do_not_create_anything(tmp_path: Path) -> None:
    spec = datasets.get_dataset("wildguardmix")
    paths = datasets.dataset_paths(spec, tmp_path)
    assert set(paths) == {"train", "test"}
    assert paths["train"].name == "wildguard_train.parquet"
    assert not any(path.exists() for path in paths.values())
    assert list(tmp_path.iterdir()) == []


def _clear_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable in datasets.TokenEnvVars:
        monkeypatch.delenv(variable, raising=False)


def test_preflight_reports_the_credential_blocker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_tokens(monkeypatch)
    report = datasets.preflight(datasets.get_dataset("wildguardmix"), tmp_path)
    assert report.ready is False
    assert report.credentials_present is False
    assert any("gated" in blocker for blocker in report.blockers)
    assert set(report.missing_splits) == {"train", "test"}


def test_preflight_clears_once_a_token_is_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_tokens(monkeypatch)
    monkeypatch.setenv("HF_TOKEN", "hf_placeholder")
    report = datasets.preflight(datasets.get_dataset("wildguardmix"), tmp_path)
    assert report.credentials_present is True
    assert report.blockers == ()
    # Still not "ready" -- the files are not cached. Credentials are necessary, not sufficient.
    assert report.ready is False


def test_preflight_sees_a_cached_split(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_tokens(monkeypatch)
    spec = datasets.get_dataset("wildguardmix")
    paths = datasets.dataset_paths(spec, tmp_path)
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"parquet-placeholder")
    report = datasets.preflight(spec, tmp_path)
    assert set(report.cached_splits) == {"train", "test"}
    assert report.ready is True


def test_gated_fetch_without_credentials_explains_the_manual_unblock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_tokens(monkeypatch)
    with pytest.raises(datasets.DatasetAccessError) as excinfo:
        datasets.ensure_available(datasets.get_dataset("expguardmix"), cache_override=tmp_path)
    message = str(excinfo.value)
    assert "MANUAL human step" in message
    assert "huggingface.co/settings/tokens" in message
    assert "HF_TOKEN" in message
    # The remediation must carry the terms, not just the mechanics.
    assert "research purposes" in message


def test_cached_files_short_circuit_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_tokens(monkeypatch)
    spec = datasets.get_dataset("wildguardmix")
    paths = datasets.dataset_paths(spec, tmp_path)
    paths["test"].parent.mkdir(parents=True, exist_ok=True)
    paths["test"].write_bytes(b"parquet-placeholder")
    resolved = datasets.ensure_available(spec, splits=("test",), cache_override=tmp_path)
    assert resolved == {"test": paths["test"]}


def test_allow_download_false_never_reaches_the_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HF_TOKEN", "hf_placeholder")
    with pytest.raises(datasets.DatasetAccessError, match="downloading is disabled"):
        datasets.ensure_available(
            datasets.get_dataset("wildguardmix"), cache_override=tmp_path, allow_download=False
        )


def test_reference_only_entry_cannot_be_fetched(tmp_path: Path) -> None:
    with pytest.raises(datasets.DatasetAccessError, match="no downloadable splits"):
        datasets.ensure_available(datasets.get_dataset("local-smoke"), cache_override=tmp_path)


def test_cli_json_listing_round_trips(capsys: pytest.CaptureFixture[str]) -> None:
    import json

    assert datasets.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    ids = {row["dataset_id"] for row in payload}
    assert {"wildguardmix", "expguardmix"} <= ids
    wildguard = next(row for row in payload if row["dataset_id"] == "wildguardmix")
    assert wildguard["gated"] is True
    assert wildguard["total_rows"] == 88_484


def test_cli_preflight_exits_nonzero_when_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_tokens(monkeypatch)
    exit_code = datasets.main(
        ["--dataset", "wildguardmix", "--preflight", "--cache", str(tmp_path)]
    )
    assert exit_code == 1
