"""Offline schema-conformance tests for the OCSF converter.

Every rule asserted here was read from the published OCSF 1.9.0 schema
(https://schema.ocsf.io/api/1.9.0/classes/api_activity) and confirmed against the official
validator. They are pinned offline so CI enforces them without a network call; re-check them
against the live schema with ``tools/audit/ocsf_validate.py`` when bumping OCSF_VERSION.

The audit that produced these found 21 validation errors across four event shapes -- every event
this forwarder emitted was rejected by the schema it claimed to speak.
"""

from __future__ import annotations

import datetime

import pytest

from warrantor_ocsf import (
    ACTIVITY_CREATE,
    ACTIVITY_DELETE,
    ACTIVITY_OTHER,
    ACTIVITY_READ,
    ACTIVITY_UNKNOWN,
    ACTIVITY_UPDATE,
    CLASS_API_ACTIVITY,
    OCSF_VERSION,
    PRODUCT_VERSION,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
    FileSink,
    OCSFForwarder,
    convert_aar_to_ocsf,
)

# The complete activity_id enum for class 6003. Anything outside this set is rejected outright:
# the module previously emitted 5 ("Authenticate") and 6 ("Detect"), neither of which exists.
VALID_ACTIVITY_IDS = {0, 1, 2, 3, 4, 99}

# The complete severity_id enum. Note 99 is "Other", NOT a high-water mark -- SEVERITY_LOW was
# defined as 99, which reads to a SIEM as "uncategorised", not "low".
VALID_SEVERITY_IDS = {0, 1, 2, 3, 4, 5, 6, 99}

# Top-level attributes that are NOT defined on class 6003. Emitting any of them makes the whole
# event fail validation.
INVALID_TOP_LEVEL_ATTRS = ("$schema", "version", "original_time", "time_dt", "scan")

BASE_AAR = {
    "aar_id": "r1",
    "identity": "spiffe://muveraai.com/agent/alpha",
    "action_name": "fetch",
    "side_effect_class": "read",
    "completed_at": 1786439001.0,
}


def _aar(**overrides: object) -> dict:
    return {**BASE_AAR, **overrides}


ALL_SHAPES = [
    pytest.param(_aar(), id="plain-read"),
    pytest.param(_aar(side_effect_class="write"), id="write"),
    pytest.param(_aar(side_effect_class="delete"), id="delete"),
    pytest.param(_aar(side_effect_class="teleport"), id="unrecognised-side-effect"),
    pytest.param(_aar(secret_findings=["aws_key"]), id="secret-finding"),
    pytest.param(_aar(kill_switch_triggered=True), id="kill-switch"),
    pytest.param(_aar(action_type="attestation"), id="attestation"),
    pytest.param(_aar(error="boom"), id="error"),
    pytest.param(_aar(completed_at="2026-08-11T09:00:00Z"), id="iso-timestamp"),
    pytest.param({}, id="empty-aar"),
]


# --- Structural conformance, asserted for every event shape ------------------


@pytest.mark.parametrize("aar", ALL_SHAPES)
def test_event_carries_no_undefined_top_level_attributes(aar: dict) -> None:
    event = convert_aar_to_ocsf(aar)
    present = [key for key in INVALID_TOP_LEVEL_ATTRS if key in event]
    assert not present, f"undefined attributes would fail validation: {present}"


@pytest.mark.parametrize("aar", ALL_SHAPES)
def test_event_carries_every_required_attribute(aar: dict) -> None:
    """The class marks these required; omitting one is an error, not a warning."""
    event = convert_aar_to_ocsf(aar)
    for required in (
        "activity_id",
        "actor",
        "api",
        "category_uid",
        "class_uid",
        "metadata",
        "severity_id",
        "src_endpoint",
        "time",
        "type_uid",
    ):
        assert required in event, f"required attribute {required!r} is missing"


@pytest.mark.parametrize("aar", ALL_SHAPES)
def test_enums_stay_inside_the_schema(aar: dict) -> None:
    event = convert_aar_to_ocsf(aar)
    assert event["activity_id"] in VALID_ACTIVITY_IDS
    assert event["severity_id"] in VALID_SEVERITY_IDS
    assert event["class_uid"] == CLASS_API_ACTIVITY
    # type_uid is derived, so it can only be valid if activity_id is.
    assert event["type_uid"] == CLASS_API_ACTIVITY * 100 + event["activity_id"]


@pytest.mark.parametrize("aar", ALL_SHAPES)
def test_metadata_separates_schema_version_from_product_version(aar: dict) -> None:
    """metadata.version is the OCSF schema version; the product's own version goes under
    product.version. Conflating them told every consumer we spoke schema 1.0.0."""
    metadata = convert_aar_to_ocsf(aar)["metadata"]
    assert metadata["version"] == OCSF_VERSION
    assert metadata["product"]["version"] == PRODUCT_VERSION


# --- Timestamps --------------------------------------------------------------


def test_time_is_milliseconds_not_seconds() -> None:
    """OCSF timestamp_t is milliseconds since the epoch. Emitting seconds placed every event in
    January 1970, where no time-range search would ever find it."""
    event = convert_aar_to_ocsf(_aar(completed_at=1786439001.0))
    assert event["time"] == 1786439001000


def test_iso_timestamps_are_accepted() -> None:
    """AARs replayed from the E1 log carry ISO-8601 strings; a bare float() raised ValueError."""
    event = convert_aar_to_ocsf(_aar(completed_at="2026-08-11T09:00:00Z"))
    expected = datetime.datetime(2026, 8, 11, 9, 0, tzinfo=datetime.UTC).timestamp()
    assert event["time"] == int(expected * 1000)


def test_unparseable_timestamp_falls_back_rather_than_raising() -> None:
    event = convert_aar_to_ocsf(_aar(completed_at="not a timestamp"))
    assert event["time"] > 0


def test_both_time_fields_derive_from_one_value() -> None:
    """They cannot drift: metadata.original_time must describe the same instant as time."""
    event = convert_aar_to_ocsf(_aar(completed_at=1786439001.0))
    from_ms = datetime.datetime.fromtimestamp(event["time"] / 1000, tz=datetime.UTC)
    from_iso = datetime.datetime.fromisoformat(
        event["metadata"]["original_time"].replace("Z", "+00:00")
    )
    assert from_ms == from_iso


# --- Severity ----------------------------------------------------------------


def test_secret_exposure_outranks_a_plain_error() -> None:
    """Both were severity 3 (Medium) -- a leaked credential was indistinguishable from a tool
    that returned an error."""
    secret = convert_aar_to_ocsf(_aar(secret_findings=["aws_key"]))["severity_id"]
    plain_error = convert_aar_to_ocsf(_aar(error="boom"))["severity_id"]
    assert secret == SEVERITY_HIGH
    assert plain_error == SEVERITY_MEDIUM
    assert secret > plain_error


def test_kill_switch_is_critical() -> None:
    assert convert_aar_to_ocsf(_aar(kill_switch_triggered=True))["severity_id"] == SEVERITY_CRITICAL


def test_ordinary_activity_is_informational() -> None:
    assert convert_aar_to_ocsf(_aar())["severity_id"] == SEVERITY_INFO


def test_severity_constants_match_the_ocsf_enum() -> None:
    """These are the schema's numbers, not ours to choose."""
    assert (SEVERITY_INFO, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL) == (1, 3, 4, 5)


# --- Activity mapping --------------------------------------------------------


@pytest.mark.parametrize(
    ("side_effect", "expected"),
    [
        ("read", ACTIVITY_READ),
        ("none", ACTIVITY_READ),
        ("write", ACTIVITY_CREATE),
        ("create", ACTIVITY_CREATE),
        ("update", ACTIVITY_UPDATE),
        ("modify", ACTIVITY_UPDATE),
        ("delete", ACTIVITY_DELETE),
        ("READ", ACTIVITY_READ),  # case-insensitive
        ("teleport", ACTIVITY_OTHER),  # present but unrecognised
    ],
)
def test_activity_comes_from_side_effect_class(side_effect: str, expected: int) -> None:
    """The AAR already carries the discriminator OCSF's enum wants. It used to be thrown into
    `unmapped` while every event was hard-coded to 1 (Create) -- so read-only agent actions were
    logged as creations."""
    assert convert_aar_to_ocsf(_aar(side_effect_class=side_effect))["activity_id"] == expected


def test_missing_side_effect_is_unknown_not_create() -> None:
    aar = _aar()
    del aar["side_effect_class"]
    assert convert_aar_to_ocsf(aar)["activity_id"] == ACTIVITY_UNKNOWN


def test_kill_switch_keeps_the_full_security_payload() -> None:
    """Class 6007 (Scan Activity) defines no actor, api or resources attribute, so routing
    kill-switch events there discarded the entire payload."""
    event = convert_aar_to_ocsf(
        _aar(kill_switch_triggered=True, secret_findings=["aws_key"], inputs={"cmd": "rm -rf /"})
    )
    assert event["class_uid"] == CLASS_API_ACTIVITY
    assert event["actor"]["user"]["uid"] == BASE_AAR["identity"]
    assert event["api"]["operation"] == BASE_AAR["action_name"]
    assert event["api"]["request"]["data"] == {"cmd": "rm -rf /"}
    assert any(resource["type"] == "credential" for resource in event["resources"])
    assert event["unmapped"]["kill_switch_triggered"] is True


# --- Batch resilience --------------------------------------------------------


class _Recorder:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def send(self, event: dict) -> bool:
        self.events.append(event)
        return True


def test_one_poison_record_does_not_lose_the_rest_of_the_batch() -> None:
    """Conversion used to run outside forward()'s try block, so a single malformed AAR raised out
    of the batch loop: the remaining events were never delivered, never counted as forwarded and
    never counted as failed. stats reported 100% success while most of the batch was gone."""
    forwarder = OCSFForwarder()
    sink = _Recorder()
    forwarder.add_sink(sink)

    batch = [
        _aar(aar_id="a1"),
        "not a dict at all",  # poison: convert_aar_to_ocsf raises TypeError
        _aar(aar_id="a3"),
        _aar(aar_id="a4"),
    ]
    accepted = forwarder.batch_forward(batch)  # type: ignore[arg-type]

    assert accepted == 3, "the three good records must still be delivered"
    assert len(sink.events) == 3
    assert forwarder.stats.forwarded == 4, "every record must be accounted for"
    assert forwarder.stats.succeeded == 3
    assert forwarder.stats.failed == 1
    assert forwarder.stats.conversion_failures == 1
    assert any("convert" in err for err in forwarder.stats.recent_sink_errors)


def test_conversion_failure_is_counted_not_swallowed() -> None:
    forwarder = OCSFForwarder()
    forwarder.add_sink(_Recorder())
    assert forwarder.forward("not a dict") is False  # type: ignore[arg-type]
    assert forwarder.stats.failed == 1
    assert forwarder.stats.conversion_failures == 1


def test_non_serialisable_payload_still_reaches_a_file_sink(tmp_path) -> None:
    """A datetime in the AAR must not blow up delivery."""
    forwarder = OCSFForwarder()
    target = tmp_path / "events.jsonl"
    forwarder.add_sink(FileSink(target))
    assert forwarder.forward(_aar(inputs={"when": datetime.datetime(2026, 8, 11)})) is True
    assert target.read_text(encoding="utf-8").count("\n") == 1
