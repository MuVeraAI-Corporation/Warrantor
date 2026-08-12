#!/usr/bin/env python3
"""Validate this repo's OCSF events against the published OCSF schema.

The offline tests in ``python/warrantor_ocsf/tests/test_ocsf_schema.py`` pin what the schema said
when they were written. This script asks the schema itself, so it catches drift the pinned tests
cannot: a deprecated attribute, a tightened enum, a newly required field.

It reaches the network. Run it when bumping ``OCSF_VERSION`` or before a release -- it is
deliberately NOT part of the default CI gate, which must stay hermetic.

Usage:
    python tools/audit/ocsf_validate.py            # validate the built-in event shapes
    python tools/audit/ocsf_validate.py --json     # machine-readable report

Exit status: 0 if every event validates with no errors, 1 otherwise (warnings do not fail the
run, but they are printed -- a deprecation warning today is an error after the next bump).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "python" / "warrantor_ocsf" / "src"))

VALIDATOR_URL = "https://schema.ocsf.io/api/v2/validate"
REQUEST_TIMEOUT_S = 30.0

# One AAR per distinct path through the converter. Add a case here whenever the converter grows a
# branch -- an unvalidated branch is how the previous mapping shipped 21 errors.
CASES: dict[str, dict[str, Any]] = {
    "plain-read": {
        "aar_id": "case-read",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_name": "fetch",
        "side_effect_class": "read",
        "completed_at": 1786439001.0,
    },
    "write": {
        "aar_id": "case-write",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_name": "put",
        "side_effect_class": "write",
        "completed_at": 1786439001.0,
    },
    "update": {
        "aar_id": "case-update",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_name": "patch",
        "side_effect_class": "update",
        "completed_at": 1786439001.0,
    },
    "delete": {
        "aar_id": "case-delete",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_name": "remove",
        "side_effect_class": "delete",
        "completed_at": 1786439001.0,
    },
    "unrecognised-side-effect": {
        "aar_id": "case-other",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_name": "teleport",
        "side_effect_class": "teleport",
        "completed_at": 1786439001.0,
    },
    "missing-side-effect": {
        "aar_id": "case-unknown",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_name": "mystery",
        "completed_at": 1786439001.0,
    },
    "secret-finding": {
        "aar_id": "case-secret",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_name": "leak",
        "side_effect_class": "write",
        "secret_findings": ["aws_access_key"],
        "completed_at": 1786439001.0,
    },
    "kill-switch": {
        "aar_id": "case-kill",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_name": "halt",
        "side_effect_class": "write",
        "kill_switch_triggered": True,
        "completed_at": 1786439001.0,
    },
    "attestation": {
        "aar_id": "case-attest",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_type": "attestation",
        "action_name": "verify",
        "completed_at": 1786439001.0,
    },
    "tool-error": {
        "aar_id": "case-error",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_name": "explode",
        "side_effect_class": "read",
        "error": "upstream refused the connection",
        "completed_at": 1786439001.0,
    },
    "iso-timestamp": {
        "aar_id": "case-iso",
        "identity": "spiffe://muveraai.com/agent/alpha",
        "action_name": "replayed",
        "side_effect_class": "read",
        "completed_at": "2026-08-11T09:00:00Z",
    },
    "empty-aar": {},
}


def validate(event: dict[str, Any]) -> dict[str, Any]:
    """POST one event to the OCSF validator and return its report."""
    request = urllib.request.Request(
        VALIDATOR_URL,
        data=json.dumps(event, default=str).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_S) as response:
        return json.loads(response.read())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="emit a machine-readable report"
    )
    args = parser.parse_args()

    from warrantor_ocsf import OCSF_VERSION, convert_aar_to_ocsf

    report: dict[str, Any] = {"ocsf_version": OCSF_VERSION, "cases": {}}
    total_errors = 0
    total_warnings = 0

    for name, aar in CASES.items():
        event = convert_aar_to_ocsf(aar)
        try:
            result = validate(event)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            # A network failure is not a schema failure; say so rather than reporting a false red.
            print(f"ERROR: could not reach the OCSF validator: {exc}", file=sys.stderr)
            return 2
        errors = result.get("errors", [])
        warnings = result.get("warnings", [])
        total_errors += len(errors)
        total_warnings += len(warnings)
        report["cases"][name] = {
            "activity_id": event["activity_id"],
            "type_uid": event["type_uid"],
            "severity_id": event["severity_id"],
            "errors": [e.get("message", "") for e in errors],
            "warnings": [w.get("message", "") for w in warnings],
        }
        if not args.json:
            status = (
                "ok  " if not errors and not warnings else "FAIL" if errors else "warn"
            )
            print(
                f"[{status}] {name:26} activity={event['activity_id']:<3} "
                f"severity={event['severity_id']} errors={len(errors)} warnings={len(warnings)}"
            )
            for entry in errors:
                print(f"         ERROR: {entry.get('message', '')}")
            for entry in warnings:
                print(f"         warn:  {entry.get('message', '')}")

    report["total_errors"] = total_errors
    report["total_warnings"] = total_warnings

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print()
        print(
            f"RESULT: {'PASS' if total_errors == 0 else 'FAIL'} - "
            f"{len(CASES)} event shapes, {total_errors} errors, {total_warnings} warnings "
            f"(schema {OCSF_VERSION})"
        )
    return 0 if total_errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
