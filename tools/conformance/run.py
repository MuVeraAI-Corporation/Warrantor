#!/usr/bin/env python3
"""Strict, cross-platform AumOS conformance orchestrator.

The runner is intentionally non-vacuous: every required language must be
available, every lane must contain vectors, and every vector must run in every
required language. Missing tools and zero-test lanes are failures.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
T1_VECTOR_DIRECTORY = REPOSITORY_ROOT / "testvectors" / "T1"
PROTOCOL_VECTOR_DIRECTORY = REPOSITORY_ROOT / "testvectors" / "protocols"
PROTOCOL_MANIFEST_PATH = PROTOCOL_VECTOR_DIRECTORY / "manifest.json"
PROTOCOL_REGISTRY_PATH = REPOSITORY_ROOT / "specs" / "protocols" / "registry.json"
PROTOCOL_ERRORS_PATH = REPOSITORY_ROOT / "specs" / "protocols" / "errors.json"
PROTOCOL_IDENTIFIERS = tuple(f"P{number}" for number in range(1, 13))
PROTOCOL_CATEGORIES = ("positive", "negative", "adversarial")
SUPPORTED_LANGUAGES = ("rust", "python", "go", "typescript")
DEFAULT_TIMEOUT_SECONDS = 180
# One protocol batch invocation covers all 40 vectors (and may include a cold
# cargo/go build), so it is allowed proportionally more wall-clock time.
PROTOCOL_BATCH_TIMEOUT_MULTIPLIER = 4


@dataclass(frozen=True)
class Vector:
    """A validated conformance vector and its raw JSON representation."""

    identifier: str
    lane: str
    path: Path
    content: dict[str, object]
    raw: bytes


@dataclass(frozen=True)
class ProtocolVector:
    """One validated P1-P12 wire vector and its declared expectation."""

    identifier: str
    protocol: str
    category: str
    expected: str
    expected_error: str
    validation_time: int
    document: object


@dataclass(frozen=True)
class ProtocolOutcome:
    """One language's verdict for one protocol vector."""

    valid: bool
    error_code: str
    detail: str


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of one language verifying one vector."""

    language: str
    lane: str
    vector_id: str
    passed: bool
    detail: str
    duration_ms: int


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require",
        default=os.environ.get(
            "AUMOS_REQUIRED_CONFORMANCE_LANGUAGES",
            ",".join(SUPPORTED_LANGUAGES),
        ),
        help="Comma-separated required languages (default: rust,python,go,typescript)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Optional path for the machine-readable JSON evidence report",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-verifier timeout in seconds",
    )
    return parser.parse_args()


def required_string(record: dict[str, object], key: str, path: Path) -> str:
    """Return a required string property or raise a precise schema error."""

    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: {key!r} must be a non-empty string")
    return value


def required_string_list(record: dict[str, object], key: str, path: Path) -> list[str]:
    """Return a required list of non-empty strings."""

    value = record.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ValueError(f"{path}: {key!r} must be a non-empty string array")
    return cast(list[str], value)


def load_vectors() -> list[Vector]:
    """Load, classify, and validate every T1 vector."""

    if not T1_VECTOR_DIRECTORY.is_dir():
        raise ValueError(f"missing vector directory: {T1_VECTOR_DIRECTORY}")

    vectors: list[Vector] = []
    identifiers: set[str] = set()
    for path in sorted(T1_VECTOR_DIRECTORY.glob("*.json")):
        raw = path.read_bytes()
        parsed: object = json.loads(raw)
        if not isinstance(parsed, dict) or not all(
            isinstance(key, str) for key in parsed
        ):
            raise ValueError(f"{path}: vector root must be a JSON object")
        content = cast(dict[str, object], parsed)
        identifier = required_string(content, "id", path)
        if identifier in identifiers:
            raise ValueError(f"{path}: duplicate vector id {identifier!r}")
        identifiers.add(identifier)

        if {
            "payload_hex",
            "verifying_key_hex",
            "signature_hex",
            "expected",
        } <= content.keys():
            lane = "signature"
            for key in ("payload_hex", "verifying_key_hex", "signature_hex"):
                bytes.fromhex(required_string(content, key, path))
            expected = required_string(content, "expected", path)
            if expected not in {"valid", "invalid"}:
                raise ValueError(f"{path}: expected must be 'valid' or 'invalid'")
        elif {"leaves_hex", "expected_root_hex"} <= content.keys():
            lane = "merkle"
            for leaf in required_string_list(content, "leaves_hex", path):
                bytes.fromhex(leaf)
            expected_root = required_string(content, "expected_root_hex", path)
            if len(bytes.fromhex(expected_root)) != 32:
                raise ValueError(f"{path}: expected_root_hex must contain 32 bytes")
        else:
            raise ValueError(f"{path}: vector does not match a supported T1 lane")

        vectors.append(Vector(identifier, lane, path, content, raw))

    for lane in ("signature", "merkle"):
        if not any(vector.lane == lane for vector in vectors):
            raise ValueError(f"T1 {lane} lane contains zero vectors")
    return vectors


def load_protocol_errors() -> set[str]:
    """Load the normative set of protocol validation error codes."""

    if not PROTOCOL_ERRORS_PATH.is_file():
        raise ValueError(f"missing protocol error registry: {PROTOCOL_ERRORS_PATH}")
    parsed: object = json.loads(PROTOCOL_ERRORS_PATH.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{PROTOCOL_ERRORS_PATH}: root must be a JSON object")
    entries = parsed.get("errors")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{PROTOCOL_ERRORS_PATH}: 'errors' must be a non-empty array")
    codes: set[str] = set()
    for entry in cast(list[object], entries):
        if not isinstance(entry, dict):
            raise ValueError(f"{PROTOCOL_ERRORS_PATH}: each error must be an object")
        codes.add(required_string(cast(dict[str, object], entry), "code", PROTOCOL_ERRORS_PATH))
    return codes


def load_protocol_vectors() -> tuple[list[ProtocolVector], dict[str, str]]:
    """Load, cross-check, and validate every P1-P12 wire vector."""

    if not PROTOCOL_MANIFEST_PATH.is_file():
        raise ValueError(f"missing protocol manifest: {PROTOCOL_MANIFEST_PATH}")
    if not PROTOCOL_REGISTRY_PATH.is_file():
        raise ValueError(f"missing protocol registry: {PROTOCOL_REGISTRY_PATH}")
    error_codes = load_protocol_errors()

    parsed: object = json.loads(PROTOCOL_MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{PROTOCOL_MANIFEST_PATH}: root must be a JSON object")
    manifest = cast(dict[str, object], parsed)

    raw_keyring = manifest.get("keyring")
    if not isinstance(raw_keyring, dict) or not raw_keyring:
        raise ValueError(f"{PROTOCOL_MANIFEST_PATH}: 'keyring' must be a non-empty object")
    keyring: dict[str, str] = {}
    for key_id, encoded in cast(dict[str, object], raw_keyring).items():
        if not isinstance(encoded, str) or len(bytes.fromhex(encoded)) != 32:
            raise ValueError(f"{PROTOCOL_MANIFEST_PATH}: key {key_id!r} must be 32 hex-encoded bytes")
        keyring[key_id] = encoded

    entries = manifest.get("vectors")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{PROTOCOL_MANIFEST_PATH}: 'vectors' must be a non-empty array")
    declared_count = manifest.get("vector_count")
    if declared_count != len(entries):
        raise ValueError(
            f"{PROTOCOL_MANIFEST_PATH}: vector_count {declared_count!r} "
            f"does not match {len(entries)} entries"
        )

    vectors: list[ProtocolVector] = []
    identifiers: set[str] = set()
    for raw_entry in cast(list[object], entries):
        if not isinstance(raw_entry, dict):
            raise ValueError(f"{PROTOCOL_MANIFEST_PATH}: each vector entry must be an object")
        entry = cast(dict[str, object], raw_entry)
        identifier = required_string(entry, "id", PROTOCOL_MANIFEST_PATH)
        if identifier in identifiers:
            raise ValueError(f"{PROTOCOL_MANIFEST_PATH}: duplicate vector id {identifier!r}")
        identifiers.add(identifier)
        relative_path = required_string(entry, "path", PROTOCOL_MANIFEST_PATH)
        vector_path = PROTOCOL_VECTOR_DIRECTORY / relative_path
        if not vector_path.is_file():
            raise ValueError(f"{PROTOCOL_MANIFEST_PATH}: missing vector file {relative_path}")

        parsed_vector: object = json.loads(vector_path.read_text(encoding="utf-8"))
        if not isinstance(parsed_vector, dict):
            raise ValueError(f"{vector_path}: vector root must be a JSON object")
        record = cast(dict[str, object], parsed_vector)

        for key in ("id", "protocol", "category", "expected"):
            if required_string(record, key, vector_path) != required_string(
                entry, key, PROTOCOL_MANIFEST_PATH
            ):
                raise ValueError(f"{vector_path}: {key!r} disagrees with the manifest")

        protocol = required_string(record, "protocol", vector_path)
        if protocol not in PROTOCOL_IDENTIFIERS:
            raise ValueError(f"{vector_path}: unknown protocol {protocol!r}")
        category = required_string(record, "category", vector_path)
        if category not in PROTOCOL_CATEGORIES:
            raise ValueError(f"{vector_path}: unknown category {category!r}")
        expected = required_string(record, "expected", vector_path)
        if expected not in {"valid", "invalid"}:
            raise ValueError(f"{vector_path}: expected must be 'valid' or 'invalid'")

        expected_error = record.get("expected_error")
        manifest_error = entry.get("expected_error")
        if not isinstance(expected_error, str) or expected_error != manifest_error:
            raise ValueError(f"{vector_path}: 'expected_error' disagrees with the manifest")
        if expected == "valid" and expected_error:
            raise ValueError(f"{vector_path}: a valid vector cannot declare an error code")
        if expected == "invalid" and expected_error not in error_codes:
            raise ValueError(
                f"{vector_path}: expected_error {expected_error!r} is not in specs/protocols/errors.json"
            )

        validation_time = record.get("validation_time")
        if not isinstance(validation_time, int) or isinstance(validation_time, bool):
            raise ValueError(f"{vector_path}: 'validation_time' must be an integer")
        document = record.get("document")
        if not isinstance(document, dict):
            raise ValueError(f"{vector_path}: 'document' must be a JSON object")

        vectors.append(
            ProtocolVector(
                identifier=identifier,
                protocol=protocol,
                category=category,
                expected=expected,
                expected_error=expected_error,
                validation_time=validation_time,
                document=document,
            )
        )

    covered = {vector.protocol for vector in vectors}
    missing = sorted(set(PROTOCOL_IDENTIFIERS) - covered)
    if missing:
        raise ValueError(f"protocol lane has no vectors for: {', '.join(missing)}")
    for category in PROTOCOL_CATEGORIES:
        if not any(vector.category == category for vector in vectors):
            raise ValueError(f"protocol {category} lane contains zero vectors")
    return vectors, keyring


def protocol_batch_payload(vectors: list[ProtocolVector], keyring: dict[str, str]) -> bytes:
    """Serialize the batch request shared by all four protocol verifiers."""

    return json.dumps(
        {
            "keyring": keyring,
            "vectors": [
                {
                    "id": vector.identifier,
                    "protocol": vector.protocol,
                    "validation_time": vector.validation_time,
                    "document": vector.document,
                }
                for vector in vectors
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")


def protocol_batch_command(language: str, executable: str) -> tuple[list[str], Path, dict[str, str]]:
    """Return the command, working directory, and environment for one verifier."""

    registry = str(PROTOCOL_REGISTRY_PATH)
    if language == "rust":
        return (
            [
                executable,
                "run",
                "-q",
                "-p",
                "warrantor-protocol-contracts",
                "--bin",
                "protocol-tck-rust",
                "--",
                registry,
            ],
            REPOSITORY_ROOT / "rust",
            {},
        )
    if language == "python":
        return (
            [executable, str(Path(__file__).with_name("verify_protocol_python.py")), registry],
            REPOSITORY_ROOT,
            {},
        )
    if language == "go":
        return (
            [executable, "run", "./cmd/protocol-tck", registry],
            REPOSITORY_ROOT / "go" / "protocol-contracts",
            {"GOCACHE": str(Path(tempfile.gettempdir()) / "warrantor-conformance-go-build")},
        )
    if language == "typescript":
        return (
            [
                executable,
                str(Path(__file__).with_name("verify_protocol_typescript.ts")),
                registry,
            ],
            REPOSITORY_ROOT,
            {},
        )
    raise ValueError(f"unsupported protocol verifier language: {language}")


def run_protocol_batch(
    language: str,
    executable: str,
    payload: bytes,
    timeout_seconds: int,
) -> tuple[dict[str, ProtocolOutcome] | None, str, int]:
    """Run one language's batch verifier and decode its per-vector verdicts."""

    command, cwd, environment = protocol_batch_command(language, executable)
    started = datetime.now(UTC)
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            input=payload,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env={**os.environ, **environment},
        )
    except subprocess.TimeoutExpired:
        duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
        return None, f"timed out after {timeout_seconds}s", duration_ms
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)

    stderr = completed.stderr.decode("utf-8", errors="replace").strip()
    if completed.returncode != 0:
        return None, f"exit code {completed.returncode}: {stderr[-400:]}", duration_ms
    lines = [
        line
        for line in completed.stdout.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    if not lines:
        return None, "verifier produced no output", duration_ms
    try:
        parsed: object = json.loads(lines[-1])
    except json.JSONDecodeError as error:
        return None, f"verifier output is not JSON: {error}", duration_ms
    if not isinstance(parsed, dict):
        return None, "verifier output must be a JSON object", duration_ms
    results = cast(dict[str, object], parsed).get("results")
    if not isinstance(results, list):
        return None, "verifier output lacks a 'results' array", duration_ms

    outcomes: dict[str, ProtocolOutcome] = {}
    for raw_result in cast(list[object], results):
        if not isinstance(raw_result, dict):
            return None, "each verifier result must be an object", duration_ms
        result = cast(dict[str, object], raw_result)
        identifier = result.get("id")
        is_valid = result.get("valid")
        error_code = result.get("error_code")
        detail = result.get("detail")
        if not isinstance(identifier, str) or not isinstance(is_valid, bool):
            return None, "verifier result is missing 'id' or 'valid'", duration_ms
        if error_code is not None and not isinstance(error_code, str):
            return None, f"{identifier}: 'error_code' must be a string or null", duration_ms
        if identifier in outcomes:
            return None, f"{identifier}: duplicate result", duration_ms
        outcomes[identifier] = ProtocolOutcome(
            valid=is_valid,
            error_code=error_code or "",
            detail=detail if isinstance(detail, str) else "",
        )
    return outcomes, f"decoded {len(outcomes)} verdicts", duration_ms


def evaluate_protocol_lane(
    vectors: list[ProtocolVector],
    keyring: dict[str, str],
    required_languages: tuple[str, ...],
    tools: dict[str, str | None],
    timeout_seconds: int,
) -> list[VerificationResult]:
    """Verify every protocol vector in every language and cross-check agreement."""

    payload = protocol_batch_payload(vectors, keyring)
    batch_timeout = timeout_seconds * PROTOCOL_BATCH_TIMEOUT_MULTIPLIER
    decoded: dict[str, dict[str, ProtocolOutcome] | None] = {}
    batch_details: dict[str, str] = {}
    batch_durations: dict[str, int] = {}

    print(f"\n[protocol] batch verification of {len(vectors)} P1-P12 vectors")
    for language in required_languages:
        executable = tools[language]
        if executable is None:
            raise RuntimeError("missing tool escaped preflight validation")
        outcomes, detail, duration_ms = run_protocol_batch(
            language, executable, payload, batch_timeout
        )
        decoded[language] = outcomes
        batch_details[language] = detail
        batch_durations[language] = duration_ms
        marker = "ok" if outcomes is not None else "FAIL"
        print(f"  [{marker:4}] {language:10} {detail} ({duration_ms}ms)")

    results: list[VerificationResult] = []
    for vector in vectors:
        agreement: dict[str, tuple[bool, str]] = {}
        for language in required_languages:
            outcomes = decoded[language]
            duration_ms = batch_durations[language] // max(len(vectors), 1)
            if outcomes is None:
                results.append(
                    VerificationResult(
                        language=language,
                        lane="protocol",
                        vector_id=vector.identifier,
                        passed=False,
                        detail=f"verifier unavailable: {batch_details[language]}",
                        duration_ms=duration_ms,
                    )
                )
                continue
            outcome = outcomes.get(vector.identifier)
            if outcome is None:
                results.append(
                    VerificationResult(
                        language=language,
                        lane="protocol",
                        vector_id=vector.identifier,
                        passed=False,
                        detail="verifier returned no verdict for this vector",
                        duration_ms=duration_ms,
                    )
                )
                continue
            agreement[language] = (outcome.valid, outcome.error_code)
            expected_valid = vector.expected == "valid"
            matches = outcome.valid == expected_valid and (
                expected_valid or outcome.error_code == vector.expected_error
            )
            observed = "valid" if outcome.valid else outcome.error_code or "invalid"
            expected_label = "valid" if expected_valid else vector.expected_error
            results.append(
                VerificationResult(
                    language=language,
                    lane="protocol",
                    vector_id=vector.identifier,
                    passed=matches,
                    detail=f"observed={observed}, expected={expected_label}",
                    duration_ms=duration_ms,
                )
            )

        distinct = sorted({verdict for verdict in agreement.values()})
        consistent = len(agreement) == len(required_languages) and len(distinct) == 1
        if consistent:
            detail = f"all {len(required_languages)} implementations agree"
        elif len(agreement) != len(required_languages):
            missing = sorted(set(required_languages) - set(agreement))
            detail = "no verdict from: " + ", ".join(missing)
        else:
            detail = "divergent verdicts: " + "; ".join(
                f"{language}={'valid' if verdict[0] else verdict[1] or 'invalid'}"
                for language, verdict in sorted(agreement.items())
            )
        results.append(
            VerificationResult(
                language="cross-language",
                lane="protocol",
                vector_id=vector.identifier,
                passed=consistent,
                detail=detail,
                duration_ms=0,
            )
        )

    failures = [result for result in results if not result.passed]
    for result in failures:
        print(f"  [FAIL] {result.language:14} {result.vector_id}: {result.detail}")
    print(
        f"  protocol lane: {len(results) - len(failures)}/{len(results)} "
        f"checks passed across {len(required_languages)} implementations"
    )
    return results


def resolve_tool(language: str) -> str | None:
    """Resolve the executable for a conformance language."""

    if language == "python":
        return sys.executable
    return shutil.which({"rust": "cargo", "go": "go", "typescript": "node"}[language])


def execute(
    command: list[str],
    *,
    cwd: Path,
    input_bytes: bytes,
    timeout_seconds: int,
    environment: dict[str, str] | None = None,
) -> tuple[bool, str, int]:
    """Execute one verifier and normalize its result."""

    started = datetime.now(UTC)
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env={**os.environ, **(environment or {})},
        )
    except subprocess.TimeoutExpired:
        duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
        return False, f"timed out after {timeout_seconds}s", duration_ms

    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    output = (
        (completed.stdout + completed.stderr).decode("utf-8", errors="replace").strip()
    )
    detail = output.splitlines()[-1] if output else f"exit code {completed.returncode}"
    return completed.returncode == 0, detail, duration_ms


def verify_rust(
    vector: Vector, cargo: str, timeout_seconds: int
) -> tuple[bool, str, int]:
    """Verify one vector with the authoritative Rust implementation."""

    if vector.lane == "signature":
        payload = bytes.fromhex(
            required_string(vector.content, "payload_hex", vector.path)
        )
        expected = required_string(vector.content, "expected", vector.path)
        command = [
            cargo,
            "run",
            "-q",
            "-p",
            "warrantor-trust-core",
            "--bin",
            "trust-core",
            "--",
            "verify",
            "--key",
            required_string(vector.content, "verifying_key_hex", vector.path),
            "--signature",
            required_string(vector.content, "signature_hex", vector.path),
        ]
        valid, _detail, duration_ms = execute(
            command,
            cwd=REPOSITORY_ROOT / "rust",
            input_bytes=payload,
            timeout_seconds=timeout_seconds,
        )
        matches_expectation = valid if expected == "valid" else not valid
        return matches_expectation, f"valid={valid}, expected={expected}", duration_ms

    leaves = required_string_list(vector.content, "leaves_hex", vector.path)
    command = [
        cargo,
        "run",
        "-q",
        "-p",
        "warrantor-trust-core",
        "--example",
        "merkle_vector",
        "--",
        json.dumps(leaves, separators=(",", ":")),
    ]
    passed, detail, duration_ms = execute(
        command,
        cwd=REPOSITORY_ROOT / "rust",
        input_bytes=b"",
        timeout_seconds=timeout_seconds,
    )
    if not passed:
        return False, detail, duration_ms
    try:
        parsed: object = json.loads(detail)
        if not isinstance(parsed, dict):
            raise ValueError("Rust output was not an object")
        root = parsed.get("root_hex")
    except (json.JSONDecodeError, ValueError) as error:
        return False, f"invalid Rust output: {error}", duration_ms
    expected_root = required_string(vector.content, "expected_root_hex", vector.path)
    return (
        root == expected_root,
        f"computed={root}, expected={expected_root}",
        duration_ms,
    )


def verify_external(
    vector: Vector,
    language: str,
    executable: str,
    timeout_seconds: int,
) -> tuple[bool, str, int]:
    """Verify a vector with Python, Go, or TypeScript."""

    if language == "python":
        script = (
            "verify_python.py"
            if vector.lane == "signature"
            else "verify_merkle_python.py"
        )
        command = [executable, str(Path(__file__).with_name(script))]
    elif language == "go":
        script = "verify_go.go" if vector.lane == "signature" else "verify_merkle_go.go"
        command = [executable, "run", str(Path(__file__).with_name(script))]
    else:
        command = [executable, str(Path(__file__).with_name("verify_typescript.ts"))]
    environment = None
    if language == "go":
        environment = {
            "GOCACHE": str(Path(tempfile.gettempdir()) / "warrantor-conformance-go-build")
        }
    return execute(
        command,
        cwd=REPOSITORY_ROOT,
        input_bytes=vector.raw,
        timeout_seconds=timeout_seconds,
        environment=environment,
    )


def write_report(
    report_path: Path,
    required_languages: tuple[str, ...],
    vectors: list[Vector],
    protocol_vectors: list[ProtocolVector],
    results: list[VerificationResult],
) -> None:
    """Write machine-readable conformance evidence."""

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 2,
        "generated_at": datetime.now(UTC).isoformat(),
        "required_languages": list(required_languages),
        "vector_count": len(vectors) + len(protocol_vectors),
        "t1_vector_count": len(vectors),
        "protocol_vector_count": len(protocol_vectors),
        "verification_count": len(results),
        "passed": all(result.passed for result in results),
        "results": [asdict(result) for result in results],
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    """Run the complete strict conformance matrix."""

    arguments = parse_arguments()
    if arguments.timeout <= 0:
        print("conformance: --timeout must be greater than zero", file=sys.stderr)
        return 2

    required_languages = tuple(
        language.strip()
        for language in arguments.require.split(",")
        if language.strip()
    )
    if not required_languages:
        print("conformance: at least one language is required", file=sys.stderr)
        return 2
    unsupported = sorted(set(required_languages) - set(SUPPORTED_LANGUAGES))
    if unsupported:
        print(
            f"conformance: unsupported languages: {', '.join(unsupported)}",
            file=sys.stderr,
        )
        return 2

    try:
        vectors = load_vectors()
        protocol_vectors, protocol_keyring = load_protocol_vectors()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"conformance: vector validation failed: {error}", file=sys.stderr)
        return 2

    tools = {language: resolve_tool(language) for language in required_languages}
    missing_tools = [
        language for language, executable in tools.items() if executable is None
    ]
    if missing_tools:
        print(
            "conformance: required toolchains unavailable: " + ", ".join(missing_tools),
            file=sys.stderr,
        )
        return 2

    print("AumOS strict cross-language conformance")
    print(f"  required: {', '.join(required_languages)}")
    print(f"  vectors:  {len(vectors)} T1 + {len(protocol_vectors)} protocol (P1-P12)")
    results: list[VerificationResult] = []
    for vector in vectors:
        print(f"\n[{vector.lane}] {vector.identifier}")
        for language in required_languages:
            executable = tools[language]
            if executable is None:
                raise RuntimeError("missing tool escaped preflight validation")
            if language == "rust":
                passed, detail, duration_ms = verify_rust(
                    vector, executable, arguments.timeout
                )
            else:
                passed, detail, duration_ms = verify_external(
                    vector, language, executable, arguments.timeout
                )
            results.append(
                VerificationResult(
                    language=language,
                    lane=vector.lane,
                    vector_id=vector.identifier,
                    passed=passed,
                    detail=detail,
                    duration_ms=duration_ms,
                )
            )
            marker = "ok" if passed else "FAIL"
            print(f"  [{marker:4}] {language:10} {detail}")

    results.extend(
        evaluate_protocol_lane(
            protocol_vectors,
            protocol_keyring,
            required_languages,
            tools,
            arguments.timeout,
        )
    )

    # Every T1 vector runs in every language; every protocol vector runs in
    # every language plus one cross-language agreement check.
    expected_verifications = len(vectors) * len(required_languages) + len(protocol_vectors) * (
        len(required_languages) + 1
    )
    passed = len(results) == expected_verifications and all(
        result.passed for result in results
    )
    print(
        f"\nRESULT: {'PASS' if passed else 'FAIL'} — "
        f"{sum(result.passed for result in results)}/{expected_verifications} verifications passed"
    )

    if arguments.report is not None:
        write_report(
            arguments.report, required_languages, vectors, protocol_vectors, results
        )
        print(f"  evidence: {arguments.report}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
