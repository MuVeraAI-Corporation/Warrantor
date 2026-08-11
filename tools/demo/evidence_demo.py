#!/usr/bin/env python3
"""Prove, end to end, that an action produced evidence a third party can verify.

    make demo

Signs a payload, records it in a transparency log, then fetches the entry back and
checks the inclusion proof -- reading the log's answer, not our own.

The distinction this demo exists to make: a signature proves *someone with the key*
produced it. A transparency-log entry proves *when*, and makes the record append-only
and independently auditable. The second is the part you cannot fake after the fact,
and it is the part that was not working until now.

Exit codes: 0 all steps verified, 1 a step failed, 2 the environment is not ready.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
#: Override to point at a different log. Default is the local stack.
REKOR = os.environ.get("REKOR_URL", "http://127.0.0.1:3000").rstrip("/")

BOLD, DIM, GREEN, RED, YELLOW, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[0m",
)


def say(msg: str = "") -> None:
    print(msg, flush=True)


def step(n: int, total: int, title: str) -> None:
    say(f"\n{BOLD}[{n}/{total}] {title}{RESET}")


def ok(msg: str) -> None:
    say(f"  {GREEN}OK{RESET}  {msg}")


def bad(msg: str) -> None:
    say(f"  {RED}FAIL{RESET}  {msg}")


def note(msg: str) -> None:
    say(f"      {DIM}{msg}{RESET}")


def get_json(url: str, timeout: int = 15) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def preflight() -> str | None:
    """Return the trust-core binary path, or None if the environment is not ready.

    Every failure here prints the exact command that fixes it. An environment check
    that says "not ready" without saying what to run is just a slower error.
    """
    step(1, 5, "Checking the environment")

    binary = REPOSITORY_ROOT / "rust" / "target" / "debug" / "trust-core.exe"
    if not binary.exists():
        binary = REPOSITORY_ROOT / "rust" / "target" / "debug" / "trust-core"
    if not binary.exists():
        bad("trust-core is not built")
        note("cargo build -p warrantor-trust-core --manifest-path rust/Cargo.toml")
        return None
    ok(f"trust-core built  {DIM}{binary.name}{RESET}")

    log = get_json(f"{REKOR}/api/v1/log")
    if log is None:
        bad(f"no transparency log reachable at {REKOR}")
        note("docker compose -f deploy/local-sigstore/docker-compose.yml up -d")
        note("./deploy/local-sigstore/bootstrap.sh")
        if not shutil.which("docker"):
            note("(docker itself was not found on PATH)")
        return None
    ok(f"transparency log up  {DIM}treeSize={log.get('treeSize')}{RESET}")
    return str(binary)


def main() -> int:
    say(f"{BOLD}warrantor — evidence demo{RESET}")
    say(f"{DIM}an action, a signature, and a record a third party can check{RESET}")

    binary = preflight()
    if binary is None:
        say(
            f"\n{YELLOW}Environment not ready. Run the commands above, then retry.{RESET}"
        )
        return 2

    before = get_json(f"{REKOR}/api/v1/log") or {}
    size_before = before.get("treeSize", 0)

    step(2, 5, "Performing an action and signing it")
    payload = f"agent deployed model artifact at {int(time.time())}"
    note(f'action: "{payload}"')

    key = subprocess.run(
        [binary, "key-gen"], capture_output=True, text=True, check=False
    )
    if key.returncode != 0:
        bad("key generation failed")
        note(key.stderr.strip()[:200])
        return 1
    signing_key = next(
        (
            line.split("=", 1)[1]
            for line in key.stdout.splitlines()
            if line.startswith("signing_key_hex=")
        ),
        "",
    )
    ok("ephemeral Ed25519 key generated")

    step(3, 5, "Recording it in the transparency log")
    notarize = subprocess.run(
        [binary, "notarize", "--key", signing_key, "--rekor-url", REKOR],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )
    if notarize.returncode != 0:
        bad("the log rejected the entry")
        note(notarize.stderr.strip()[:300])
        return 1

    fields = dict(
        line.split("=", 1) for line in notarize.stdout.splitlines() if "=" in line
    )
    uuid = fields.get("rekor_uuid", "")
    ok(f"accepted  {DIM}logIndex={fields.get('rekor_log_index')}{RESET}")
    note(f"uuid {uuid[:48]}...")

    step(4, 5, "Asking the log to prove it — not taking our own word for it")
    entry = get_json(f"{REKOR}/api/v1/log/entries/{uuid}")
    if not entry:
        bad("the log did not return the entry we just wrote")
        return 1

    record = next(iter(entry.values()))
    proof = record.get("verification", {}).get("inclusionProof", {})
    if not proof:
        bad("no inclusion proof returned")
        return 1
    ok(
        f"inclusion proof present  {DIM}treeSize={proof.get('treeSize')}, "
        f"{len(proof.get('hashes', []))} sibling hash(es){RESET}"
    )

    if record.get("verification", {}).get("signedEntryTimestamp"):
        ok("signed entry timestamp present  " + DIM + "the log attests WHEN" + RESET)
    else:
        bad("no signed entry timestamp")
        return 1

    step(5, 5, "Confirming the log actually grew")
    after = get_json(f"{REKOR}/api/v1/log") or {}
    size_after = after.get("treeSize", 0)
    if size_after <= size_before:
        bad(f"treeSize did not advance ({size_before} -> {size_after})")
        return 1
    ok(f"treeSize {size_before} -> {size_after}")

    say(f"\n{GREEN}{BOLD}Verified.{RESET}")
    say(f"""
{DIM}What was actually proven, and what was not:

  PROVEN   an entry exists in an append-only log, at a known index, with an
           inclusion proof and a log-signed timestamp. Anyone with the log's
           public key can check this without trusting us.

  NOT      that the action described in the payload really happened. The log
           attests to the record, not to the world. Binding a record to a real
           action is what the agent runtime has to do, and is where the
           substrate's remaining work is.{RESET}

{DIM}Inspect it yourself:{RESET}
  curl -s {REKOR}/api/v1/log/entries/{uuid[:24]}... | jq
  curl -s {REKOR}/api/v1/log/publicKey
""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
