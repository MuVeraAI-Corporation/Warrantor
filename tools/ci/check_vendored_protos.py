#!/usr/bin/env python3
"""Fail if the protos vendored into `warrantor-api` have drifted from `<repo>/proto/`.

Why this exists
---------------

`rust/warrantor-api/build.rs` regenerates Rust types from the protobuf definitions on every
build, which is what keeps the Rust types from drifting away from the wire format. In a
workspace checkout those definitions live at ``<repo>/proto/``.

`cargo package`, however, copies only files *inside* the crate directory into the tarball. A
crate whose build script reaches two levels up finds nothing there, fails verification with
``Could not make proto path relative``, and cannot be published at all. That is not a
hypothetical: it is what the first real publish attempt hit.

So the protos are vendored into ``rust/warrantor-api/proto/`` and shipped with the crate.
Two copies of anything will drift, and this one would drift silently — the workspace build
prefers the vendored copy, so a change to ``<repo>/proto/`` alone would be *ignored* rather
than producing an error. The published crate would then encode a wire format that no other
language in this repository speaks.

Duplication is the right trade here (the alternative is an unpublishable crate), but it has
to be enforced by something that fails loudly rather than by remembering.

Exit codes: 0 in sync, 1 drifted or missing.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CANONICAL = REPO_ROOT / "proto"
VENDORED = REPO_ROOT / "rust" / "warrantor-api" / "proto"


def digest(path: pathlib.Path) -> str:
    """Content hash, newline-normalised.

    Git may check out CRLF on Windows and LF elsewhere; a line-ending difference is not drift
    and failing CI over it would train people to ignore this check.
    """
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    if not VENDORED.is_dir():
        print(f"error: no vendored protos at {VENDORED}", file=sys.stderr)
        print("       warrantor-api cannot be published without them.", file=sys.stderr)
        return 1

    problems: list[str] = []
    checked = 0

    for vendored_file in sorted(VENDORED.rglob("*.proto")):
        relative = vendored_file.relative_to(VENDORED)
        canonical_file = CANONICAL / relative
        checked += 1

        if not canonical_file.exists():
            problems.append(
                f"  {relative}: vendored in warrantor-api but absent from proto/ — "
                f"either it was deleted upstream, or it was never canonical"
            )
            continue

        if digest(vendored_file) != digest(canonical_file):
            problems.append(
                f"  {relative}: DRIFTED from proto/{relative}. "
                f"The workspace build prefers the vendored copy, so this difference is "
                f"currently being used and silently ignored."
            )

    if problems:
        print("Vendored protos are out of sync with proto/:\n", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        print(
            "\nFix by re-copying the canonical files:\n"
            "  python tools/ci/check_vendored_protos.py --sync\n",
            file=sys.stderr,
        )
        return 1

    print(f"vendored protos in sync with proto/ ({checked} files)")
    return 0


def sync() -> int:
    """Re-copy the canonical protos over the vendored ones."""
    import shutil

    copied = 0
    for vendored_file in sorted(VENDORED.rglob("*.proto")):
        relative = vendored_file.relative_to(VENDORED)
        canonical_file = CANONICAL / relative
        if canonical_file.exists():
            shutil.copy2(canonical_file, vendored_file)
            copied += 1
    print(f"re-synced {copied} proto files from proto/")
    return 0


if __name__ == "__main__":
    sys.exit(sync() if "--sync" in sys.argv else main())
