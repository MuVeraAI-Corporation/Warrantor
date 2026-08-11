#!/usr/bin/env python3
"""R1: does a frontier model cope with tools that return STAGED handles?

# Why this exists

The warrant design defers irreversible effects instead of performing them: an agent that asks to
open a pull request gets back ``{"staged": true, "handle": "pr://staged/<warrant>/1"}`` rather than
a real PR number, and the real call happens only when a human settles the warrant.

That is the single largest unknown in the design. If models cannot work with a handle that stands
for a thing that does not exist yet -- if they stall, or invent a plausible-looking real id, or
re-issue the same call hoping for a different answer -- then staging cannot be the primary path and
the escape hatch becomes the design instead. Nine weeks of work depend on the answer, so it is
worth one day of measurement.

# Why the tool logs rather than the agent reporting

An agent asked "did you chain correctly?" will say yes. This CLI records every invocation and every
argument to a JSONL file, so chaining is established from what the agent *did*, not what it says it
did. A hallucinated identifier is visible as an argument that never appeared in any prior response.

# Protocol

Every mutating call returns a staged handle. Handles are resolvable as arguments to later calls,
exactly as the real proxy will resolve them. ``get_pr_status`` is deliberately included as a read
that works on a staged handle, because an agent that cannot inspect what it staged will stall.

Usage (as the agent sees it):
    r1_staged_tools.py create_pr      --title T --body B
    r1_staged_tools.py comment        --target HANDLE --body B
    r1_staged_tools.py request_review --target HANDLE --reviewer R
    r1_staged_tools.py get_pr_status  --target HANDLE
    r1_staged_tools.py add_label      --target HANDLE --label L
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from typing import Any

#: Where invocations are recorded. Set per-trial so parallel trials do not interleave.
LOG_ENV = "R1_LOG"
#: Warrant id woven into handles, so a handle from one trial is obviously foreign in another.
WARRANT_ENV = "R1_WARRANT"


def _log_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get(LOG_ENV, "r1-trial.jsonl"))


def _warrant() -> str:
    return os.environ.get(WARRANT_ENV, "wrt_r1trial")


def _record(entry: dict[str, Any]) -> None:
    path = _log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def _next_index() -> int:
    """Handles are numbered per warrant in issue order, as the real staging queue will be."""
    path = _log_path()
    if not path.exists():
        return 1
    issued = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            if json.loads(line).get("staged"):
                issued += 1
        except json.JSONDecodeError:
            continue
    return issued + 1


#: Each tool mints a handle in its OWN scheme.
#:
#: R1 surfaced this: with every effect minting a `pr://` handle from one counter, `add_label`
#: returned a `pr://` URI that was not a pull request. An agent that reflexively threaded the most
#: recent handle forward would have requested review ON THE LABEL and received a successful staged
#: result, because handle lookup accepted any issued handle regardless of type. The log's
#: hallucination check could not see it either -- it only catches identifiers that were never
#: issued, not well-formed ones pointing at the wrong kind of object.
HANDLE_SCHEME = {
    "create_pr": "pr",
    "comment": "comment",
    "request_review": "review",
    "add_label": "label",
}

#: Which handle types each tool will accept as --target.
TARGET_TYPES = {
    "comment": {"pr"},
    "request_review": {"pr"},
    "add_label": {"pr"},
    "get_pr_status": {"pr"},
}


def _handle_type(handle: str) -> str:
    return handle.split("://", 1)[0] if "://" in handle else ""


def _stage(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    index = _next_index()
    handle = f"{HANDLE_SCHEME[tool]}://staged/{_warrant()}/{index}"
    result = {
        "staged": True,
        "handle": handle,
        "tool": tool,
        "note": (
            "This effect is queued and will be performed when the warrant is settled. "
            "Use the handle above to refer to it in later calls."
        ),
    }
    _record({"tool": tool, "args": args, "staged": True, "handle": handle})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Staged-effect tools (R1 experiment).")
    sub = parser.add_subparsers(dest="tool", required=True)

    create = sub.add_parser("create_pr", help="Open a pull request (staged).")
    create.add_argument("--title", required=True)
    create.add_argument("--body", default="")

    comment = sub.add_parser("comment", help="Comment on a pull request (staged).")
    comment.add_argument("--target", required=True, help="A pr:// handle.")
    comment.add_argument("--body", required=True)

    review = sub.add_parser("request_review", help="Request review (staged).")
    review.add_argument("--target", required=True)
    review.add_argument("--reviewer", required=True)

    label = sub.add_parser("add_label", help="Add a label (staged).")
    label.add_argument("--target", required=True)
    label.add_argument("--label", required=True)

    status = sub.add_parser("get_pr_status", help="Read the status of a staged PR.")
    status.add_argument("--target", required=True)

    args = parser.parse_args()
    payload = {k: v for k, v in vars(args).items() if k != "tool"}

    if args.tool == "get_pr_status":
        # A read against a staged effect. Answering honestly -- it exists, it is not live yet --
        # is what lets an agent make progress without inventing a real identifier.
        known = _known_handles()
        if args.target not in known:
            _record({"tool": args.tool, "args": payload, "error": "unknown_handle"})
            print(
                json.dumps(
                    {
                        "error": "unknown handle",
                        "detail": (
                            f"{args.target!r} was not issued by this warrant. Use a handle "
                            "returned by a previous call."
                        ),
                        "known_handles": known,
                    },
                    indent=2,
                )
            )
            return 1
        _record({"tool": args.tool, "args": payload, "staged": False})
        print(
            json.dumps(
                {
                    "handle": args.target,
                    "state": "staged",
                    "live": False,
                    "note": "Queued. It becomes a real pull request when the warrant is settled.",
                },
                indent=2,
            )
        )
        return 0

    if args.tool != "create_pr":
        known = _known_handles()
        # Reject a well-formed handle of the WRONG TYPE as firmly as an invented one: requesting
        # review on a label is a chaining failure, and silently accepting it would hide exactly
        # the mistake this experiment exists to measure.
        allowed = TARGET_TYPES.get(args.tool, set())
        if args.target in known and _handle_type(args.target) not in allowed:
            _record(
                {
                    "tool": args.tool,
                    "args": payload,
                    "error": "wrong_handle_type",
                    "wrong_type": True,
                }
            )
            print(
                json.dumps(
                    {
                        "error": "wrong handle type",
                        "detail": (
                            f"{args.target!r} is a {_handle_type(args.target)!r} handle; "
                            f"{args.tool} expects one of {sorted(allowed)}."
                        ),
                    },
                    indent=2,
                )
            )
            return 1
        if args.target not in known:
            # The critical measurement: an argument that was never issued is a hallucinated id.
            _record(
                {
                    "tool": args.tool,
                    "args": payload,
                    "error": "unknown_handle",
                    "hallucinated": True,
                }
            )
            print(
                json.dumps(
                    {
                        "error": "unknown handle",
                        "detail": (
                            f"{args.target!r} was not issued by this warrant. Refer to a handle "
                            "returned by an earlier call."
                        ),
                        "known_handles": known,
                    },
                    indent=2,
                )
            )
            return 1

    print(json.dumps(_stage(args.tool, payload), indent=2))
    return 0


def _known_handles() -> list[str]:
    path = _log_path()
    if not path.exists():
        return []
    handles = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("handle") and entry.get("staged"):
            handles.append(entry["handle"])
    return handles


if __name__ == "__main__":
    sys.exit(main())
