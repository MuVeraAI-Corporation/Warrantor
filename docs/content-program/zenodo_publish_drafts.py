#!/usr/bin/env python3
"""Publish EXISTING Zenodo drafts by id. Irreversible.

⚠️ WHY THIS EXISTS AND `zenodo_deposit.py --publish` DOES NOT DO IT. That script's `deposit()`
creates a NEW deposition on every call -- `POST /deposit/depositions` -- and then optionally
publishes the thing it just made. Run with `--publish` after drafts already exist, it would create
six MORE records, publish those, and leave the six reviewed drafts sitting unpublished and
orphaned. The reviewed artifact and the published artifact would be different objects.

So publishing takes ids. Each one is re-verified against the PDF on disk immediately before the
irreversible call: file size, licence, community, ORCID, and that the record is still unsubmitted.
A mismatch aborts that paper and does not stop the others.

**A published Zenodo record can never be deleted, only tombstoned.** There is no undo below this
line. Requires `--yes-publish` as well as the ids, so a stray run cannot mint DOIs.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time

import requests

API = "https://zenodo.org/api"

#: The drafts created 2026-09-02, tag -> deposition id.
DRAFTS = {
    "P1": 22258095,
    "P8": 22258102,
    "T04": 22258108,
    "T12": 22258111,
    "P3": 22258117,
    "P6": 22258119,
}


def _token() -> str:
    tok = os.environ.get("ZENODO_TOKEN", "").strip()
    if not tok:
        raise SystemExit("ZENODO_TOKEN is not set.")
    return tok


def _request(method, url, token, **kw):
    headers = dict(kw.pop("headers", {}))
    headers["Authorization"] = f"Bearer {token}"
    for attempt in range(4):
        try:
            r = requests.request(method, url, headers=headers, timeout=120, **kw)
            if r.status_code < 500:
                return r
            print(f"      {r.status_code} from Zenodo, retrying")
        except requests.RequestException as exc:
            print(f"      {type(exc).__name__}, retrying")
        time.sleep(5 * (attempt + 1))
    raise SystemExit(f"giving up on {method} {url}")


def verify(dep: dict, expect_size: int) -> list[str]:
    """Everything that must hold before an irreversible publish."""
    m = dep.get("metadata", {})
    files = dep.get("files", [])
    problems = []
    if dep.get("state") != "unsubmitted":
        problems.append(f"state is {dep.get('state')!r}, expected 'unsubmitted'")
    if len(files) != 1:
        problems.append(f"{len(files)} files attached, expected 1")
    elif files[0].get("filesize") != expect_size:
        problems.append(f"file is {files[0].get('filesize')}B, PDF on disk is {expect_size}B")
    if m.get("license") != "cc-by-4.0":
        problems.append(f"licence is {m.get('license')!r}")
    if m.get("communities") != [{"identifier": "warrantor"}]:
        problems.append(f"communities is {m.get('communities')!r}")
    creators = m.get("creators") or [{}]
    if creators[0].get("orcid") != "0009-0004-3959-6099":
        problems.append(f"ORCID is {creators[0].get('orcid')!r}")
    if not m.get("title"):
        problems.append("no title")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default="zenodo-depositions.json")
    ap.add_argument("--only", help="comma-separated tags")
    ap.add_argument("--yes-publish", action="store_true",
                    help="REQUIRED. Mints permanent DOIs. A published record cannot be deleted.")
    a = ap.parse_args(argv)

    token = _token()
    sizes = {d["tag"]: os.path.getsize(d["file"])
             for d in json.load(io.open(a.manifest, encoding="utf-8"))}
    tags = list(DRAFTS)
    if a.only:
        want = {t.strip() for t in a.only.split(",")}
        tags = [t for t in tags if t in want]

    if not a.yes_publish:
        print("DRY RUN -- verifying only. Pass --yes-publish to mint DOIs.\n")

    published, failed = [], []
    for tag in tags:
        dep_id = DRAFTS[tag]
        r = _request("GET", f"{API}/deposit/depositions/{dep_id}", token)
        if r.status_code != 200:
            print(f"  {tag}: cannot read draft {dep_id} ({r.status_code})")
            failed.append(tag)
            continue
        dep = r.json()
        problems = verify(dep, sizes[tag])
        if problems:
            print(f"  {tag}: NOT PUBLISHED -- {len(problems)} problem(s)")
            for p in problems:
                print(f"      - {p}")
            failed.append(tag)
            continue
        if not a.yes_publish:
            print(f"  {tag}: verified, ready ({dep_id})")
            continue
        r = _request("POST", f"{API}/deposit/depositions/{dep_id}/actions/publish", token)
        if r.status_code not in (200, 202):
            print(f"  {tag}: publish FAILED {r.status_code} {r.text[:200]}")
            failed.append(tag)
            continue
        out = r.json()
        doi = out.get("doi") or (out.get("metadata") or {}).get("doi")
        print(f"  {tag}: PUBLISHED  doi={doi}  https://doi.org/{doi}")
        published.append((tag, doi, out.get("links", {}).get("record_html")))

    print()
    if a.yes_publish:
        print(f"published {len(published)}/{len(tags)}")
        if published:
            io.open("zenodo-published.json", "w", encoding="utf-8", newline="\n").write(
                json.dumps([{"tag": t, "doi": d, "url": u} for t, d, u in published], indent=1))
            print("wrote zenodo-published.json")
    if failed:
        print("FAILED:", ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
