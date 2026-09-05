#!/usr/bin/env python3
"""Stage a NEW VERSION of each published Zenodo record, as a draft. Never publishes.

WHY A SEPARATE SCRIPT. `zenodo_deposit.py` creates new records and `zenodo_publish_drafts.py`
publishes existing drafts by id. Revising a published paper is neither: Zenodo's versioning
keeps the concept DOI stable and mints a new version DOI under it, which is the property the
papers' face DOI depends on (build_preprint.CONCEPT_DOI). A new record would orphan that.

WHAT IT DOES, per paper, for a version DOI in zenodo-published.json:
  1. POST /deposit/depositions/{id}/actions/newversion  -> a draft that inherits metadata + files
  2. delete every inherited file from the draft
  3. upload the rebuilt PDF
  4. PUT metadata with `version` set and the description prefixed by the change note
  5. STOP. The draft is left unpublished for a human to open and read.

Publishing is done by a person in the browser, or by `zenodo_publish_drafts.py` once the new
draft ids are placed in its DRAFTS table -- the same two-step discipline as the first version.

Requires --yes-create so a dry run is the default. Reads ZENODO_TOKEN from the environment
(`deposit:write` + `deposit:actions`); never takes it as an argument.
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
D = os.path.dirname(os.path.abspath(__file__))

VERSION = "3"
CHANGE_NOTE = {
    "P1": ("Version 3 (2026-09-05): reports the per-item structure of the two unstable items -- they "
           "flip together, in the same four of eighteen runs, and every flip crosses the Safe/Controversial "
           "boundary; adds the Wilson interval on the floor, the companion floor on a second corpus, the "
           "serving-stack disclosure, and the Artifact section and prior-art scope note that the first "
           "two versions omitted."),
    "P3": ("Version 3 (2026-09-05): adds paired matched-cell and payload-level tests (30 of 30 discordant "
           "cells fall the same way in the 4B), risk-ratio intervals, the 0.6B per-length table with its one "
           "exception, the P3-X payload-level unit and its non-significant 4B steps; corrects a novelty "
           "claim that contradicted the note's replication framing."),
    "P8": ("Version 3 (2026-09-05): defines the decision margin of Sec. 5.8, cites the companion floor by "
           "DOI, and corrects a miscounted contribution list, three references to a nonexistent Sec. 0 and "
           "one wrong cross-reference."),
    "T04": ("Version 3 (2026-09-05): folds in the pre-registered follow-up T04-X2 (two scales, different "
            "corpus and stack; all 111 moved verdicts Unsafe->Safe), the format-acquisition failure mode "
            "found on the way to it, the adapter hyperparameters, the gate's comparator, a third masked run "
            "with retained outputs, and corrects which run the ablation control reproduces."),
    "T12": ("Version 3 (2026-09-05): the fifteenth scored work, AIP, had been mislabeled as the authors' "
            "own system in six table cells and one sentence; corrected, with its coder disagreement added to "
            "the composition-count robustness table. Method section brought into line with the reported "
            "screening; AgentThread given its reference entry; contribution 6 restated as the prediction "
            "the paper actually publishes."),
    "P6": ("Version 3 (2026-09-05): states the strata of the difficulty control and which test each of the "
           "three survivor counts comes from; corrects a reference to a nonexistent Sec. 0."),
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--published", default=os.path.join(D, "zenodo-published.json"))
    ap.add_argument("--folder", required=True, help="published-<date> folder holding <TAG>/<TAG>-named.pdf")
    ap.add_argument("--only", help="comma-separated tags")
    ap.add_argument("--yes-create", action="store_true", help="actually create the drafts")
    a = ap.parse_args(argv)

    published = json.load(io.open(a.published, encoding="utf-8"))
    tags = [p["tag"] for p in published]
    if a.only:
        want = {t.strip() for t in a.only.split(",")}
        tags = [t for t in tags if t in want]
    ids = {p["tag"]: int(p["doi"].rsplit(".", 1)[1]) for p in published}

    for tag in tags:
        pdf = os.path.join(a.folder, tag, f"{tag}-named.pdf")
        if not os.path.exists(pdf):
            raise SystemExit(f"{tag}: {pdf} does not exist -- build and publish.py first")
        if tag not in CHANGE_NOTE:
            raise SystemExit(f"{tag}: no change note written -- a version without one is not stageable")

    if not a.yes_create:
        print("DRY RUN. Would stage new-version drafts for: " + ", ".join(tags))
        for tag in tags:
            print(f"  {tag}: record {ids[tag]} <- {os.path.relpath(os.path.join(a.folder, tag, tag + '-named.pdf'), D)}")
        print("Pass --yes-create to create the drafts (nothing is published).")
        return 0

    token = _token()
    staged = []
    for tag in tags:
        rec_id = ids[tag]
        r = _request("POST", f"{API}/deposit/depositions/{rec_id}/actions/newversion", token)
        if r.status_code not in (200, 201):
            print(f"  {tag}: newversion failed {r.status_code} {r.text[:200]}")
            continue
        draft_url = r.json()["links"]["latest_draft"]
        draft = _request("GET", draft_url, token).json()
        draft_id, bucket = draft["id"], draft["links"]["bucket"]
        for f in draft.get("files", []):
            _request("DELETE", f"{API}/deposit/depositions/{draft_id}/files/{f['id']}", token)
        pdf = os.path.join(a.folder, tag, f"{tag}-named.pdf")
        with io.open(pdf, "rb") as fh:
            up = _request("PUT", f"{bucket}/{tag}-named.pdf", token, data=fh)
        if up.status_code not in (200, 201):
            print(f"  {tag}: upload failed {up.status_code} {up.text[:200]}")
            continue
        meta = draft["metadata"]
        meta["version"] = VERSION
        meta["publication_date"] = time.strftime("%Y-%m-%d")
        # ⚠️ The new-version draft inherits title, creators, licence and description from the
        # published record but NOT its community: on 2026-09-05 all six drafts came back with
        # `communities: None` and had to be patched afterwards. Set it explicitly every time.
        meta["communities"] = [{"identifier": "warrantor"}]
        desc = meta.get("description", "")
        if not desc.startswith("Version 3"):
            meta["description"] = CHANGE_NOTE[tag] + "\n\n" + desc
        put = _request("PUT", f"{API}/deposit/depositions/{draft_id}", token, json={"metadata": meta})
        if put.status_code != 200:
            print(f"  {tag}: metadata failed {put.status_code} {put.text[:200]}")
            continue
        print(f"  {tag}: DRAFT v{VERSION} staged  id={draft_id}  https://zenodo.org/deposit/{draft_id}")
        staged.append({"tag": tag, "draft_id": draft_id, "from": rec_id})

    out = os.path.join(D, "zenodo-v3-drafts.json")
    io.open(out, "w", encoding="utf-8", newline="\n").write(json.dumps(staged, indent=1))
    print(f"\nstaged {len(staged)}/{len(tags)}; wrote {os.path.relpath(out, D)}. Nothing published.")
    return 0 if len(staged) == len(tags) else 1


if __name__ == "__main__":
    sys.exit(main())
