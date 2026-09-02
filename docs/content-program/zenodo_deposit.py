"""Create Zenodo depositions for the published paper set.

# Why this defaults to a DRAFT

Publishing on Zenodo mints a DOI, and **a published record cannot be deleted** -- Zenodo will
only ever tombstone it. That makes publication the one genuinely irreversible step in this
pipeline, so it is not the default and it is not bundled with upload. This script creates the
drafts, attaches the PDFs and writes the metadata; a human opens each draft, reads it, and presses
Publish.

`--publish` exists for when that review has already happened. It is deliberately a separate run.

# Credentials

Reads `ZENODO_TOKEN` from the environment and never takes it as an argument, so the token does not
land in shell history or in this file. Create one at https://zenodo.org/account/settings/
applications/tokens/new with the `deposit:write` and `deposit:actions` scopes, then put it in your
shell profile:

    export ZENODO_TOKEN="..."

`--sandbox` targets sandbox.zenodo.org, which mints throwaway DOIs against a separate account and
is the right place to check the metadata renders before touching the real thing.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time

import requests

LIVE = "https://zenodo.org/api"
SANDBOX = "https://sandbox.zenodo.org/api"


def _token() -> str:
    tok = os.environ.get("ZENODO_TOKEN", "").strip()
    if not tok:
        raise SystemExit(
            "ZENODO_TOKEN is not set.\n"
            "  Create one: https://zenodo.org/account/settings/applications/tokens/new\n"
            "  Scopes needed: deposit:write, deposit:actions\n"
            "  Then: export ZENODO_TOKEN=\"...\"  (put it in your shell profile so it persists)"
        )
    return tok


def _request(method, url, token, **kw):
    """One retry loop for every call. Zenodo rate-limits and occasionally resets a connection."""
    for attempt in range(4):
        try:
            r = requests.request(
                method, url, params={"access_token": token}, timeout=120, **kw
            )
            if r.status_code < 500:
                return r
            print(f"    {r.status_code} from Zenodo, retrying")
        except requests.RequestException as exc:
            print(f"    {type(exc).__name__}, retrying")
        time.sleep(5 * (attempt + 1))
    raise SystemExit(f"giving up on {method} {url}")


def deposit(entry, token, api, publish=False):
    tag, meta, path = entry["tag"], entry["metadata"], entry["file"]
    if not os.path.exists(path):
        print(f"  {tag}: PDF missing at {path} -- skipped")
        return None

    r = _request("POST", f"{api}/deposit/depositions", token, json={})
    if r.status_code not in (200, 201):
        print(f"  {tag}: create failed {r.status_code} {r.text[:160]}")
        return None
    dep = r.json()
    dep_id, bucket = dep["id"], dep["links"]["bucket"]

    with io.open(path, "rb") as fh:
        r = _request("PUT", f"{bucket}/{os.path.basename(path)}", token, data=fh)
    if r.status_code not in (200, 201):
        print(f"  {tag}: upload failed {r.status_code} {r.text[:160]}")
        return None

    r = _request(
        "PUT", f"{api}/deposit/depositions/{dep_id}", token, json={"metadata": meta}
    )
    if r.status_code != 200:
        print(f"  {tag}: metadata failed {r.status_code} {r.text[:200]}")
        return None

    state = "draft"
    if publish:
        r = _request("POST", f"{api}/deposit/depositions/{dep_id}/actions/publish", token)
        if r.status_code not in (200, 202):
            print(f"  {tag}: publish failed {r.status_code} {r.text[:160]}")
            return None
        state = "PUBLISHED"

    doi = r.json().get("doi") or dep.get("metadata", {}).get("prereserve_doi", {}).get("doi")
    url = f"{api.replace('/api','')}/deposit/{dep_id}"
    print(f"  {tag}: {state}  id={dep_id}  doi={doi or '(reserved on publish)'}")
    print(f"       {url}")
    return {"tag": tag, "id": dep_id, "state": state, "doi": doi, "url": url}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default="zenodo-depositions.json")
    ap.add_argument("--sandbox", action="store_true", help="target sandbox.zenodo.org")
    ap.add_argument(
        "--publish",
        action="store_true",
        help="PUBLISH, minting permanent DOIs. A published Zenodo record cannot be deleted.",
    )
    ap.add_argument("--only", help="comma-separated tags, e.g. P1,T04")
    a = ap.parse_args(argv)

    api = SANDBOX if a.sandbox else LIVE
    token = _token()
    entries = json.load(io.open(a.manifest, encoding="utf-8"))
    if a.only:
        want = {t.strip() for t in a.only.split(",")}
        entries = [e for e in entries if e["tag"] in want]

    if a.publish and not a.sandbox:
        print("PUBLISHING to live Zenodo. Records cannot be deleted once published.")

    print(f"{'publishing' if a.publish else 'creating drafts'} on {api} ({len(entries)} papers)")
    out = [deposit(e, token, api, a.publish) for e in entries]
    out = [o for o in out if o]
    print(f"\n{len(out)}/{len(entries)} ok")
    if out and not a.publish:
        print("Review each draft in the browser, then publish there, or re-run with --publish.")
    return 0 if len(out) == len(entries) else 1


if __name__ == "__main__":
    sys.exit(main())
