#!/usr/bin/env python3
"""Assemble the publication set from the two build trees -- after verifying it.

WHY THIS EXISTS. The first publication set was assembled by hand: PDFs copied from tex-preprint/
and tex/ into published-<date>/<TAG>/ and renamed. Nothing checked them on the way. Six papers went
out with empty document properties, their own revision history in the body, a section headed
"strip before submission", and literal unfilled blanks -- and were rejected by a preprint server
for exactly those reasons. This script is the step that was missing: it runs the PDF-level
verifier first and copies nothing if any paper fails.

Layout produced, per paper:
    published-<date>/<TAG>/<TAG>-named.pdf   the named preprint -- deposit this
    published-<date>/<TAG>/<TAG>-named.tex   its LaTeX source (needs ../preamble-preprint.tex)
    published-<date>/<TAG>/<TAG>-anon.pdf    the double-blind build, where one exists -- venue only
    published-<date>/<TAG>/<source>.md       the markdown both builds are generated from
    published-<date>/preamble-preprint.tex

Usage:  python publish.py [--date 2026-09-01]
        The date defaults to today's; pass the existing folder's date to refresh it in place.
"""
from __future__ import annotations

import argparse
import datetime as dt
import io
import os
import shutil
import subprocess
import sys

D = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(D)
sys.path.insert(0, D)
from build_preprint import PAPERS  # noqa: E402  -- the publication set, defined once


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", default=dt.date.today().isoformat())
    a = ap.parse_args(argv)

    print("verifying the built PDFs before copying anything")
    rc = subprocess.run([sys.executable, os.path.join(D, "verify_published.py")]).returncode
    if rc != 0:
        print("\nREFUSED: verification failed. Nothing was copied.")
        return rc

    out = os.path.join(ROOT, f"published-{a.date}")
    os.makedirs(out, exist_ok=True)
    shutil.copy2(os.path.join(D, "preamble-preprint.tex"), os.path.join(out, "preamble-preprint.tex"))

    print(f"\nassembling {os.path.relpath(out, ROOT)}/")
    for tag, source in PAPERS:
        dest = os.path.join(out, tag)
        os.makedirs(dest, exist_ok=True)
        named_pdf = os.path.join(D, "tex-preprint", f"{tag}.pdf")
        named_tex = os.path.join(D, "tex-preprint", f"{tag}.tex")
        anon_pdf = os.path.join(D, "tex", f"{tag}.pdf")
        if not os.path.exists(named_pdf):
            print(f"  {tag}: NAMED PDF MISSING -- build it first")
            return 1
        shutil.copy2(named_pdf, os.path.join(dest, f"{tag}-named.pdf"))
        shutil.copy2(named_tex, os.path.join(dest, f"{tag}-named.tex"))
        shutil.copy2(os.path.join(ROOT, "drafts", source), os.path.join(dest, source))
        line = f"  {tag}: named"
        if os.path.exists(anon_pdf):
            shutil.copy2(anon_pdf, os.path.join(dest, f"{tag}-anon.pdf"))
            line += " + anon"
        else:
            stale = os.path.join(dest, f"{tag}-anon.pdf")
            if os.path.exists(stale):
                # A leftover anon PDF from a paper that no longer has an anonymous build would
                # ship silently. Say so rather than remove it: deletion is a human decision.
                line += f"   WARNING: stale {os.path.basename(stale)} present, no anon build exists"
        print(line)
    print("\nDone. README.md in that folder is maintained by hand; update its page counts and notes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
