#!/usr/bin/env python3
"""Build the flat LaTeX source archives -- one zip per paper -- and prove each one compiles.

WHY A SCRIPT. The first set of archives was produced by a snippet that lived only in a commit
message; the folder README said "regenerate with the snippet in the commit that added this
folder". A build step that has to be recovered from git history before it can be run is a build
step that will be done by hand the second time, and by-hand is how a stale preamble ships.

Each archive holds `<TAG>.tex` and `preamble-preprint.tex`, flat, with the tree's
`\\input{../preamble-preprint}` rewritten to `\\input{preamble-preprint}` IN THE COPY ONLY: a
submitted archive is extracted into an empty directory, where `../` resolves to nothing.

Every archive is then extracted into a scratch directory and compiled, and its page count is
compared with the published PDF's. A zip that does not compile, or compiles to a different
length, fails the run. Nothing here is copied anywhere on failure.

Usage:  python make_latex_zips.py --out ../published-<date>/latex-zips
        Requires latexmk on PATH or in the MiKTeX location below.
"""
from __future__ import annotations

import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

D = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, D)
from build_preprint import PAPERS  # noqa: E402
from verify_published import page_count  # noqa: E402

MIKTEX = os.path.expandvars(r"%LOCALAPPDATA%\Programs\MiKTeX\miktex\bin\x64")


def latexmk() -> str:
    return shutil.which("latexmk") or os.path.join(MIKTEX, "latexmk.exe")


def compile_check(zip_path: str, expect_pages: int, tag: str) -> str | None:
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(tmp)
        r = subprocess.run([latexmk(), "-pdf", "-interaction=nonstopmode", f"{tag}.tex"],
                           cwd=tmp, capture_output=True, text=True, timeout=600)
        pdf = os.path.join(tmp, f"{tag}.pdf")
        if r.returncode != 0 or not os.path.exists(pdf):
            return f"did not compile from the archive (latexmk exit {r.returncode})"
        got = page_count(pdf)
        if got != expect_pages:
            return f"archive compiles to {got} pages, published PDF has {expect_pages}"
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="destination folder for the zips")
    ap.add_argument("--no-compile", action="store_true", help="skip the compile proof (not for shipping)")
    a = ap.parse_args(argv)

    tree = os.path.join(D, "tex-preprint")
    preamble = os.path.join(D, "preamble-preprint.tex")
    os.makedirs(a.out, exist_ok=True)
    failures = 0
    lines = []
    for tag, _ in PAPERS:
        tex = io.open(os.path.join(tree, f"{tag}.tex"), encoding="utf-8").read()
        flat, n = re.subn(r"\\input\{\.\./preamble-preprint\}", r"\\input{preamble-preprint}", tex)
        if n != 1:
            print(f"  {tag}: expected exactly one preamble \\input, found {n}")
            failures += 1
            continue
        zpath = os.path.join(a.out, f"{tag}.zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{tag}.tex", flat)
            z.write(preamble, "preamble-preprint.tex")
        pages = page_count(os.path.join(tree, f"{tag}.pdf"))
        problem = None if a.no_compile else compile_check(zpath, pages, tag)
        if problem:
            print(f"  {tag}: FAIL -- {problem}")
            failures += 1
            os.remove(zpath)
        else:
            print(f"  {tag}: ok  {pages} pp  {os.path.getsize(zpath):,} bytes")
            lines.append(f"{tag} {pages}")
    if failures:
        print(f"\nFAILED: {failures} archive(s) not written.")
        return 1
    print("\nAll archives written and compile-verified: " + ", ".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
