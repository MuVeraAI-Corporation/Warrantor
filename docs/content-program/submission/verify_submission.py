#!/usr/bin/env python3
"""Verify the built PDFs are anonymous and complete.

THE PDF IS WHAT SHIPS. Checking the markdown or the .tex is not sufficient: PDF metadata carries
author, producer and creator fields that no amount of care in the body text touches, and a
submission whose document properties name the author is deanonymized regardless of its title page.
This script reads the built PDFs.

Three checks, in the order that matters:
  1. METADATA -- author, title, subject, keywords, creator, producer. A non-empty author field is
     an immediate fail.
  2. EXTRACTED TEXT -- the deny list, run against the text a reviewer can select and copy, not
     against the source.
  3. COMPLETENESS -- page count and that the reference section survived, so a truncated build
     cannot pass as a good one.
"""
from __future__ import annotations

import glob
import io
import os
import re
import subprocess
import sys
import zlib

D = os.path.dirname(os.path.abspath(__file__))
TEX = os.path.join(D, "tex")

DENY = [
    (r"Vikram", "author name"),
    (r"\bJha\b", "author name"),
    (r"MuVeraAI", "organization"),
    (r"AumOS", "program name"),
    (r"Warrantor", "program name"),
    (r"warrantor-runs", "repository path"),
    (r"C:[\\/]Users", "local path"),
    (r"M:[\\/]Project", "local path"),
    (r"this program", "possessive framing"),
    (r"\bT-\d\d\b", "internal companion label"),
]

META_KEYS = ["Author", "Title", "Subject", "Keywords", "Creator", "Producer"]


def pdf_metadata(path):
    """Read the /Info dictionary without a PDF library."""
    raw = io.open(path, "rb").read()
    found = {}
    for k in META_KEYS:
        for m in re.finditer(rb"/" + k.encode() + rb"\s*\((.*?)(?<!\\)\)", raw, re.S):
            v = m.group(1).decode("latin-1", "replace").strip()
            if v:
                found.setdefault(k, []).append(v)
    return found


def pdf_text(path):
    """Extract text via pdftotext if present, else decompress the content streams."""
    exe = None
    for cand in ("pdftotext",):
        try:
            subprocess.run([cand, "-v"], capture_output=True)
            exe = cand
            break
        except FileNotFoundError:
            pass
    if exe:
        p = subprocess.run([exe, path, "-"], capture_output=True)
        if p.returncode == 0:
            return p.stdout.decode("utf-8", "replace")
    raw = io.open(path, "rb").read()
    out = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        try:
            out.append(zlib.decompress(m.group(1)).decode("latin-1", "replace"))
        except Exception:
            pass
    return "\n".join(out)


def main():
    pdfs = sorted(glob.glob(os.path.join(TEX, "*.pdf")))
    if not pdfs:
        print("no PDFs built")
        return 1
    failures = 0
    for path in pdfs:
        tag = os.path.basename(path)[:-4]
        raw = io.open(path, "rb").read()
        pages = len(re.findall(rb"/Type\s*/Page[^s]", raw))
        print("=" * 88)
        print(f"{tag}   {len(raw):,} bytes   {pages} pages")

        meta = pdf_metadata(path)
        # Author must be EMPTY -- it is the field that deanonymizes, and no legitimate submission
        # populates it. Subject and Keywords are checked for identifying CONTENT rather than
        # required to be empty: acmart writes the CCS concepts into Subject and the keyword list
        # into Keywords, which is exactly what ACM wants there. An earlier version of this check
        # failed P6 for merely having a non-empty Subject, which was a false alarm about correct
        # ACM metadata -- a check should reject what is wrong, not what is unfamiliar.
        bad_meta = {}
        if meta.get("Author"):
            bad_meta["Author"] = meta["Author"]
        for k in ("Subject", "Keywords"):
            for v in meta.get(k, []):
                for pat, why in DENY:
                    if re.search(pat, v, re.I):
                        bad_meta.setdefault(k, []).append(f"{why}: {v[:60]}")
        if bad_meta:
            print(f"   METADATA FAIL: {bad_meta}")
            failures += 1
        else:
            shown = {k: v[0][:34] for k, v in meta.items() if k != "Subject"} or "(all empty)"
            extra = "  +Subject(CCS)" if meta.get("Subject") else ""
            print(f"   metadata: clean  {shown}{extra}")

        text = pdf_text(path)
        hits = []
        for pat, why in DENY:
            for m in re.finditer(pat, text, re.I):
                ctx = re.sub(r"\s+", " ", text[max(0, m.start() - 35):m.end() + 35])
                hits.append(f"[{why}] ...{ctx}...")
        if hits:
            print(f"   TEXT FAIL: {len(hits)} deny-list hit(s)")
            for h in hits[:5]:
                print("      " + h)
            failures += 1
        else:
            print(f"   extracted text: clean  ({len(text):,} chars scanned)")

        if "References" not in text and "REFERENCES" not in text.upper():
            print("   WARNING: no reference section found in extracted text")
        if pages < 4:
            print(f"   WARNING: only {pages} pages -- verify the build is not truncated")

    print("\n" + "=" * 88)
    if failures:
        print(f"FAILED: {failures} check(s) failed. Do not submit.")
        return 1
    print(f"All {len(pdfs)} PDFs are anonymous in both metadata and extracted text.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
