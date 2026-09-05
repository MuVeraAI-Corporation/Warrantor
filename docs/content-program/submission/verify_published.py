#!/usr/bin/env python3
"""Verify the PDFs that ship -- named preprints and anonymous submissions -- before they are copied.

THE PDF IS WHAT A MODERATOR OPENS. Every check here runs against the built PDF: its document
properties and the text a reader can select. Checking the markdown or the .tex is not sufficient
and was, in fact, how six papers went out with empty metadata, literal blanks and their own revision
history in the body. This script exists so that cannot happen quietly again.

NAMED build (tex-preprint/):
  - /Title present; /Author is the author
  - the identity block is in the text: name, affiliation, ORCID, email, licence
  - no draft apparatus survives (see to_latex.DRAFT_APPARATUS)
ANONYMOUS build (tex/):
  - /Title present; /Author EMPTY (the field that deanonymizes)
  - the anonymity deny list from verify_submission.py finds nothing
  - no draft apparatus survives
BOTH:
  - a References section exists and the page count is plausible, so a truncated build cannot pass

Exit status is the verdict. A non-zero exit is "do not publish", not a warning.
"""
from __future__ import annotations

import glob
import io
import os
import re
import sys
import zlib

D = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, D)
from to_latex import DRAFT_APPARATUS          # noqa: E402  -- one list, one place
from verify_submission import DENY            # noqa: E402  -- the anonymity deny list

NAMED_DIR = os.path.join(D, "tex-preprint")
ANON_DIR = os.path.join(D, "tex")

AUTHOR = "Vikram Jha"
IDENTITY = ["Vikram Jha", "MuVeraAI", "0009-0004-3959-6099", "vikram@muveraai.com", "CC BY 4.0"]

#: Patterns in DRAFT_APPARATUS that only exist in LaTeX source and can never appear in a PDF's text.
TEX_ONLY = {r"\\warn\b", r"\\(?:sout|st)\{"}


def pdf_metadata(path: str) -> dict[str, str]:
    """The /Info dictionary, without a PDF library. hyperref writes UTF-16BE with a BOM."""
    raw = io.open(path, "rb").read()
    out = {}
    for key in ("Title", "Author", "Subject", "Keywords"):
        m = re.search(rb"/" + key.encode() + rb"\s*\((.*?)(?<!\\)\)", raw, re.S)
        if not m:
            continue
        v = m.group(1)
        # ⚠️ ORDER MATTERS. hyperref writes the UTF-16 byte-order mark as OCTAL ESCAPES inside the
        # PDF string -- the raw bytes are the seven characters "\376\377", not 0xFE 0xFF. Testing
        # for the BOM before resolving the escapes never matches, so every title and author came
        # back as latin-1 mush and the check failed on thirteen PDFs whose metadata was correct.
        v = re.sub(rb"\\(\d{3})", lambda mm: bytes([int(mm.group(1), 8)]), v)
        v = v.replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
        if v.startswith(b"\xfe\xff"):
            v = v[2:].decode("utf-16-be", "replace")
        else:
            v = v.decode("latin-1", "replace")
        out[key] = v.strip()
    return out


def pdf_text(path: str) -> str:
    """Text a reader can select, recovered from the content streams. Spaces are unreliable in this
    extraction, so callers compare with whitespace removed where that matters."""
    raw = io.open(path, "rb").read()
    chunks = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        try:
            chunks.append(zlib.decompress(m.group(1)).decode("latin-1", "ignore"))
        except Exception:
            pass
    body = "\n".join(chunks)
    # Text operands sit inside (...) in TJ/Tj operators; join them and drop escapes.
    parts = re.findall(r"\((?:[^()\\]|\\.)*\)", body)
    return " ".join(p[1:-1] for p in parts).replace("\\", "")


def page_count(path: str) -> int:
    raw = io.open(path, "rb").read()
    counts = [int(x) for x in re.findall(rb"/Count\s+(\d+)", raw)]
    return max(counts) if counts else 0


def check(path: str, named: bool, doi: str = "") -> list[str]:
    problems: list[str] = []
    meta = pdf_metadata(path)
    text = pdf_text(path)
    squashed = text.replace(" ", "")

    # The concept DOI is on the face of every named build from v3 onward; the anonymous build
    # must not carry any Zenodo DOI, because a DOI resolves to the author as surely as a name does.
    if named and doi and doi.replace(" ", "") not in squashed:
        problems.append(f"concept DOI {doi} not on the face of the named build")
    if not named and "10.5281/zenodo." in squashed:
        problems.append("anonymous build carries a Zenodo DOI, which resolves to the author")

    if not meta.get("Title"):
        problems.append("no /Title in document properties")
    if named and meta.get("Author") != AUTHOR:
        problems.append(f"/Author is {meta.get('Author')!r}, expected {AUTHOR!r}")
    if not named and meta.get("Author"):
        problems.append(f"anonymous build carries /Author={meta['Author']!r}")

    for pat, why in DRAFT_APPARATUS:
        if pat in TEX_ONLY:
            continue
        if pat == r"double-blind" and not named:
            continue
        for m in re.finditer(pat, text):
            ctx = re.sub(r"\s+", " ", text[max(0, m.start() - 40):m.end() + 40])
            problems.append(f"draft apparatus [{why}]: ...{ctx}...")
            break

    if named:
        for s in IDENTITY:
            if s.replace(" ", "") not in squashed:
                problems.append(f"identity block missing: {s!r}")
    else:
        for pat, why in DENY:
            m = re.search(pat, text, re.I)
            if m:
                ctx = re.sub(r"\s+", " ", text[max(0, m.start() - 35):m.end() + 35])
                problems.append(f"anonymity [{why}]: ...{ctx}...")

    # Kerned text arrives as fragments -- "(Ref)-3(erences)" -- so the contiguous word only exists
    # once spaces are squashed. Checked on `squashed` for that reason; the unsquashed check reported
    # a missing reference section on every anonymous PDF that had one.
    if "References" not in squashed and "REFERENCES" not in squashed.upper():
        problems.append("no References section in extracted text")
    if page_count(path) < 4:
        problems.append(f"only {page_count(path)} pages -- truncated build?")
    return problems


def main() -> int:
    # The publication set, not whatever PDFs happen to be in the tree: a stale P2.pdf from before
    # P2 was dropped from the set sat in both trees and was being checked -- and failing -- as if
    # it were about to ship.
    from build_preprint import PAPERS, CONCEPT_DOI
    tags = [tag for tag, _ in PAPERS]
    failures = 0
    for tree, named in ((NAMED_DIR, True), (ANON_DIR, False)):
        label = "NAMED" if named else "ANON "
        for tag in tags:
            path = os.path.join(tree, f"{tag}.pdf")
            if not os.path.exists(path):
                continue                      # T04 has no anonymous build, by design
            probs = check(path, named, CONCEPT_DOI.get(tag, "") if named else "")
            meta = pdf_metadata(path)
            tag = os.path.basename(path)[:-4]
            print(f"  {'FAIL' if probs else 'ok  '} {label} {tag:<4} {page_count(path):>3}pp  "
                  f"title={meta.get('Title', '')[:40]!r}  author={meta.get('Author', '')!r}")
            for p in probs:
                print(f"         - {p}")
            failures += bool(probs)
    print()
    if failures:
        print(f"FAILED: {failures} PDF(s) must not be published.")
        return 1
    print("All PDFs verified: metadata present, identity where it belongs and nowhere else, "
          "no draft apparatus in the text.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
