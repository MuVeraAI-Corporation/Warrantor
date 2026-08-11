#!/usr/bin/env python3
"""Find components that claim a capability nothing in them implements.

Two components were found by hand to sign a caller-supplied assertion while describing
it as verification:

    eval-guard    run_preflight(results)      "cryptographic sandbox boundary attestation"
    provena-chain checkpoint(log, entry_id)   "anchored to the Sigstore Rekor transparency log"

Both are invisible to tests. Every test passes, the cryptography is correct, and the
guarantee is inverted -- the function takes as an argument the very fact it purports to
establish. This script looks for the same shape across every component.

Method: for each claimed capability, require at least one piece of MECHANISM evidence in
the component's own source. A claim to inspect the network with no socket, no syscall and
no shell-out is a claim with nothing behind it. The output is a lead list for a human, not
a verdict -- absence of a keyword is evidence, not proof.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LANGUAGE_ROOTS = ("rust", "python", "go", "typescript")

#: How far into a file counts as the module header.
HEADER_LINES = 40

# claim -> (what the docs say it does, what would have to be in the source for it to be true)
CAPABILITIES: dict[str, tuple[re.Pattern[str], re.Pattern[str]]] = {
    "network inspection": (
        re.compile(
            r"network isolation|network boundary|egress (filter|attestation)|inspect.*traffic",
            re.I,
        ),
        re.compile(
            r"TcpStream|UdpSocket|socket\(|connect\(|libc::|nix::|iptables|eBPF|bpf|pcap|reqwest|ureq|net/http|net\.Dial",
            re.I,
        ),
    ),
    "process isolation": (
        re.compile(
            r"process isolation|sandboxe?s? the|enforces? (a )?sandbox|cgroup|seccomp",
            re.I,
        ),
        re.compile(
            r"unshare|clone3|setns|seccomp|cgroup|prctl|libc::|nix::|CreateProcess|Job ?Object|os/exec|subprocess",
            re.I,
        ),
    ),
    "filesystem boundary": (
        re.compile(
            r"filesystem boundary|filesystem isolation|chroot|path (jail|confinement)",
            re.I,
        ),
        re.compile(
            r"canonicalize|std::fs|openat|chroot|pivot_root|os\.path\.realpath|filepath\.Abs|fs::",
            re.I,
        ),
    ),
    "transparency log anchoring": (
        re.compile(
            r"anchor(ed|ing)? to|transparency log|rekor|sigstore|inclusion proof", re.I
        ),
        re.compile(r"http|ureq|reqwest|net/http|fetch\(|api/v1/log|POST", re.I),
    ),
    "hardware attestation": (
        re.compile(
            r"(hardware|GPU) attestation|nvtrust|SEV-SNP|TDX|confidential comput", re.I
        ),
        re.compile(
            r"nvml|nvidia_?ml|/dev/sev|tpm|quote|ioctl|libc::|attestation_report|SNP_",
            re.I,
        ),
    ),
    "signature verification": (
        re.compile(
            r"verif(y|ies|ication) .*(signature|signed)|signature verification", re.I
        ),
        re.compile(
            r"verify\(|VerifyingKey|ed25519|rsa|ecdsa|Signature::|crypto|hmac", re.I
        ),
    ),
    "secret scanning": (
        re.compile(r"scans? (for |output for )?(exposed )?(secret|credential)", re.I),
        re.compile(r"regex|Regex|re\.compile|pattern|MatchString", re.I),
    ),
    "containment / kill": (
        re.compile(
            r"kill.?switch|terminates? (the )?(agent|process)|halts? the agent", re.I
        ),
        re.compile(
            r"SIGKILL|SIGSTOP|SIGTERM|kill\(|taskkill|TerminateProcess|os\.kill|syscall|libc::|nix::",
            re.I,
        ),
    ),
}

# Files that describe rather than implement.
SKIP = re.compile(
    r"(^|/)(tests?|fuzz|examples?|benches)(/|$)|\.md$|\.json$|\.toml$|\.lock$"
)


@dataclass
class Finding:
    component: str
    capability: str
    claim_site: str
    claim_text: str
    mechanism_found: bool


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, cwd=REPOSITORY_ROOT
    )
    return [f for f in out.stdout.split("\n") if f]


def components() -> dict[str, list[Path]]:
    """Map component directory -> its source files."""
    grouped: dict[str, list[Path]] = {}
    for rel in tracked_files():
        parts = rel.split("/")
        if len(parts) < 2 or parts[0] not in LANGUAGE_ROOTS or SKIP.search(rel):
            continue
        if not rel.endswith((".rs", ".py", ".go", ".ts")):
            continue
        grouped.setdefault(f"{parts[0]}/{parts[1]}", []).append(REPOSITORY_ROOT / rel)
    return grouped


def audit() -> list[Finding]:
    findings: list[Finding] = []
    for component, files in sorted(components().items()):
        blobs: list[tuple[Path, str]] = []
        for path in files:
            try:
                blobs.append((path, path.read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError):
                continue
        if not blobs:
            continue
        corpus = "\n".join(text for _, text in blobs)

        for capability, (claim_re, mechanism_re) in CAPABILITIES.items():
            claim_site = ""
            claim_text = ""
            for path, text in blobs:
                # Only the module/crate HEADER counts. That is where a component states what
                # it IS, and it is what a reader takes as its claim about itself. An incidental
                # "contains any refusal marker" or a comment about K8s "namespaces" 300 lines
                # down is not a claim -- counting those produced 34 findings, mostly noise.
                for lineno, line in enumerate(text.split("\n")[:HEADER_LINES], 1):
                    if not re.match(r'\s*(//[/!]|"""|#!)', line):
                        continue
                    # A line that merely LISTS component names is not a claim about this
                    # component. `warrantor-api` was flagged for both "containment" and
                    # "hardware attestation" purely for naming kill-switch and nvtrust-bridge
                    # in a dependency list.
                    if len(re.findall(r"`[a-z0-9-]+`", line)) >= 2:
                        continue
                    if claim_re.search(line):
                        claim_site = (
                            f"{path.relative_to(REPOSITORY_ROOT).as_posix()}:{lineno}"
                        )
                        claim_text = line.strip()[:150]
                        break
                if claim_site:
                    break
            if not claim_site:
                continue
            findings.append(
                Finding(
                    component=component,
                    capability=capability,
                    claim_site=claim_site,
                    claim_text=claim_text,
                    mechanism_found=bool(mechanism_re.search(corpus)),
                )
            )
    return findings


def main() -> int:
    findings = audit()
    unbacked = [f for f in findings if not f.mechanism_found]

    print(f"claims examined : {len(findings)}")
    print(f"WITHOUT mechanism: {len(unbacked)}\n")
    for f in sorted(unbacked, key=lambda x: (x.component, x.capability)):
        print(f"  {f.component}")
        print(f"    claims   : {f.capability}")
        print(f"    at       : {f.claim_site}")
        print(f"    text     : {f.claim_text}")
        print()

    report = REPOSITORY_ROOT / "evidence" / "claim-vs-mechanism.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "claims_examined": len(findings),
                "claims_without_mechanism": len(unbacked),
                "findings": [asdict(f) for f in findings],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"report: {report.relative_to(REPOSITORY_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
