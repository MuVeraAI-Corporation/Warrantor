# Verdict on the Repaired Tier Instrument

**Status:** re-score complete, 15 works, two columns each. Written 2026-08-30 against the stored
decisive-pass coder records. Governs §3.1, §3.1.1, §5.4 and §9 of
[`T-12-sok-authority-and-containment.md`](T-12-sok-authority-and-containment.md).

---

## 1. The verdict

**The collapse was an artifact of the rule, and the repaired instrument works.** Under the single
column, exactly one work in fifteen scored above T3. Under the two-column rule, **seven of fifteen
works verify a claim at cryptographic tier (A-T1)** while **eleven of fifteen bound an action only at
an application chokepoint (B-T3)**. Five works are A-T1 and B-T3 at once. That combination was
unrepresentable in the old instrument, which is why the old instrument returned T3 for every one of
them.

The repair is discriminating rather than indiscriminate, and that is the part that makes it
trustworthy. It did not lift the corpus. **Seven works remain at A-T3 and one at A-NONE**, so the
acceptance column is split almost exactly in half, and six works land at T3 in *both* columns for
independent reasons. Two works — SEAgent and Arbiter-K — contain no cryptographic primitive and no
kernel mechanism anywhere, and both columns land on in-process Python for reasons that have nothing
to do with the rule. Those are negative controls, and they came back negative.

The single sharpest confirmation is an internal consistency check the re-score did not aim for. The
SoK abstract records that five works advertised cryptographic enforcement, all five scored T3, and in
**four of the five** the coder recorded a narrower guarantee that is genuinely T1 and proved. Under
the repaired rule, exactly those four rise to A-T1 — PEA, PAuth, AIP, HBHC — and the fifth, the Intel
TDX trusted plane, **stays at A-T3**. The instrument promoted the four works whose coders had already
written the promotion into the notes, and declined to promote the one whose coder had not. A rule
that lifted all five would be evidence of a rule that lifts anything.

**The decisive negative control is the TDX trusted plane, and it deserves to be stated first because
it is the uncomfortable half.** If any work in the batch should have populated A-T1, it is this one:
its entire architecture is an acceptance architecture — classify, authorize, scope-bind, generate
evidence, all inside a hardware-isolated domain the rich execution environment cannot reach — and it
advertises unforgeability in as many words. It scores A-T3, because the conservative coder searched
the full text and found that *signature*, *signed authorization*, *MAC*, *nonce* and *encrypt* never
appear in a construction, and because the party that performs the check is one the paper itself
declines to trust. Forging acceptance there requires no signature break, no attestation break and no
TDX compromise. It requires a compromised executor that field-matches a tuple it made up. **A
confidential-computing architecture with no cryptographic binding on the object it asks a relying
party to accept is a stronger finding than any demotion in the batch**, and the repaired instrument
is what made it sayable, because the acceptance column is where that failure lives and the old column
had already condemned the work for a different reason.

One further structural result, which no single-column instrument could have produced: **the
acceptance column is bimodal and its middle tier is empty.** Zero works score A-T2. Nobody in this
corpus makes acceptance turn on a kernel-mediated fact — a real uid, a namespace membership, a
measured boot value. Acceptance is decided either by a signature or by in-process application state,
with nothing in between. TDX came closest and did not cash it out: its plane never attests itself to
any verifier, so a fact that is true of the computation is never made into something a relying party
checks.

### 1.1 The two-column distribution

**Column A — tier of acceptance (n = 15)**

| Tier | n | Works |
|---|---|---|
| **A-T1** cryptographic | **7** | MiniScope, PEA, PAuth, AIP, HBHC, Grimlock, AARM |
| A-T2 operating system | **0** | — |
| **A-T3** application | **7** | SEAgent, CaMeL-NOVA, Arbiter-K, AgentCgroup, SandScope, Caging the Agents, TDX |
| A-NONE no claim | 1 | Sandlock |
| unscorable | 0 | — |

**Column B — tier of action (n = 15)**

| Tier | n | Works |
|---|---|---|
| B-T1 cryptographic | 1 | PAuth |
| B-T2 operating system | 2 | Sandlock; Caging the Agents (designed architecture only) |
| **B-T3** application chokepoint | **11** | SEAgent, MiniScope, CaMeL-NOVA, Arbiter-K, PEA, AgentCgroup, SandScope, TDX, AIP, HBHC, AARM |
| B-NONE | 0 (see note) | AgentCgroup is B-NONE in any effector sense; scored B-T3 on its resource ceiling |
| **unscorable** | **1** | Grimlock |

**The joint distribution is the finding.**

| | B-T1 | B-T2 | B-T3 | unscorable |
|---|---|---|---|---|
| **A-T1** | 1 (PAuth) | 0 | **5** (MiniScope, PEA, AIP, HBHC, AARM) | 1 (Grimlock) |
| **A-T2** | 0 | 0 | 0 | 0 |
| **A-T3** | 0 | 1 (Caging) | **6** (SEAgent, CaMeL-NOVA, Arbiter-K, AgentCgroup, SandScope, TDX) | 0 |
| **A-NONE** | 0 | 1 (Sandlock) | 0 | 0 |

Two cells carry the corpus: **A-T1/B-T3 at 5** and **A-T3/B-T3 at 6**. The first is a pattern the old
rule could not express. The second is the finding the old rule was right about. Both are real, and
reporting only one of them would be the same error in the opposite direction.

---

## 2. The two-column table

| # | Work | Advertised | Single column | **A: acceptance** | **B: action** | What changed |
|---|---|---|---|---|---|---|
| 1 | **SEAgent** (2601.11893) | T2 | T3 | **A-T3** | **B-T3** | **Nothing, and that is the point.** No cryptographic primitive and no OS mechanism anywhere, so both columns land on in-process state independently. The demotion is better argued: not "a compromised agent can write a file" but "the label store, the round graph and the default-allow fallthrough are all in-process." |
| 2 | **MiniScope** (2512.11147) | unclear / T3 | T3 | **A-T1** | **B-T3** | **Decisive.** The charitable coder wrote the T1 reading out and then rejected it under the weakest-link rule. Credential isolation from the agent is real and enforced by the service. Holds at published-OAuth-scope granularity, not at the ILP-minimal granularity the product is named for. |
| 3 | **CaMeL-NOVA** (2601.09923) | unclear / T2 | T3 | **A-T3** | **B-T3** | Tier unchanged, diagnosis inverted. The action column is genuinely bounded — the plan's call graph is fixed by an environment-blind planner — and the system fails in the acceptance column, because every branch value is supplied by an untrusted model. Branch Steering is an acceptance attack on an intact action bound. |
| 4 | **Arbiter-K** (2604.18652) | T2 | T3 | **A-T3** | **B-T3** | No change; second negative control. Kernel, ISA, microarchitectural and privilege rhetoric against a 28,914-line userspace Python runtime. The undefined VERIFY instruction makes the *strength within* A-T3 unscorable, not the tier. |
| 5 | **PEA** (2604.23646) | T1 | T3 | **A-T1** | **B-T3** | **Decisive.** HMAC-SHA256, TTL-bound, single-use, version-checked, subset-attenuating tokens genuinely bind what the dispatcher accepts, against the untrusted Policy layer the paper actually models. The advertised claim — "enforces safety regardless of agent behavior" — is an action claim and remains T3 resting on Assumption A3. |
| 6 | **Sandlock** (2605.26298) | T2 | **T2** | **A-NONE** | **B-T2** | Not a demotion, a relocation. Its T2 was always an action bound, and it makes no verifiable claim to any relying party. It anchors column B and is absent from column A, which is the correct shape for a sandbox. |
| 7 | **AgentCgroup** (2602.09345) | T2 | T3 | **A-T3** | **B-T3** | Both verdicts stand; two things become sayable. The acceptance defeat (set `AGENT_RESOURCE_HINT`) is strictly cheaper than the action defeat (avoid `bash -c`). The genuine B-T2 workload-level cgroup ceiling is recordable as a residual instead of being laundered or lost. |
| 8 | **SandScope** (2601.01241) | T2 | T3 | **A-T3** | **B-T3** | Category error corrected. Its entire product is an acceptance decision — a pre-adoption audit report — and the single column scored it on a deployment-time action bound it never claimed. A-T3 by the authors' own concession that absence of a witness does not prove absence of a flow. |
| 9 | **Caging the Agents** (2603.17419) | T2, with unbacked T1 rhetoric | **split T3 / T2** | **A-T3** | **B-T2** designed; **B-T3** deployed | Partially resolves the coder split. "Cryptographically structured metadata envelopes" cash out to a JSON schema the model is instructed to trust. gVisor and per-pod NetworkPolicy do bind regardless of intent — but Table 3 places them in the unshipped K8s target column, and the 90-day fleet ran on DNS filtering. |
| 10 | **TDX trusted plane** (2605.06393) | T1 / unclear | T3 | **A-T3** | **B-T3** | **No change, and it is the strongest result in the re-score.** The two columns are genuinely independent here — decision plane in hardware, effectors in the REE — so the collapse critique has no purchase, and both columns fail for different, independently sufficient reasons. |
| 11 | **PAuth** (2603.17170) | T1 | **split T3 / T1** | **A-T1** | **B-T1** | The only work cryptographic in both columns, and the reason is topological: the verifier is embedded in each server's dispatch layer, so it is not in the adversary's address space. Binds at operand granularity, not scope granularity. Tier disagreement dissolves; a v1/v2 version mismatch between coders does not. |
| 12 | **AIP** (2603.24775) | T1 | T3 | **A-T1** | **B-T3** | **Paradigm case.** Ed25519 append-only chain with check-all-blocks attenuation, 600/600 adversarial rejections, 78 cross-language conformance tests — the best-evidenced acceptance column in the batch. Three independent B-column defects, none requiring cryptographic work. |
| 13 | **HBHC** (2605.20704) | T1 | **split T3 / T1** | **A-T1** | **B-T3** | **Textbook resolution.** Conservative scored the action bound; charitable scored the acceptance decision; neither erred. Two proved theorems, a measured bound (7.8s against 8s) and an offline partition demonstration in column A; "Bypass-proof: Yes" is a column-B claim and column B is where it fails. |
| 14 | **Grimlock** (2605.27488) | T2 | **split T3 / T2** | **A-T1** | **unscorable** | The silent demotion is retired. A cryptographic acceptance decision (TEE evidence over a TLS-exporter channel binding, re-validated at the receiving guard) sitting on an action substrate the paper never specifies: no hook family, and no statement of whether the eBPF program attaches in the host kernel or the agent's own guest kernel. |
| 15 | **AARM** (2602.09433) | unclear, advertised per architecture | T3 | **A-T1** for receipt integrity only | **B-T3** ⚠️ reconstructed | The evidentiary tier is finally recordable. The conservative coder asked for this instrument by name: "worth recording separately if the SoK ever splits enforcement tier from evidentiary tier." See §7.5 — this row's action column was reconstructed from the underlying codings, not delivered in the re-scored record. |

---

## 3. The disagreements the two columns explain

Four works split the coders on scored tier under the single column: Caging the Agents (T3/T2), PAuth
(T3/T1), HBHC (T3/T1) and Grimlock (T3/T2). The column dimension bears on three of them and fully
dissolves one.

| Work | Does it resolve into "one coder scored acceptance, the other scored action"? | Residual |
|---|---|---|
| **HBHC** | **Yes, completely.** Conservative: "the check lives in the caller's own address space and the caller declines to call it" — column B. Charitable: "a third-party resource server running VerifyAuth over a self-contained signed object" — column A. Both correct, one slot, two answers. | None. |
| **PAuth** | **Yes on tier.** The conservative coder concedes the acceptance column outright: "an adjudicator could defensibly split-score it T1 for the narrow decision 'what a compliant participating server accepts.'" | Design versus evaluated artifact, compounded by the coders reading different versions (v1 against the 25 Aug 2026 v2). Not a column question. |
| **Caging the Agents** | **About half.** Conservative anchored on "a manipulated agent cannot exfiltrate PHI" — an acceptance claim with no verifier, since the same allowlisted HTTPS POST is compliant or a breach depending on payload semantics. Charitable anchored on "no packet leaves for an off-allowlist address" — an action bound that genuinely holds. | Deployment status: the fleet as run against the architecture as specified. No column captures it. |
| **Grimlock** | **No.** Both coders were arguing inside column B — kernel unavoidability against a userspace release gate. Neither was scoring acceptance. | Resolved by the **mechanism-specificity floor**, not by the columns. The paper does not contain the fact that would decide it. |

**Count: 1 of 4 dissolves completely, 2 of 4 partially, 1 of 4 not at all.** The honest summary is
that the instrument manufactured some of these disagreements and not others. In HBHC it manufactured
the whole thing — the stances decided the outcome instead of the evidence, which is a defect of the
first order in a two-coder design. In PAuth and Caging it manufactured the tier gap and left a real
methodological disagreement underneath: **which artifact are we scoring, the design or the thing that
ran?** That question is now the largest unadjudicated hole in the method, and it should be written
into §4 as a coding rule rather than left to stance.

Grimlock is worth reporting as a negative result. **Two repairs were proposed and only one of them
was the columns.** The specificity floor is doing independent work, and this batch proves it: without
the floor, Grimlock would have been silently demoted to T3 a second time, and the conservative coder
would have drawn the same over-general corpus lesson from it ("mixing a higher tier INTO a system
does not raise the system") that the rule itself had manufactured.

---

## 4. The narrower T1 guarantees, and whether they now score

This is the direct test of the artifact hypothesis. Coders recorded a narrower, genuinely-T1
guarantee they could not score in seven works. **All seven now score A-T1. None of the works whose
coders recorded "no narrower T1 guarantee" was promoted.**

| Work | The narrower guarantee the coder recorded | Now scores |
|---|---|---|
| **MiniScope** | Credential isolation: the agent holds only a session token; the proxy substitutes the real OAuth bearer after the check. Calls to an enrolled service outside granted scope are impossible without breaking the auth protocol. | **A-T1**, and genuinely **B-T1 on that narrow lane** — the one place in the batch where an action is impossible without a secret the actor lacks, on a surface narrower than the paper's headline. |
| **PEA** | Token unforgeability and delegation attenuation against the untrusted Policy layer. Cannot mint, cannot replay, cannot escalate beyond a parent's scope without breaking HMAC-SHA256. | **A-T1**, against the modeled adversary (A3, A1). Collapses under A4, which the paper places out of scope. |
| **PAuth** | The paper's own headline: no agent action sequence can cause a server to accept a call whose operands are inconsistent with the user's task, given unforgeable envelopes. | **A-T1 and B-T1.** Unusually, nothing had to be rescued from the notes — the scoring rule was discarding the paper's primary claim. |
| **AIP** | "A delegation block that attempts to widen any capability beyond its parent block fails verification." Plus depth bounding via Block 0 `max_depth`, which reaches descendants cryptographically. | **A-T1**, at 100/100 on the widening class and 600/600 overall. |
| **HBHC** | "No HBHC-modified verifier accepts an authentication proof whose parent heartbeat epoch is older than Wmax by the verifier's local clock." Proved, measured, demonstrated under partition. | **A-T1**, the only acceptance column in the batch carrying a formal proof and a measured bound. |
| **Grimlock** | The Scope Token — "a genuine T1-styled artifact (cryptographic binding to a TLS exporter, TEE evidence over H(cb))," discarded because "the T1 artifact is only ever consulted by a verifier reachable through the T2 steering layer." | **A-T1** by named mechanism at evidence grade L0. That discarding sentence is a column-B statement with no bearing on column A. |
| **AARM** | Receipt integrity: every action yields a signed, offline-verifiable, tamper-evident receipt over an append-only hash chain. The coder's exact request: "worth recording separately if the SoK ever splits enforcement tier from evidentiary tier." | **A-T1 for receipt integrity**, with the completeness caveat in §7.5. |

**The controls held.** Sandlock's conservative coder searched for a cryptographic construction and
found none; it stays A-NONE. AgentCgroup and SandScope both recorded "no T1 anywhere," and both stay
A-T3 — while their genuine T2-character sub-properties (the inherited cgroup ceiling with
`cgroup.kill`; the WASI guest bound with no process-spawn primitive) are now recordable as column-B
residuals rather than being lost or laundered. Caging the Agents recorded "none, and the absence is
the point," and stays A-T3 with its cryptographic rhetoric unbacked.

**And one recorded narrower guarantee was declined.** The TDX plane's coder recorded a real narrower
property — classification logic and audit evidence computed inside a hardware-isolated domain the REE
cannot read, modify or impersonate — and correctly labeled it **T2-character, not T1**. Under the
repaired rule it would be A-T2 if the plane attested itself to the executor. It does not, so the fact
is true of the computation and never cashed out as something a relying party checks, and the work
stays A-T3. **A rule that promotes six of seven recorded guarantees and refuses the seventh on a
stated criterion is behaving like an instrument.**

---

## 5. What the two columns say together

### 5.1 The modal pattern has a name

**A-T1 with B-T3 is the modal pattern for the cryptographic half of this corpus: 5 of 15 works
overall, and 5 of the 7 works that reach A-T1.** Add Grimlock, whose action column is unscorable
rather than higher, and it is 6 of 7. The exception is PAuth, and the exception is instructive.

The pattern is: **a system cryptographically controls who may authorize, and controls nothing about
what may execute.** PEA's coder produced the sentence the SoK should adopt verbatim:

> the crypto binds who may AUTHORIZE, not what may EXECUTE.

Call it the **authorization–execution gap**. It is not overclaiming in the ordinary sense and it
should not be reported as if it were. Every one of these five built a real cryptographic artifact,
several of them tested it adversarially, and one proved it. What they did not build is a floor under
the process. The signature governs a decision; the decision governs a call site; the call site is one
of several ways to reach the effector; and the paper's advertised guarantee is written over the
effector.

### 5.2 The consequence is a composition requirement, and the corpus contains both halves

The two columns turn a per-work verdict into a **pairing rule**, which is exactly what §6 of the SoK
needs and what the single column could not supply:

> **An A-T1/B-T3 system delivers its advertised guarantee only when composed with a B-T2 substrate it
> does not itself provide.**

The corpus contains both halves and no work that is both. Sandlock is **A-NONE/B-T2** — a pure action
bound making no claim to anyone. The five A-T1/B-T3 works are pure acceptance bounds with no action
floor. **They are complements, and nobody in the corpus shipped the pair.** Several papers say so
themselves, in different words: CaMeL-NOVA concedes it "requires additional infrastructural defenses";
SandScope says native scans "should be paired with an OS-level sandbox such as Docker or Bubblewrap";
AARM says kernel monitoring is a defense-in-depth backstop that cannot alone satisfy conformance.
Three works independently name the missing half. None of them supplies it.

### 5.3 The one existence proof, and how it was achieved

PAuth is the only work in the batch that is cryptographic in both columns, and the mechanism is
**topological rather than rhetorical**: the middleware is embedded in each MCP server's tool-dispatch
layer, so the verifier is not in the adversary's address space. The adversary is the agent; for any
effect realized at a participating server there is no second door, because a subprocess, a sub-agent
or an FFI call all arrive at the same middleware from the outside.

That generalizes into the most useful engineering sentence the re-score produces:

> **The only way anyone in this corpus obtained a cryptographic action bound was to move the verifier
> out of the adversary's address space, to the far side of the call.**

Its cost is stated in the same breath: the bound covers only the participating-server surface. Local
file writes, subprocess spawns and non-participating endpoints are unreached. That is coverage, not
tier — and it is precisely why the coverage axis must be declared to be a column-B measurement
(§6, §3.2 edits below).

### 5.4 Where the paper's central contribution may now live

The SoK's working headline is a demotion rate. **The demotion rate is now a column-B statistic and
should be labeled as one**, because in column A the same corpus looks materially different and both
descriptions are true. The stronger claim available after the re-score is structural rather than
statistical:

> This literature has built a credible cryptographic layer for **deciding authority** and has built
> almost nothing for **bounding execution** — and the two halves are being advertised as one
> guarantee.

That reframes the corpus from "a field that overclaims" to "a field that has solved one of two
problems and is describing the solved one in the vocabulary of the unsolved one." It is more useful
to a practitioner, harder for an author to contest (the acceptance column *credits* their
cryptography, often more than their own paper does), and it lands directly on §6's composition
result, §7's surrogate/objective split, and §9's own-system row.

---

## 6. What this changes in T-12, section by section

### Abstract
- **Replace** "exactly one work in fifteen scores above T3" with the two-column distribution: *seven
  of fifteen verify a claim at cryptographic tier; eleven of fifteen bound an action only at an
  application chokepoint; one does both.*
- **Relabel** "12 of 14 works with a scorable advertised tier demote (85.7%)" as an **action-column**
  rate. Keep the number and keep the upper-bound caveat; add that in the acceptance column the same
  works do not demote.
- **Rewrite the ⚠️ negative-result paragraph** from *defect found, repair proposed* to *defect found,
  repair executed, result reported*. It should carry the 4-of-5 consistency check and the TDX
  negative control, because a repair that reports its own controls is the version a reviewer trusts.
- **Add** the authorization–execution gap in one sentence, as a named result.

### §1.2 Contributions
- Contribution 1 becomes **the two-column tier rule plus the mechanism-specificity floor**, presented
  as a rule change discovered by measurement and disclosed as such.
- **Add a contribution**: the authorization–execution gap and the composition requirement it implies
  (§5.2 above), since that is now a result rather than a discussion point.

### §3.1 Axis 1
- Promote the two columns from a §3.1.1 repair note into **the axis definition itself**. The three
  tiers stay; they are applied twice.
- **The worked example is now the paper's central pattern, not a demotion demo.** The example as
  written — signed capability mandates enforced by an in-process hook — currently concludes "it scores
  T3." It now scores **A-T1/B-T3**, which is the modal cell, and the example should say so.
- Keep weakest-link scoring, **scoped within each column**. The rule was never wrong; it was applied
  across two questions at once.

### §3.1.1
- Rewrite from "the repair" to "the repair and what it returned." Carry: the joint distribution
  table, the 4-of-5 check, the two negative controls (SEAgent, Arbiter-K), the empty A-T2 cell, and
  the one work the floor made unscorable.
- **State the empty A-T2 cell explicitly.** Zero works decide acceptance on a kernel-mediated fact.
  That is a clean, checkable, previously unsayable finding.

### §3.2 Axis 2, coverage
- **Declare coverage a column-B measurement.** Acceptance has no effector surface; all 105 adjudicated
  cells are action-column cells. Without this sentence a reader will try to reconcile A-T1 works with
  their `not-covered` cells and conclude the instrument is inconsistent.
- **Add a note on AgentCgroup**: in any effector sense it is B-NONE — it authorizes nothing and denies
  nothing, and bounds only how much a descendant may consume. The three-value rubric cannot currently
  say that.

### §3.4 Evidence grade
- **Add one paragraph separating the acceptance column from the evidence grade**, because they will
  be confused. Column A asks *what would forging cost*; the L-grade asks *what has been tested*. The
  batch supplies the illustration: **Grimlock is A-T1 at L0** (named mechanism, no evaluation) and
  **AIP is A-T1 at L2** (600/600 adversarial rejections). Same cell, very different rows.
- **Fold in AARM's evidentiary-tier request.** The acceptance column now absorbs what its coder called
  "evidentiary tier" — a receipt that cannot be retroactively altered undetected is an acceptance
  claim to an auditor.

### §5.4 Tier: advertised against scored
- The comparison table gains a second half. Suggested shape:

| | Pilot (10) | Decisive, single column (15) | **Decisive, two columns (15)** |
|---|---|---|---|
| Action-column demotion | 4 of 10 | 12 of 14 scorable | 12 of 14 scorable (**unchanged**) |
| Works above T3, acceptance | n/a | n/a | **7 of 15** |
| Works above T3, action | 0 | 1 of 15 | 3 of 15 (one designed-only) |
| Unscorable under the floor | 0 | 0 (silently demoted) | **1** |
| Scored-tier coder agreement | 6 of 6 | 11 of 15 | 12 of 15 on tier; the 2 residual disagreements are artifact-selection, not tier |

- **Keep "exactly one work scores above T3" only as a column-B sentence about Sandlock**, and keep the
  observation that it is the only work whose prose declines to overclaim.
- **Retire the phrase "silently demoted"** in favor of the recorded `unscorable` cell, and name
  Grimlock as the work that was mishandled under the old rule.

### §5.5 Coverage
- Annotate the whole section as column B. The headline sentence — *network egress is reached by 14 of
  15 systems and bounded completely by none* — is unaffected and gets stronger next to §5.2, because
  it is a statement about exactly the half of the problem nobody solved.

### §6 Composition
- **§6.2's matrix gains a companion**: the A/B pairing rule in §5.2 above. It is a composition result
  that does not depend on the full pass, and it is stated over cells the pilot already has.
- **§6.3 gains the artifact-selection defect.** Caging the Agents and PAuth both leave a residual
  disagreement that is not about placement and not about columns: design against deployed, and v1
  against v2. The method needs a stated rule — score the artifact evaluated, note the design in the
  justification — and it needs it before the full pass, not after.

### §7 Enforceability
- **Map the surrogate/objective split onto the two columns**, which is a free strengthening. In work
  after work, the monitorable surrogate is an **acceptance predicate** (a signature check, a scope
  match, a label test, a freshness window) and the advertised objective is an **action or flow
  property**. The 50-of-50 split verdict and the A/B gap are the same phenomenon measured two ways,
  and saying so converts two separate findings into one mechanism.
- The universality claim is untouched.

### §9 Own system
- The §9 row is already written in two columns — receipts T1 of acceptance, enforcement T3 of action
  — and it is now **the modal row, not a special confession**. Edit accordingly: keep scoring the
  authors' system first and at full severity, and add that it sits in a named pattern alongside five
  other works.
- **Add the honest consequence**: under §5.2, the system's advertised guarantee requires a B-T2
  substrate it does not provide, and the published architecture contains no namespace, seccomp or
  firewall mechanism. That is a sharper self-criticism than the current row, and it is the same
  criticism the paper makes of five other works.

### §10 Limitations
- Add the four new ones in §7 below.

### Headline
**Yes, the headline changes.** From *"85.7% of works demote under the weakest-link rule"* to a
two-part claim:

> **The cryptography in this literature binds acceptance, not action.** Seven of fifteen works verify
> a claim at cryptographic tier; eleven bound an action only at an application chokepoint; one does
> both, and it does so by putting the verifier on the far side of the call.

The demotion rate stays in the paper, correctly labeled as an action-column statistic and correctly
caveated as a selection-biased upper bound. It is no longer the sentence the paper is remembered for,
and it should not be: a demotion rate says the field is worse than it claims, while the two columns
say **which half is real, which half is missing, and what has to be composed with what**. The second
is the more defensible claim and the more useful one.

---

## 7. Honest limits

### 7.1 This is a re-score from stored records, not a re-reading
Every verdict above was produced from the stored decisive-pass coder records — quoted spans, tier
spans, cheapest-defeat derivations and notes — not from re-reading fifteen papers under the new rule.
That is defensible for column A, because the coders were required to quote, and in six of seven A-T1
works the promoting evidence is a span the coder had already extracted and written a paragraph about.
It is weaker wherever a column-A fact would have needed a *new* search of the source: a signature
scheme mentioned only in an appendix, an attestation flow in a figure, a key-management paragraph
neither coder had reason to quote. **The risk is one-directional and it runs against the artifact
hypothesis**: an unquoted cryptographic construction would push a work *up* into A-T1, so the A-T1
count of seven is a **floor**, not a ceiling. Before publication, the seven A-T1 rows and the seven
A-T3 rows should be re-read against column A specifically.

### 7.2 The coders are LLM agents, and the caveat is unchanged
Two opposed-stance prompts of the same model family. Their agreement is an upper bound on
reliability, not an estimate of it, and it is never reported as inter-coder reliability (§3.5.2).
**This re-score makes that caveat sharper, not weaker**, in a way worth writing down: the disagreement
analysis in §3 shows the instrument was *manufacturing* disagreements in at least one case and
suppressing correct readings in several others. Two prompts of one model share failure modes; they
also, evidently, share the discipline to record a finding they cannot score. Six coders wrote out an
A-T1 verdict in prose and then scored T3 per the rule. That is the behavior the repair was inferred
from, and it is one model family's behavior.

### 7.3 Selection makes every count in this document an upper bound
The decisive fifteen were selected for tier-axis power — six demotion candidates, six T2 anchors,
**three T1 candidates**. The acceptance column is therefore *enriched for cryptographic works by
construction*. **7 of 15 A-T1 must never be reported as a corpus rate**, exactly as 85.7% must not.
The full-pass number will be lower, probably substantially, because the screened corpus contains a
large prompt-injection and policy-enforcement cluster with no cryptographic layer at all.

### 7.4 One work is unscorable, and the floor was not applied in the other direction
Grimlock's action column is recorded `unscorable` under the specificity floor: the paper names eBPF
but never the hook family and never whether the program attaches in the host kernel or the agent's
own guest kernel — and its own named adversary is a runtime that attempts direct sockets and
alternate stacks, so that omission decides the question rather than decorating it. A v3 naming the
hook family and stating host-kernel attachment would make it scorable at B-T2 for reachability, still
capped by a payload-blind release gate.

**The floor should also cut the other way, and here it did not.** Several A-T3 verdicts in this batch
were reached over an explicitly considered A-NONE — SEAgent, CaMeL-NOVA and AgentCgroup all record
the alternative in their justifications. Each was scored A-T3 on the ground that *some* claim reaches
*some* relying party. A stricter reading pushes them to A-NONE, which would make the acceptance
column emptier at T3 and the corpus look **more** bimodal, not less. The A-T3 count of seven is
therefore the generous reading, and the boundary between A-T3 and A-NONE needs a written criterion
before the full pass. Proposed: *a work has an acceptance surface only if some party other than the
enforcing component acts on the verdict.*

### 7.5 ⚠️ The AARM row is partly reconstructed
The re-scored record for AARM (arXiv:2602.09433) arrived **truncated mid-sentence in the acceptance
justification**; its `tierOfAction`, `changedFromSingleColumn`, `coderDisagreementResolved` and
`narrowerT1Guarantee` fields were not delivered. The **A-T1 for receipt integrity is as supplied**.
The **B-T3 in the table above is reconstructed** from the two underlying codings, which is a
straightforward reading — both coders scored T3, both selected the chokepoint as the tier span, both
recorded the paper's own enumeration of uncovered paths (raw HTTP, direct database connections, local
filesystem access, shell execution, FFI, tools added after instrumentation), and the specification
itself bars an eBPF-only deployment from claiming conformance. The eBPF backstop remains a **narrow
B-T2 sub-guarantee over the static forbidden class only**, exactly as the charitable coder
recommended recording it.

The completeness caveat the truncated record was in the middle of stating should be verified before
publication, and on the coders' own evidence it reads: **signatures establish that issued receipts
are unaltered; they do not establish that every action produced a receipt.** An action that never
traverses the chokepoint generates no receipt at all, so the audit log is silently incomplete rather
than detectably tampered — a materially different property from the one the tamper-evidence rhetoric
implies, and one the enum cannot express. **Do not publish this row until the adjudicator confirms
both the action column and the caveat.**

### 7.6 Two residual disagreements are not tier questions, and the method does not yet adjudicate them
PAuth (coders read v1 and v2) and Caging the Agents (coders scored the deployed fleet and the
designed architecture) both leave a live disagreement after the columns are applied. Neither is a
defect the columns can fix. Both are artifact-selection questions, both were flagged by the coders
themselves, and both need a stated rule in §4 before the full pass.
