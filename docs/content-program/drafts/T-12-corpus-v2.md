# T-12 Corpus v2: The Decisive Coding Pass

**Companion artifact to [T-12](T-12-sok-authority-and-containment.md) · 2026-08-30 · coverage scored against [`ACTION-SURFACE-v1.1`](ACTION-SURFACE-v1.md)**

> **Provenance.** 30 coding records were read from disk at
> `aumos/docs/content-program/drafts/corpus-codings/`. **30 of 30 found; 30 of 30 report
> `fullTextRetrieved: true`.** That is two coders (conservative, charitable) on each of 15 works,
> with no truncation, no missing record, and no work scored from an abstract. The upstream defect
> that reduced the v1 pilot to two adjudicated works did not recur.
>
> These 15 works were selected for power on the tier axis, not at random. **The demotion rate in
> §3 is an upper bound on the corpus rate and must never be reported as a corpus rate.** §8 states
> this again at length because it is the number most likely to be quoted out of its selection.

---

## 1. Lead: what this pass shows, and what it overturns

Six findings, ordered by how much they change the paper. The first three contradict a prediction
the draft makes about itself.

### 1.1 · The weakest-link rule discriminates, and it discriminates far harder than the draft claims

**12 of 14 works with a scorable advertised tier demote: 85.7%.** Against the v1 pilot's 4 of 10
(40%), and against the delivered two-work pilot's 0 of 2. Five of the twelve fall two tiers.
Only **one work in fifteen scores at the tier it advertises under the rhetoric reading**, and it is
Sandlock, which is also the only work in the set whose prose declines to overclaim.

This is the finding the draft wanted and could not test. It is also the finding most damaged by
selection, and §8 says so.

### 1.2 · The T1 cell of the tier axis is not currently measuring anything, and that is a defect in the rule

Five works advertise cryptographic enforcement. **All five score T3 after adjudication.** In four
of them the coder who scored T1 wrote, in the same record, that a *narrower* guarantee is genuinely
T1 and proved. The collapse is not a property of the corpus. It is a property of the instrument:

> **T1 is "defeated by an actor that never consults the verifier." T3 is "defeated by any path that
> does not traverse it." For an agent-side guarantee these are the same sentence.**

Any work claiming that a compromised agent *cannot act* outside its authority is therefore T3 by
construction, no matter how sound its cryptography, because the agent can always write a file. The
rule cannot presently distinguish "the cryptography does not bind execution" (a real finding, and
the paper's §9 point about its own system) from "the guarantee was stated in agent-side terms" (a
sentence-level accident). §7 proposes the fix, and it is one column.

### 1.3 · Both T1 candidates and two of six T2 anchors split the coders, and every split went one direction

Scored-tier agreement fell from the pilot's 6 of 6 (100%) to **11 of 15 (73.3%)**. All four
disagreements are the charitable coder scoring higher. The conservative coder returned T3 on
**14 of 15 works**, which is a near-degenerate marginal: Cohen's kappa on scored tier is **0.268**
against a raw agreement of 73.3%. The raw figure is inflated by prevalence, and the paper must
report both or neither. See §4.

### 1.4 · E2 is not the least-covered effector, and E3 is never covered by anything

After adjudication the least-covered effectors are **E5 package install (12 of 15 `not-covered`)**
and **E4 VCS push (11 of 15)**. E2 subprocess spawn is third at 8 of 15. §3.2 of the paper calls E2
"the exclusion that inflates coverage most" and §5 predicts it will be least covered. On this pass
it is neither least nor tied for least.

The sharper result sits next to it. **E3 network egress is reached by 14 of 15 works and scored
`covered` by none.** Every system in the set touches egress; not one bounds it completely. That is
a better sentence than the E2 claim it replaces, and it lands on the same §6.4 target.

### 1.5 · Two `covered` cells in 105, and both belong to one work

**2 of 105 adjudicated cells scored `covered` (1.9%)**, both on Sandlock (E1, E2). The paper's §5.5
reports 17 of 140 (12.1%) from the earlier pass. The number moves by an order of magnitude in the
unflattering direction, and the modal cell remains `partial`. Thirteen of fifteen works fully
mediate **nothing**.

### 1.6 · The Schneider split held at 30 of 30, including the OS-tier and cryptographic-tier works

The pilot returned split on 20 of 20 and the obvious objection was that the pilot had sampled only
proxy-tier systems. This pass includes a Landlock/seccomp sandbox, an eBPF cgroup controller, a WASI
runtime, an Intel TDX trusted plane, and three signature-based capability protocols. **Every one
returned split.** Zero enforceable, zero non-enforceable, both coders, all fifteen works. The
prediction in §7.2 that split would be "modal" is too weak: across 25 works and 50 codings to date
over both passes, split is not modal, it is **universal**.

---

## 2. The decisive question: does anything score above T3?

**One work does: Sandlock, at T2, unanimously.** That is 1 of 15.

The set was built to test exactly this. Six works were selected as T2 anchors and three as T1
candidates:

| Selected as | Work | Advertised | Charitable | Conservative | **Adjudicated** |
|---|---|---|---|---|---|
| T2 anchor | Sandlock | T2 | T2 | T2 | **T2** |
| T2 anchor | AgentCgroup | T2 | T3 | T3 | **T3** |
| T2 anchor | MCP-SandboxScan | T2 | T3 | T3 | **T3** |
| T2 anchor | Caging the Agents | T2 | T2 | T3 | **T3** |
| T2 anchor | TDX trusted plane | T1 | T3 | T3 | **T3** |
| T2 anchor | Grimlock | T2 | T2 | T3 | **T3** |
| T1 candidate | PAuth | T1 | T1 | T3 | **T3** |
| T1 candidate | AIP | T1 | T3 | T3 | **T3** |
| T1 candidate | Heartbeat-Bound | T1 | T1 | T3 | **T3** |

Delta distribution across all 15 works, adjudicated: **Δ = 2 on five works** (PAuth, AIP,
Separation-of-Powers, TDX, Heartbeat-Bound); **Δ = 1 on seven** (MCP-SandboxScan, CaMeLs, SEAgent,
AgentCgroup, Caging, From Craft to Kernel, Grimlock); **Δ = 0 on two** (MiniScope on the mechanism
reading, Sandlock); **not computable on one** (AARM, which advertises a different tier per
architecture and is a specification rather than a system).

### 2.1 · Which is it: a finding about the field, or a defect in the rule?

**It is both, in a proportion that can be stated.** The T2 collapse is a real finding. The T1
collapse is a rule artifact. Here is the case for each, and it matters that they separate.

**The five T2 demotions are real, and they demote for five structurally different reasons.** A
scoring artifact produces one failure mode repeated. These produce five:

- **AgentCgroup.** The kernel enforcement is genuine. What is not genuine is *membership*. Limits
  bind whatever cgroup a process is actually in, and placement into the per-tool-call cgroup is
  performed by "a transparent bash wrapper [that] intercepts each `bash -c` invocation." A direct
  `execve`, a `sh -c`, or the sub-agent tool (17.3% of Haiku tool execution time, by the paper's own
  measurement) never enters an ephemeral cgroup. **An in-kernel mechanism placed downstream of a
  userspace placement step inherits the tier of that step.** Both coders reached this independently.
- **MCP-SandboxScan.** WASI is a genuine capability boundary. It is also, by the paper's own
  account, the minority path: "The real-world corpus primarily uses the native MCP path for
  unmodified servers." The T2 mechanism exists and is not on the path most of the traffic takes.
- **TDX trusted plane.** The hardware boundary protects the *decision*, not the *action*.
  "Actual interaction with protected resources is not performed by the trusted operation plane
  itself, but by constrained executors on the REE side." The words *descendant*, *child process*,
  *fork* and *subprocess* appear nowhere in the paper.
- **Caging the Agents.** The T2 layers are documented by the authors as unshipped. Table 3 places
  gVisor, the credential sidecar and NetworkPolicy in the "K8s Target" column, labeled "the current
  migration target." The measured 90-day fleet ran "Multi user" isolation and DNS filtering.
- **Grimlock.** The paper never names the eBPF hook family, never says whether the program attaches
  in the host kernel or in the agent's own confidential-VM guest kernel, and carries **evidence
  grade L0 from both coders**. There is no mechanism to identify, so there is nothing for §3.1's
  assignment procedure to score.

None of those is a sentence-level accident. Each is a named, quoted, checkable gap between an
advertised substrate and where the guarantee actually binds, and the through-line across all five is
the single most useful thing this pass produced:

> **The tier of a composite control is set by its weakest *placement* step, not by its strongest
> *enforcement* mechanism.** Four of the five T2 demotions are placement failures, not enforcement
> failures. The kernel works. Something in userspace decides what the kernel sees.

**The T1 collapse is a rule artifact, and the evidence is that the coders said so.** PAuth's
charitable record: the narrower guarantee is T1 and "there is no bypass cheaper than the crypto AT a
participating server." Heartbeat-Bound's conservative record: "a narrower guarantee ... IS genuinely
T1, and the paper proves it (Theorems 4.1 and 4.2)." AIP's charitable record: "the cryptographic
core is genuine and would be T1 for what a compliant verifier accepts." Separation-of-Powers,
conservative: "the crypto binds only what the dispatcher chooses to consult."

Four of four independent codings identify the same thing: **a cryptographic mechanism that is T1
for what a verifier accepts and T3 for what an agent can do, scored as one number.** Collapsing to
the minimum is correct under the weakest-link rule and it is the paper's whole point. But reporting
only the minimum destroys the information a practitioner needs, and it makes the T1 column
unpopulated by construction, which a reviewer will notice.

**Two further defects the pass exposed, both of which had to be papered over to adjudicate at all:**

1. **The rule has no evidence conditioning.** Sandlock scores T2 with a named LSM, stated
   `PR_SET_NO_NEW_PRIVS` inheritance semantics across `fork()`/`execve()`, and a ten-case behavioral
   micro-evaluation (L2). Grimlock advertises the same tier with an unnamed hook set and no
   implementation (L0). The rule as written cannot separate them; the §5 ruling had to import
   evidence grade into a tier decision, which the instrument does not authorize.
2. **The rule forces one tier per work on systems that are genuinely mixtures.** AgentCgroup is T2
   at the workload cgroup and T3 at the tool-call cgroup, which is its contribution. Caging is T2
   for host escape and T3 for the composite PHI claim. Grimlock is T1 crypto on T2 steering into a
   T3 decision point. The floor is a defensible score and a poor description.

**Bottom line.** Report the finding as: *systems advertising operating-system enforcement bind, in
this selected set, at the placement step above the kernel rather than at the kernel, and the failure
is consistent enough across five different mechanisms to be a design pattern rather than a sampling
accident.* Do **not** report "nothing scores T1" as a finding about the field. It is a finding about
the sentence in §3.1, and §7 fixes it.

---

## 3. Demotion table

Advertised tier is coded twice, per the amendment corpus-v1 §5.2 demanded and the paper has not yet
adopted: **by rhetoric** (title, abstract, framing) and **by mechanism** (the interposition
paragraph). The gap between the two columns is itself a measurement.

Δ is advertised-by-mechanism minus adjudicated scored, in tiers of demotion.

| Work | Rhetoric column, the paper's own words | Adv. by rhetoric | Adv. by mechanism | **Scored** | Δ |
|---|---|---|---|---|---|
| MiniScope | "our enforcement is mechanical and provides rigorous guarantees"; but also "serves as the 'firewall' between the agent and the services" | T1 | T3 | **T3** | **0** |
| MCP-SandboxScan | "WASM-based Secure Execution and Runtime Analysis for MCP Tools"; "a lightweight, capability-restricted runtime for containing untrusted code" | T2 | T2 | **T3** | **1** |
| CaMeLs Can Use Computers Too | "System-level Security for Computer Use Agents"; "structurally enforcing control flow integrity"; "architectural isolation provides the strongest guarantees" | T2 | T2 | **T3** | **1** |
| SEAgent | "a mandatory access control (MAC) framework built upon attribute-based access control"; policy syntax "inspired by SELinux" | T2 | T2 | **T3** | **1** |
| AgentCgroup | "in-kernel enforcement via sched_ext and memcg_bpf_ops"; "isolation is achieved entirely through container cgroup boundaries and eBPF hooks" | T2 | T2 | **T3** | **1** |
| AARM | "User-space code cannot bypass kernel enforcement without kernel compromise"; "Bypass risk: Lowest of any architecture" | T2 | unclear | **T3** | n/a |
| PAuth | "server-produced values are wrapped in signed envelopes that bind concrete values to symbolic provenance"; authority holds "even when the agent is compromised" | T1 | T1 | **T3** | **2** |
| Caging the Agents | "kernel level workload isolation using gVisor sandboxed containers on Kubernetes"; controls that "operate independently of the LLM's compliance with instructions" | T2 | T2 | **T3** | **1** |
| AIP | "Scope attenuation is cryptographically enforced"; "This is a cryptographic guarantee, not a runtime policy." | T1 | T1 | **T3** | **2** |
| From Craft to Kernel | "enforces security as a microarchitectural property"; "structural constraints that the PPU cannot override" | T2 | T2 | **T3** | **1** |
| Separation-of-Powers | "cryptographically constrained capability tokens"; "the system enforces safety regardless of agent behavior" | T1 | T1 | **T3** | **2** |
| TDX trusted plane | "hardware-backed protection"; "It cannot forge a valid authorization without the trusted operation plane" | T1 | T1 | **T3** | **2** |
| Heartbeat-Bound Credentials | "a cryptographic protocol that binds credential validity to periodic parent liveness proofs"; Table 8, "Bypass-proof: Yes" | T1 | T1 | **T3** | **2** |
| **Sandlock** | "static, input-independent policy is compiled into kernel-enforced rules"; separation "enforced by the kernel rather than trusted to the LLM's judgment" | T2 | T2 | **T2** | **0** |
| Grimlock | "eBPF ... enables OS-enforced, application-transparent mediation at the sandbox boundary"; "No-bypass enforcement" | T2 | T2 | **T3** | **1** |

### 3.1 · Rates

| Measure | This pass | v1 pilot (paper §5.4) | Delivered two-work pilot |
|---|---|---|---|
| Works with a scorable advertised tier | 14 of 15 | 10 | 2 |
| **Demotions, mechanism column** | **12 of 14 (85.7%)** | 4 of 10 (40%) | 0 of 2 |
| **Demotions, rhetoric column** | **14 of 15 (93.3%)** | not coded | not coded |
| Works scoring above T3 | **1 of 15** | 0 of 10 | 0 of 2 |
| Mean Δ over scorable works | 1.29 tiers | not reported | 0 |

**Under the rhetoric column, exactly one work in fifteen scores at the tier it advertises, and it is
the one work whose authors explicitly refuse to overclaim.** Sandlock's own record notes it
"repeatedly names what is not a boundary (argv matching, pipe content, cooperative resource caps)
and declares kernel bugs, side channels and privileged local attackers out of scope." That
correlation, honest prose and an honest score, is worth one sentence in the paper and no more, since
n = 1 supports nothing stronger.

### 3.2 · The rhetoric-versus-mechanism gap is a second, cleaner measurement

Three works advertise a strictly higher tier in their framing than in their own interposition
paragraph: **MiniScope** (T1 adjectives, self-described as a firewall), **AARM** (kernel-bypass-
resistance rhetoric, then a conformance clause stating that "Kernel-level (eBPF/LSM) implementations
alone cannot satisfy AARM conformance"), and to a lesser degree **CaMeLs** ("System-level Security"
in the title, a plan interpreter in the mechanism). Twelve of fifteen advertise consistently in both
registers.

That 3-of-15 rate is the honest answer to the question corpus-v1 §5.2 raised: **the demotion finding
is not mostly a rhetoric artifact.** Eleven of the twelve demotions survive under the strict
mechanism reading. The paper can therefore report the mechanism-column rate as the headline, which
is the defensible choice, and cite the rhetoric column as the sensitivity check.

### 3.3 · Comparison against the v1 pilot's 4 of 10 is not like-for-like

The pilot's 4 of 10 was drawn from a set with no T2 anchors coded. This pass was drawn from a set
built almost entirely of T1 and T2 claimants. **Neither rate estimates the corpus.** The pilot
rate is biased low by sampling the proxy-tier cluster; this rate is biased high by sampling the
overclaiming cluster. What can be said honestly is that the rule now has demonstrated
discriminating power in both directions: it demoted 12 works and it declined to demote Sandlock,
MiniScope's mechanism column, and (on the charitable stance alone) four others. A rule that demoted
everything would be worthless. This one does not.

---

## 4. Inter-coder agreement

**Standing caution, restated because it governs every number in this section.** Both coders are LLM
agents of the same model family differing only in a stance prompt. Their agreement is an **upper
bound on reliability, not an estimate of it.** Two prompts of one model share failure modes and will
agree on the same misreadings. Nothing here is inter-coder reliability, and no figure in this
section is eligible for a headline finding until human coding exists, per the paper's §3.5.2.

### 4.1 · Per axis, with denominators

| Axis | Raw agreement | Cohen's κ | Reportable? |
|---|---|---|---|
| Scored tier | **11 of 15 (73.3%)** | **0.268** | With the prevalence warning below |
| Advertised tier | 12 of 15 (80.0%) | 0.690 | Yes |
| Adversary placement, primary | 12 of 15 (80.0%) | 0.612 | Yes |
| Evidence grade | **15 of 15 (100%)** | 1.000 | Yes |
| Schneider verdict | 15 of 15 (100%) | **undefined** | Raw only, see §4.3 |
| Coverage, per cell | **74 of 105 (70.5%)** | **not computed** | Raw only, see §4.4 |

### 4.2 · Why the scored-tier kappa is reported, and why it is worse news than the raw figure

κ = 0.268 against 73.3% raw agreement. The gap is prevalence. The conservative coder returned **T3
on 14 of 15 works**; a near-constant coder agrees with anyone at a high rate by chance, so expected
agreement is 0.636 and the raw figure carries almost no information.

Three of the corpus-v1 §2.2 objections to computing kappa are now discharged: n is 15 paired works
rather than 1, the marginals exist, and v1.1 gave both coders the same nominal scale. So the
statistic is computable and refusing to compute it would be a convenience. **It is reported here
precisely because it is unflattering**: the raw 73.3% overstates the tier axis, and the paper should
report the pair or neither.

The same prevalence caution does **not** apply to placement (κ = 0.612 with a 10/10 modal category
and three others populated) or to evidence grade (κ = 1.000 across four populated categories).

### 4.3 · Why the Schneider kappa is undefined and must not be manufactured

All 30 codings returned `split`. With zero variance in both marginals, expected agreement is 1.0 and
κ is 0/0. **Undefined is the correct entry**, and a reader should read the 100% raw agreement as
what it is: two coders applying a three-value scale in which one value absorbed everything. That is
either the strongest agreement signal in the study or evidence that the column does not discriminate.
§6.3 argues it is the former and states the test that would settle it.

### 4.4 · Why no coverage kappa is computed

One objection from corpus-v1 §2.2 survives v1.1 intact: **the seven coverage cells of a work are not
seven independent observations.** They come from one reading of one text by each coder. Pooling
105 cells as an n = 105 sample would inflate apparent precision by exactly the amount the
within-work dependence is ignored. A per-work kappa on seven cells is degenerate. The figure
reported is raw agreement with its denominator, and nothing else.

### 4.5 · Did the explicit three-value rubric help? Yes, by about six points

**Coverage-cell agreement: 74 of 105 (70.5%) under v1.1, against the v1 pilot's 45 of 70 (64.3%)
under v1.1 and 39 of 70 (55.7%) under v1.0** (paper §5.5).

⚠️ **A discrepancy in the record that has to be flagged.** The paper's §5.5 reports 64.3% for a
10-work, 20-coding pilot. The companion document `T-12-corpus-v1.md` reports **14.3% (1 of 7)** on
the single doubly-coded work it received, and the `ACTION-SURFACE-v1.1` changelog cites **50%**.
These are three different pilots, or three different tallies of one pilot, all labeled "the pilot."
**The paper cannot cite all three.** Before submission, one figure must be designated the pilot of
record and the other two withdrawn or relabeled. This document compares against 64.3% because that
is the figure the paper itself carries.

**The improvement is real but modest, and it stops where the pilot predicted it would stop.** The
v1.1 amendments eliminated the entire class of pure label collisions: `not-applicable` appears
nowhere in these 30 records, and there is **not one disagreement in this pass in which the coders
read the text identically and differed only about which label to write.** That class is closed.

What remains is the class corpus-v1 §3.7 called "depth-of-mediation" and predicted would require
re-coding rather than re-labeling. It does. All 31 residual disagreements are substantive.

### 4.6 · The direction of coverage disagreement is uniform, and that is the finding

**All 31 coverage disagreements go the same way: the charitable coder scored higher.** Not 29 of 31.
All of them.

| Coder | `covered` | `partial` | `not-covered` |
|---|---|---|---|
| Charitable | 9 | 73 | 23 |
| Conservative | 1 | 58 | 46 |
| **Adjudicated** | **2** | **57** | **46** |

A 31-of-31 direction is not noise. It is the stance prompt operating as designed, and it means the
coverage axis is **stance-sensitive in a way the tier axis is not** (where four disagreements also
ran one way, but out of fifteen opportunities rather than thirty-one). The practical consequence:
a single-coder coverage pass would produce a systematically different heatmap depending on which
stance ran it, which is exactly the objection §3.2 anticipates when it says a reviewer will "call
this the authors' opinion rendered as a heatmap." **The two-coder procedure is not optional on this
axis.** It is the only thing standing between the number and that objection.

### 4.7 · Per-cell agreement

| Cell | Agreement | Note |
|---|---|---|
| E6 credential use | 14 of 15 (93%) | Highest. The §5A.3 published-credential-list cap makes this cell nearly mechanical |
| E3 network egress | 13 of 15 (87%) | The covert-channel rule resolves most cases |
| E7 sub-agent spawn | 12 of 15 (80%) | |
| E1 file write | 11 of 15 (73%) | |
| E2 subprocess spawn | 9 of 15 (60%) | |
| E5 package install | 8 of 15 (53%) | |
| **E4 VCS push** | **7 of 15 (47%)** | Lowest. Below chance-corrected usefulness |

**E4 and E5 are the two cells `ACTION-SURFACE-v1.1` §3 already flags as heuristic**, because they
are recognized by inspecting process arguments rather than by a distinct observation class. They are
also the two lowest-agreement cells here, on a purely derived pass with no instrumentation involved.
That convergence is worth stating in the paper: the two cells the enumeration marks as least
reliably *detectable* are the two cells two coders least reliably *derive*. It suggests the problem
is the effector definitions rather than the observation method.

### 4.8 · Agreement by work

Fully agreed vectors (7 of 7): **MiniScope, AgentCgroup, AARM**. Worst: **CaMeLs Can Use Computers
Too, 1 of 7**, which was also the worst work in the v1 pilot on a different paper. Works whose
mechanism is a single named chokepoint agree; works whose mechanism spans several layers do not.

---

## 5. The disagreement record

Seven substantive non-coverage disagreements, each adjudicated against a specific clause of the
frozen instruments. Thirty-one coverage disagreements, summarized by pattern in §5.8.

**Standing note on the adjudicator, carried forward from corpus-v1 §3.** These rulings were made by
the same program that wrote the enumeration and that ran the coders. That is a real dependency.
Every ruling cites the clause it turns on, so that a reader who rejects the clause can reject the
ruling without re-reading the paper. **Where a ruling turns on a clause the instruments do not
contain, that is stated in the ruling itself and recorded as a v1.2 trigger.** Two of the four tier
rulings are in that category, which is the most important procedural fact in this section.

---

### T-1 · PAuth, scored tier: T1 (charitable) versus T3 (conservative), ruled **T3**

**Charitable span and reasoning.** "The PAuthServer middleware is embedded in each MCP server and
intercepts every tool invocation at the server's tool-dispatch layer." Therefore "a subprocess or
sub-agent of the compromised agent cannot route around it, because there is no other door into that
server ... So there is no bypass cheaper than the crypto AT a participating server." The coder
explicitly rules that routing to a non-participating server "is not a defeat of the mechanism at all
— it is a failure to reach the effector, and per the rubric that is a coverage question."

**Conservative span and reasoning.** "In the evaluated build the interposition point is an in-process
enforcer sitting between the agent and a fixed table of local Python functions ('tools are local
functions and envelopes are stored in shared memory rather than carried in network messages'), with
no OS-level confinement of the agent process anywhere in the system." All 734 evaluation runs used
that build; the multi-host signed variant is "a mock demo with mock data" and carries no adversarial
evaluation.

**Ruling: T3**, on paper §3.1's assignment procedure, first step: *"enumerate the guarantee as
stated."* The guarantee PAuth states is agent-side. Its abstract claims that submitting a task
"implicitly authorizes exactly the operations its faithful execution requires, **even when the agent
is compromised**," and its design section claims the mechanism "prevents it from performing any
action that deviates from faithful execution." Scored against *that* guarantee, an agent that writes
a file, opens a socket, or calls one of the non-PAuth services the paper explicitly expects to
coexist ("Low-sensitivity websites can continue using OAuth") has performed an unauthorized
operation, and the mechanism it defeated is a per-call chokepoint. T3, per the §3.1 worked example.

**The charitable reading is correct about a different guarantee.** "No compliant participating server
accepts an off-task call" is genuinely T1 and the charitable coder's key-forgery analysis is right
about it. That guarantee is recorded as a **scope note**, per `ACTION-SURFACE-v1.1` §5A.2's
instruction to record stated design boundaries beside the vector rather than inside the cell.

⚠️ **This ruling exposes the §1.2 defect and does not resolve it.** The instrument's T1 defeat
condition and T3 defeat condition are the same event. The ruling turns entirely on *how the paper
phrased its guarantee*, which is not a security property. Recorded as **v1.2 trigger 1**.

---

### T-2 · Heartbeat-Bound Credentials, scored tier: T1 versus T3, ruled **T3**

**Charitable span.** The cheapest defeat is "NOT forgery ... The cheap move is to reach the effector
by a path that never presents a proof to an HBHC-verifying endpoint at all." Scored T1 anyway
because "the enforcement point is a third-party resource server running VerifyAuth over a
self-contained signed object, not an in-process hook whose bypass is the whole attack."

**Conservative span.** "The same integration pattern, which wraps tool calls with a cryptographic
auth check, works identically across LangChain-style, CrewAI-style, and OpenAI-SDK-style agent
frameworks with 14-18 lines of code." Therefore "the check lives in the caller's own address space
and the caller declines to call it. Cost: one line of code inside the compromised process."

**Ruling: T3**, on the same §3.1 clause and the same reasoning as T-1, reinforced by the paper's own
framing. Table 8 is captioned "HBHC provides identity-layer safety that cannot be bypassed by
application-layer attacks" and scores HBHC "Bypass-proof: Yes"; the conclusion says HBHC "constrains
whether a rogue agent **can act**." That is an agent-side guarantee, stated by the authors, and it
falls to a file write.

**Scope note.** Theorems 4.1 and 4.2 are genuine, proved, and T1 for the narrower property that a
compliant verifier will not accept a proof older than W_max + Δ_h + ε. The conservative coder says
so in its own record. **Same v1.2 trigger 1.**

---

### T-3 · Caging the Agents, scored tier: T2 versus T3, ruled **T3**

**Charitable span.** "gVisor implements a user space kernel (Sentry) that intercepts all system calls
from the containerized agent, filtering and mediating access to host resources." Cheapest defeat is
an over-broad capability, "which the T2 definition explicitly admits as a T2 defeat."

**Conservative span.** "The current migration target: Kubernetes with Temporal workflow
orchestration, gVisor runtime sandboxing, credential proxy sidecars, network egress policies, and
centralized logging." For the deployed fleet, Table 3 lists workload isolation as "Multi user" and
egress control as "DNS filtering."

**Ruling: T3, on two independent grounds, either sufficient.**

1. **The T2 mechanisms are not deployed, and both coders agree on this fact.** The charitable record
   concedes it in its own defeat analysis: "for the fleet as actually run during the 90 days, Table 3
   places gVisor, the proxy sidecar and NetworkPolicy in the unshipped 'K8s Target' column." Paper
   §3.1's assignment procedure requires identifying "the mechanism that would have to fail." A
   mechanism the authors describe as a migration target cannot fail; it is not there. The system as
   measured is bounded by DNS filtering, which a connection to a raw IP does not traverse. T3.
2. **Even in the target architecture, the advertised composite guarantee falls to a T3 defeat.** The
   advertised objective is PHI non-exfiltration. Every agent class carries at least one
   general-purpose, write-capable allowlisted destination (`api.anthropic.com` for all;
   `api.github.com` and `api.linear.app` for R&D; `hooks.slack.com` and `api.telegram.org` for
   operations). Exfiltration over an allowlisted destination crosses no kernel boundary and violates
   no NetworkPolicy. What stands between the agent and disclosure is the credential proxy's
   "request level policies: rate limiting, destination allowlisting, and payload size limits" plus
   the Layer 4 prompt rules, both application chokepoints the paper itself concedes are the brittle
   part.

**Scope note.** gVisor and NetworkPolicy are genuine T2 for host escape and for off-allowlist
destinations. Recorded beside the vector, per §5A.2.

**Why ground 2 does not also demote Sandlock, where both coders agreed on T2.** Sandlock's
conservative record raises the identical "exfiltrate through an allowlisted endpoint" defeat and
still scores T2, because Sandlock's *advertised guarantee* is capability separation, not
non-exfiltration: the paper states plainly that it "bounds stage capabilities, not pipe content."
Caging advertises the exfiltration property; Sandlock disclaims it. The rule scores the guarantee as
stated, so the two rulings are consistent, and the difference is entirely in what the authors chose
to claim.

---

### T-4 · Grimlock, scored tier: T2 versus T3, ruled **T3**

**Charitable span.** "Grimlock uses eBPF because it enables OS-enforced, application-transparent
mediation at the sandbox boundary. eBPF can interpose on ingress/egress, associate flows with stable
sandbox identity, and force all traffic through a controlled path." Reasoning: a subprocess "sits
inside the same mediated sandbox boundary," so unlike a proxy chokepoint it cannot be routed around.

**Conservative span.** "Traffic is then forwarded to the destination host, where the receiving guard
re-validates the attestation result, token scope, audience, expiry, and channel binding; terminates
TLS; and releases plaintext to the destination sandbox only after policy checks succeed." Reasoning:
"The guard validates the ENVELOPE of a flow ... and never the payload ... The chokepoint is defeated
by passing through it, not around it." Plus: "the paper never names the eBPF hook family
(cgroup/connect4, sockops, tc, XDP) nor whether the program is attached in the host kernel or inside
the agent's own CVM guest kernel."

**Ruling: T3**, on paper §3.1's assignment procedure: *"identify the mechanism that would have to
fail."* **No mechanism is identified in the source.** The hook family is unnamed, the attachment
point is unstated, and the work carries **evidence grade L0 from both coders** — claim only, no
implementation, no evaluation. A T2 assignment would rest entirely on the authors' word about a
mechanism they decline to specify.

⚠️ **This ruling imports evidence grade into a tier decision and the instruments do not authorize
that.** The evidence grade is explicitly "a column, not an axis" (paper §3.4). The ruling is made
anyway because the alternative is to score an unspecified mechanism at the tier of its vocabulary,
which is the exact failure the weakest-link rule exists to prevent. Recorded as **v1.2 trigger 2:
the tier rule needs a mechanism-specificity floor.** A reader who rejects the import should read
this row as T2 and adjust §2's count to 2 of 15.

**Contrast, and it is the useful part.** Sandlock advertises the same tier and scores it, because it
names the LSM (Landlock), names the filter (seccomp-bpf), states the inheritance semantics
("installed after PR_SET_NO_NEW_PRIVS and both inherited across fork() and execve()"), states its
failure mode ("If freezing or creation tracking is unavailable ... the syscall is denied with EPERM
rather than silently relaxed"), and evaluates ten deny/allow cases. **The T2 score tracks mechanism
specificity and evidence, not vocabulary.** That sentence is the finding this disagreement produced,
and it is worth more to the paper than the row it settles.

---

### P-1 · PAuth, primary placement: A4 (charitable) versus A2 (conservative), ruled **A4**

**Charitable span.** "Under our threat model, the agent is untrusted and may issue calls that deviate
from the task for any reason. **To evaluate PAuth without depending on a particular attack method,
we construct adversarial tool calls for each task.**"

**Conservative span.** "The agent is untrusted. It may be malicious or compromised. In particular,
the agent processes untrusted contents returned by tools and web endpoints, and prior work shows that
attackers can embed instructions in such contents to hijack the agent's behavior."

**Ruling: A4**, on the amendment adopted in paper §6.3: *"each work carries a primary placement — the
one its evaluation actually tests."* PAuth's evaluation constructs adversarial tool calls directly.
It runs no injection corpus and tests no untrusted-content vector. The adversary the experiment
instantiates sits inside the orchestrator emitting calls, which is A4. The conservative span is from
the motivation, not the evaluation, and is recorded as a **secondary** placement.

---

### P-2 · Caging the Agents, primary placement: A2 (charitable) versus A4 (conservative), ruled **A4**

**Charitable span.** "agent corruption via indirect prompt injection through external editable
resources."

**Conservative span.** "Any process running on the VM could read every credential the agent
possessed."

**Ruling: A4**, on the same §6.3 clause. The paper's only empirical content is the 90-day fleet audit
(evidence grade L1 from both coders), whose findings H1 through H4 are credential file permissions
and shell-rc credential exports readable by any local process. That is an A4 adversary, tested. The
A2 threat model is asserted and illustrated by case studies, not evaluated, and is recorded as
**secondary**.

**This ruling has a consequence worth its own line in §7.** For this work the *stated threat model*
and the *evaluated threat model* are different placements. §3.3 justifies the placement axis as
"extractable rather than derived, since G3 already requires a stated threat model." That
justification and §6.3's "the one its evaluation actually tests" are **two different coding rules**,
and this pass found two works where they give different answers.

---

### P-3 · AIP, primary placement: A1 (charitable) versus A4 (conservative), ruled **A4**

**Charitable span.** "We evaluated AIP against six attack categories, with 100 iterations per attack
(600 total attempts), under three deployment configurations."

**Conservative span.** "A delegatee that attempts to widen its granted scope beyond the parent
block's authority is prevented by Biscuit's check-all-blocks semantics."

**Ruling: A4.** The 600 attempts test scope widening, replay, and depth violation by a **delegatee**,
which is a participant in the delegation graph and therefore inside the system, not outside it. A1
is "outside the system entirely," and no attempt in the suite instantiates an outsider. The
charitable coder's span describes the evaluation's *shape* rather than its adversary.

### P-4 · What the three placement disagreements have in common

**All three are the same disagreement.** In each case one coder read the threat-model paragraph and
the other read the evaluation section, and they diverged because the two say different things. That
is a rubric gap, not a reading disagreement, and it is the placement-axis analog of what v1.0's
missing value set was to the coverage axis. **Recorded as v1.2 trigger 3.**

### 5.5 · Adjudicated placement distribution, and the composition result it unlocks

| Placement | n | Works |
|---|---|---|
| A1 outside the system | 1 | AgentCgroup |
| **A2 inputs or retrieved context** | **9** | MiniScope, MCP-SandboxScan, CaMeLs, SEAgent, AARM, From Craft to Kernel, TDX, Heartbeat-Bound, Sandlock |
| A3 policy or weights | 1 | Separation-of-Powers |
| **A4 inside the harness** | **4** | PAuth, Caging, AIP, Grimlock |
| A5 below the harness | **0** | — |

**This is the first pass to produce non-composing pairs.** Paper §6.3 records that "no non-composing
pair was observed, because the pilot has no pair to test," with nine of ten works at A2. This set
yields **36 A2 × A4 pairs**, which §6.1 defines as non-composing: the A2 control assumes the harness
is trustworthy and screens what enters it; the A4 control assumes the harness is compromised.
Deploying Sandlock alongside Grimlock, or MiniScope alongside PAuth, does not yield the union of
their guarantees.

**A5 remains empty across 25 works coded to date.** The one candidate interposing below the harness
was again not coded. Until it is, the composition matrix has an unpopulated row and column and the
paper should say so rather than draw the 5 × 5.

### 5.8 · Coverage disagreements, by pattern

Thirty-one disagreements, in exactly two patterns, plus zero of a third.

| Pattern | n | Adjudication rule | Ruled for |
|---|---|---|---|
| **A.** charitable `partial` vs conservative `not-covered` | 24 | `ACTION-SURFACE-v1.1` §5A.2: "A system that does not address an effector scores `not-covered`, not `not-applicable`" — and the corpus-v1 D-5 precedent that a constraint on an *adjacent* effector is not partial credit on this one | conservative, 24 of 24 |
| **B.** charitable `covered` vs conservative `partial` | 7 | §5A.3 depth rule (`covered` requires the guarantee to survive the transitive closure) and §5A.4 covert-channel rule (a contractually excluded channel caps at `partial`) | conservative, 6 of 7 |
| **C.** charitable and conservative differing by two steps | **0** | — | — |
| **D.** conservative scoring higher than charitable | **0** | — | — |

**The single Pattern B ruling that went to the charitable coder: Sandlock E2, ruled `covered`.**
§5A.3 states "E2 is `covered` only if descendant spawns are mediated," and Sandlock's text
affirmatively establishes that: the seccomp filter is installed after `PR_SET_NO_NEW_PRIVS`, cannot
be shed, and is inherited across `fork()` and `execve()`. That is the only cell in 105 where a
work's own text discharges the depth rule.

**Thirty of thirty-one rulings went to the conservative coder.** The pilot's six of six went the same
way. The correct reading, as corpus-v1 §3.7 argued, is **not** that the charitable coder was wrong
thirty times. It is that `ACTION-SURFACE-v1.1`'s counting rules were written to resist exactly the
inflations a charitable stance produces, and they resolved 30 of 31 disagreements mechanically,
without a judgment call about what any paper says. **That is the strongest available defense of the
coverage axis**, and it is a stronger claim than the pilot could make because the sample is five
times larger.

### 5.9 · Adjudicated coverage matrix

Legend: **C** covered · **P** partial · **–** not-covered.

| Work | E1 | E2 | E3 | E4 | E5 | E6 | E7 |
|---|---|---|---|---|---|---|---|
| MiniScope | P | – | P | – | – | P | – |
| MCP-SandboxScan | P | – | P | – | – | P | – |
| CaMeLs Can Use Computers Too | – | – | P | – | – | – | P |
| SEAgent | P | – | P | – | – | P | P |
| AgentCgroup | – | P | – | – | – | – | – |
| AARM | P | P | P | P | P | P | P |
| PAuth | P | – | P | – | – | P | – |
| Caging the Agents | P | P | P | – | – | P | – |
| AIP | – | – | P | – | – | – | P |
| From Craft to Kernel | P | P | P | – | – | P | P |
| Separation-of-Powers | P | – | P | – | – | P | P |
| TDX trusted plane | P | P | P | P | – | P | – |
| Heartbeat-Bound Credentials | P | P | P | – | – | P | – |
| **Sandlock** | **C** | **C** | P | P | P | P | P |
| Grimlock | – | – | P | P | P | P | P |

| Effector | `covered` | `partial` | `not-covered` |
|---|---|---|---|
| E1 file write | 1 | 10 | 4 |
| E2 subprocess spawn | 1 | 6 | 8 |
| **E3 network egress** | **0** | **14** | **1** |
| E4 VCS push | 0 | 4 | **11** |
| **E5 package install** | 0 | 3 | **12** |
| E6 credential use | 0 | 12 | 3 |
| E7 sub-agent spawn | 0 | 8 | 7 |
| **Total** | **2 (1.9%)** | **57 (54.3%)** | **46 (43.8%)** |

**Two observations the full pass must test.**

**E3 is the universal effector and nobody covers it.** Fourteen of fifteen works reach network
egress; zero bound it. Egress is simultaneously the thing every control claims to constrain and the
thing no control constrains completely. Under §6.4's Anderson cross-cut, that is a cleaner statement
of the "always invoked" failure than any per-work vector.

**The AARM row is uniformly `partial` and should probably not be a row at all.** AARM is a
specification describing four candidate architectures, one of which its own conformance clause
disqualifies. Every cell is `partial` because the specification reaches every effector in one
architecture and none in another. A specification is not a system, and scoring it on a system axis
produces a row that is arithmetically valid and semantically empty. §7 proposes it move to a stated
sub-population.

---

## 6. Schneider distribution

### 6.1 · The distribution

| Verdict | Codings | Works |
|---|---|---|
| Enforceable | **0** of 30 | **0** of 15 |
| **Split** | **30** of 30 | **15** of 15 |
| Non-enforceable | **0** of 30 | **0** of 15 |

**The pilot's 20 of 20 held at 30 of 30, and it held under the test designed to break it.** The
obvious objection to the pilot was that it sampled only application-chokepoint systems, where a
per-call predicate standing in for an information-flow objective is the expected shape. This set
deliberately includes a kernel LSM sandbox (Sandlock), an eBPF cgroup controller (AgentCgroup), a
WASI capability runtime (MCP-SandboxScan), a hardware TEE (TDX), and three signature-based
capability protocols (PAuth, AIP, Separation-of-Powers). **The split is invariant to the enforcement
tier.** Fifty codings across two passes, one value.

That is a real result and it is also a warning. A column with one value does not discriminate. §6.4
gives the test that would settle whether it is a finding or a broken instrument.

### 6.2 · Split cases: the surrogate against the advertised objective

All fifteen. Both halves are quoted or closely paraphrased from the coder records, which quote the
source.

| Work | Enforced surrogate (monitorable safety property) | Advertised objective (not monitorable) |
|---|---|---|
| MiniScope | Per-step scope containment: every executed tool call is permitted under the granted permission state ρ_j | "confining potential damage from unreliable LLMs" — non-leakage of sensitive data (information flow) plus alignment with user intention (not a trace predicate at all) |
| MCP-SandboxScan | WASI capability admissibility, plus a byte-level witness predicate over extracted sinks | Absence of confused-deputy flow from external input to LLM-visible fields. Authors concede: "a positive-evidence detector, not a complete information-flow system" |
| CaMeLs Can Use Computers Too | Control-flow integrity over the environment-blind plan's call graph | Agent performs only user-intended actions. Requires data-flow security the paper concedes it lacks: "It does not prevent data-flow attacks" |
| SEAgent | Deny any invocation whose path in the System View matches a prohibited attribute pattern | (a) Least privilege relative to intent, whose referent T_q "is oracle-defined and often not known in advance"; (b) "user-level non-interference," the canonical non-monitorable hyperproperty |
| AgentCgroup | Per-cgroup CPU and memory ceilings enforced at kernel allocation and dispatch points | Multi-tenant isolation in which all sessions complete, achieved by the agent voluntarily re-planning. "Declarations are advisory" |
| AARM | Per-action interception, static policy match, parameter validation, semantic-distance threshold, signed receipt | Non-exfiltration by composition and intent alignment. Authors: "Individual actions may satisfy policy while their composition violates security objectives" |
| PAuth | Per-call default-deny operand equality against compiled rules over signed envelopes | Faithful execution of NL intent, plus minimality of granted authority (a comparison across possible executions, hence a hyperproperty) |
| Caging the Agents | (a) No syscall to host except through the gVisor Sentry; (b) no egress outside the per-pod NetworkPolicy; (c) no raw credential in the agent container | PHI never flows to an unauthorized party (HIPAA 164.312(e)). The same allowlisted POST is compliant or a reportable breach depending on payload semantics |
| AIP | Per-request Ed25519 chain verification, subset attenuation, depth, expiry | Accountable provenance and non-misuse. "does not prevent a dishonest agent from misrepresenting results"; in-scope misuse explicitly out of scope |
| From Craft to Kernel | No Sink executes with an uncleared taint label; no trajectory prefix violates the FSM | Non-influence of untrusted data on sensitive operations, i.e. noninterference. VERIFY is a declassification primitive whose soundness is assumed |
| Separation-of-Powers | Per-action capability-token check against the static MinimalCapSet table, NLR hash anchor, blacklist veto | "Goal Integrity" — semantic faithfulness to originating intent, absence of coercion, non-disclosure. Authors: "Traceability ≠ Correctness" |
| TDX trusted plane | Per-operation authorization bound to action/object/scope/context/sequence, re-checked by the constrained executor | "confidentiality loss," "the externalization of protected resources," and multi-step chains "whose combined effect is more dangerous than any single step" |
| Heartbeat-Bound | VerifyAuth rejects any proof whose heartbeat epoch exceeds W_max by the verifier's own clock | "once the operator stops the orchestrator, no descendant performs any privileged action" — quantifies over all effect channels, including those presenting no proof |
| **Sandlock** | Kernel-enforced per-stage capability bound: no FS operation outside granted prefixes, no connect outside the pinned allowlist, no syscall in the seccomp deny set | Prompt-injection resistance via the "lethal trifecta": private data must not reach an externally communicating component. Authors: "Sandlock bounds stage capabilities, not pipe content" |
| Grimlock | No plaintext released into a destination sandbox without valid attestation, scope, audience, expiry and TLS channel binding | "least privilege, delegation propagates auditable, scoped permissions" end to end. "The guard authorizes the pipe and never inspects what travels in it" |

### 6.3 · The pattern is one pattern, and it is the paper's central finding

Read the right-hand column. **Fourteen of fifteen advertised objectives are information-flow
hyperproperties** — non-leakage, non-exfiltration, non-interference, non-influence, confidentiality.
The fifteenth (AgentCgroup) is a liveness objective over a non-deterministic model, which is outside
the class for a different reason.

Read the left-hand column. **Fifteen of fifteen enforced surrogates are per-event admissibility
predicates.** Different substrates, one shape.

> **The field is uniformly enforcing a per-event predicate and uniformly advertising an
> information-flow property. The enforcement tier changes what the predicate is enforced *by*. It
> does not change what the predicate *is*, and it does not close the gap to the objective.**

Sandlock proves the point most cleanly. It is the one genuine T2 anchor in the set, its mechanism is
a real in-kernel reference monitor, and its gap to its own objective is identical in shape to
MiniScope's, which is a Python decorator. **Moving from a decorator to an LSM changes the tier and
not the enforceability verdict.** That is a sentence the paper does not currently contain and it is
worth more than the tier delta.

### 6.4 · The test that would falsify the split column

A column returning one value on 50 codings is either a discovery or a broken instrument. The
discriminating test is cheap and should run before submission: **code three works whose advertised
objective is itself a safety property** — a rate limiter, a spend cap, a deny-list on a fixed
operation set, an append-only audit requirement. If those return `enforceable`, the column
discriminates and split is a finding about what this field claims. If they also return `split`, the
verdict is an artifact of how the coders identify "the advertised objective" and the column must be
rebuilt or removed.

Neither pass has attempted this. It is one batch of three works, and until it runs, §7.3's claim
that the split "may be the paper's central contribution" is unsupported by a negative control.

---

## 7. What this changes in the paper, section by section

### §3.1, enforcement tier: the largest required change

**Split the tier column into two scope-qualified tiers.** The current single value is a floor that
destroys information and leaves the T1 cell unpopulated by construction (§1.2, §2.1).

- **Tier-of-acceptance:** the tier that binds what a compliant verifier or enforcer will accept.
- **Tier-of-action:** the tier that binds what the agent can do, which is the weakest-link score.

Every T1-advertising work in this pass has T1 acceptance and T3 action, and in four of five the
coder wrote both numbers unprompted. Report the pair. The demotion finding then becomes sharper, not
weaker: *"five works bind cryptographically what a verifier accepts and bind nothing at all about
what the agent does."*

**Add a mechanism-specificity floor.** Insert into the assignment procedure: *a work may not be
scored above T3 unless the source names the specific enforcement mechanism (LSM, filter, hook family,
attachment point) and its inheritance semantics across `fork`/`exec`.* Without this the rule cannot
separate Sandlock from Grimlock, and the §5 T-4 ruling had to import evidence grade illegitimately.

**Rewrite the T1 and T3 defeat conditions so they are not the same sentence.** Proposed: T1 is
defeated by *forgery or by acceptance from a non-compliant verifier*; T3 is defeated by *any effector
path that does not traverse the chokepoint*. The current T1 row folds the T3 defeat into the T1
definition.

**Replace the ⟦Quantify from the screening pass⟧ placeholder** with the §3 table, both columns, and
the §8 selection caveat in the same paragraph. Not in a footnote.

### §3.2, coverage: one addition, one softening

**Add the 31-of-31 direction result (§4.6).** Coverage is stance-sensitive in a way no other axis is.
This converts the two-coder procedure from a methodological nicety into a load-bearing requirement
and is the strongest available answer to "the authors' opinion rendered as a heatmap."

**Soften the E2 framing.** "The exclusion that inflates coverage most" is not supported: E2 is third
by not-covered count behind E5 and E4. Replace with the E3 result, which is stronger and unambiguous
(§1.4).

**Add the E4/E5 convergence (§4.7).** The two effectors the enumeration flags as heuristically
*detected* are the two with the lowest derived-coding agreement. That is evidence the effector
definitions need work, not just the instrumentation.

### §3.3, adversary placement: resolve the two-rule conflict

§3.3 justifies the axis as extractable from the stated threat model. §6.3 defines primary placement
as the one the evaluation tests. **These are different rules and this pass found two works where they
disagree** (PAuth, Caging). Pick one, state it, and record the other as the secondary. Recommendation:
keep §6.3's evaluation-tested rule for the primary, since it is the rule that makes the composition
matrix mean something, and record threat-model placement as a separate coded field. The gap between
them is a publishable measurement of how far a threat model outruns its own experiment.

### §3.4, evidence grade: the empty L1 cell is no longer empty

§5.6 reports L1 = 0 and builds an argument on it ("the intermediate practice of verifying a mechanism
by inspection without testing it is nearly absent"). **Caging the Agents is L1 from both coders.**
Across the combined 25 works, L1 is rare rather than absent, and the sentence must change from
"nearly absent" to a stated count.

Combined evidence distribution for this pass (30 codings): L0 = 4, L1 = 2, L2 = 22, L3 = 2. Note
that **evidence grade is the only axis with perfect agreement and a well-behaved kappa (1.000)**,
which is worth one sentence: it is the axis a reviewer will trust most and it is currently demoted
to a column.

### §5.4, tier results: replace wholesale

Replace the 4-of-10 table with §3's 15-row table, both advertised columns, the 12-of-14 and
14-of-15 rates, the Δ distribution, and the selection caveat. **Delete the sentence "No work in the
pilot scored above T3."** It is now false: Sandlock does, unanimously.

### §5.5, coverage results: replace wholesale, and resolve the three-figure discrepancy

Replace 17 of 140 (12.1%) with **2 of 105 (1.9%)** and the §5.9 matrix. Replace the tied-least
claim with E5 > E4 > E2.

⚠️ **Then fix the pilot-agreement citation.** The paper says 64.3%; `T-12-corpus-v1.md` says 14.3%;
the `ACTION-SURFACE` changelog says 50%. Designate one as the pilot of record and withdraw the
others. A reviewer who reads the artifact will find all three.

### §6.3, composition: the first real result

Replace "no non-composing pair was observed" with the §5.5 distribution: 9 works at A2, 4 at A4,
**36 non-composing pairs**, named. Keep the A5 gap disclosed: A5 is empty across 25 coded works and
the matrix therefore has an unpopulated row and column.

### §6.4, reference-monitor cross-cut: strengthen with E3

The Anderson "always invoked" argument currently reads "a control that mediates three of seven
effectors is not always invoked." The available statement is stronger: **thirteen of fifteen works
mediate zero of seven effectors completely, and no work in the set completely mediates network
egress.**

### §7.1–7.3, enforceability: upgrade the claim and add the negative control

"Split is expected to be modal" understates the data. On 50 codings across two passes, split is
**universal and invariant to enforcement tier**. Add the Sandlock-versus-MiniScope comparison from
§6.3: the LSM and the Python decorator have the same enforceability verdict and the same
surrogate-to-objective gap.

**Then add §6.4's negative control as a stated, scheduled test**, and say plainly that until it runs,
the column has not been shown to discriminate. A reviewer will ask this on the first read.

### §9, the authors' own system: one word changes

§9 scores the system T3 with "the cheapest defeat is a subprocess spawn that never traverses the
protocol." That is now the modal finding rather than an act of self-criticism, which is exactly what
§3.5.1 predicted would happen and is an improvement. Under the two-column tier proposal the row
becomes **acceptance T1 / action T3**, which is both more accurate and more useful. Update the
coverage line to cite `ACTION-SURFACE-v1.1` rather than v1.0.

### §10, limitations: three additions

Add: the 31-of-31 stance direction on coverage; the prevalence distortion in the scored-tier kappa;
and the selection statement from §8 verbatim.

### Venue decision: the rule's first arm now fires, with a caveat

The stated rule: *"If agreement is high and the weakest-link rule produces clear demotions, target
SaTML."* Demotions are unambiguous at 12 of 14. Agreement is high on four of six axes (evidence
grade 100%, Schneider 100% raw, advertised tier 80%, placement 80%) and **not high on the two that
carry the headline findings**: scored tier at κ = 0.268, coverage at 70.5% with a uniform stance
direction.

**The honest reading is that the rule's first arm fires on the demotion clause and fails on the
agreement clause for exactly the two axes the paper leads with.** That is not a calendar decision;
it is a finding. Three things would settle it inside the SaTML window, and none requires new works:
human coding of the four tier disagreements in §5 (§3.5.2 requires this before any of them enters a
headline finding); the three-work enforceability negative control in §6.4; and the v1.2 amendments
in §7 above, which would mechanically resolve at least the T1 collapse.

---

## 8. Honest limits

**Selection, stated first because it is the limit most likely to be misread.** These 15 works were
chosen for power on the tier axis. Six were nominated at screening as T2 anchors, three as T1
candidates, and most of the remainder as demotion candidates whose rhetoric was flagged in advance.
**A set assembled to contain overclaimers will report a high overclaim rate.**

> **The 85.7% demotion rate is an upper bound on the corpus rate. It must not be reported as a
> corpus rate, in the abstract, in the introduction, in a talk, or in a figure caption. Any
> statement of it carries the selection sentence in the same breath.**

The v1 pilot's 40% is biased the other way, having sampled the proxy-tier cluster with no T2 anchors.
The corpus rate lies somewhere between and neither pass estimates it. Only a random sample of the
frozen population can, and that sample has not been drawn.

**Sample size.** 15 works, 30 codings, out of a screened population of 49 and a candidate pool of
322 of which 267 were never screened (paper §5.1). This is 31% of the screened population and under
5% of the candidate pool. No figure here is a corpus result.

**Machine coding.** Both coders are LLM agents of the same model family differing only in a stance
prompt. Every agreement figure in §4 is an **upper bound on reliability, not an estimate of it**.
Two prompts of one model share failure modes and will agree on the same misreadings. **No row in this
document has been human coded**, which means by the paper's own §3.5.2 standard **no row here is yet
eligible to enter a headline finding.** The four tier disagreements in §5 are the highest-value
targets for the first human pass, because each of them individually moves the §2 count.

**Adjudicator independence.** The rulings in §5 were made by the same program that authored
`ACTION-SURFACE-v1.1` and ran both coders. Each ruling cites the clause it turns on so the dependency
is inspectable, but it remains a dependency. **Two of the four tier rulings turn on clauses the
instruments do not contain** (T-1 and T-2 on how a guarantee happens to be phrased; T-4 on importing
evidence grade into a tier decision). Both are flagged in place and recorded as v1.2 triggers. A
reader who rejects the T-4 import should read Grimlock as T2 and adjust §2's count from 1 of 15 to
2 of 15.

**Coverage adjudication is mechanical, and mechanical is not the same as correct.** Thirty of
thirty-one rulings applied §5A.2, §5A.3 or §5A.4 without a judgment call about what the paper says.
That is the axis's defense and also its exposure: a reader who rejects the depth rule or the
covert-channel rule rejects thirty rulings at once. The rules are stated in the frozen instrument
precisely so that rejection can be specific.

**Full text.** **30 of 30 codings report `fullTextRetrieved: true`.** There is **no work in this set
whose full text could not be retrieved**, and none was scored from an abstract. The v1 pilot's
truncation defect did not recur: no record arrived truncated, no work is single-coded, and no coded
field is missing from any record.

**One work is not a system.** AARM is a specification describing four candidate architectures, one of
which its own conformance clause disqualifies. Its advertised tier is not computable, its coverage
vector is uniformly `partial` for a structural reason rather than an empirical one, and it is L0. It
is reported in every table with that flag. If it stays in the corpus it should be in a stated
sub-population of specifications, scored against a different question.

**Cohen's kappa is reported for three axes and refused for two, and the refusals are the load-bearing
ones.** Refused for coverage, because the seven cells of a work are not seven independent
observations. Refused for Schneider, because zero variance makes it undefined. Reported for scored
tier only with the prevalence warning, since the conservative coder's 14-of-15 T3 marginal makes
κ = 0.268 against 73.3% raw. **No kappa in this document is inter-coder reliability**, and any
future version that reports one must still label it stance-prompt divergence until human coding
exists.

**What was not tested.** No A5 work was coded, so the composition matrix still has an empty row and
column. No enforceability negative control was run, so the 30-of-30 split has no falsification test
behind it. No random sample was drawn, so no rate here estimates the population. Each of those is a
bounded, scheduled piece of work, and each is named above with what it would settle.
