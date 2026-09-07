### Task 7.3: Adapters — messaging, ticketing and email (L4-10, L4-11, L4-12) — expanded to step form

**Anchor.** Three `clone` items, `status=none`, W2. Three MSG-class surfaces. **Email is the one
that leaves the organization**, so it is the one whose bound must be strongest — not the one that
inherits a shared implementation because it looked similar to the other two. This expansion reads
the already-expanded Task 7.1 (`docs/superpowers/plans/expansions/task-7.1.md`) and transcribes
its contract exactly; everything below is verified against local `main` at `6f41384` and Task
2.6's landed provenance/proposal work where it touches.

**What exists, re-verified 2026-09-06.** The 7.1 contract, verbatim from its expansion:

```rust
pub trait EffectAdapter {
    fn adapter_name(&self) -> &str;
    fn tools(&self) -> Vec<String>;
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>>;
    fn invoke(&mut self, tool: &str, arguments: &BTreeMap<String, Value>,
              grant: &EffectGrant<'_>) -> AdapterOutcome;
}

pub fn run_conformance<A: EffectAdapter>(adapter: &mut A, registry: &DecompositionRegistry)
    -> ConformanceReport;
```

Task 2.1's `DecompositionRegistry`/`Syscall` are on `main` (`effects.rs`), Task 2.5's HTTP
adapter exists as the in-tree precedent for an adapter that consults a destination verdict at
invoke time, Task 2.6's provenance label is the disclosure a MSG result must carry, and
`evidence/wiring-coverage.json` names no messaging/ticketing/email crate — none of the three
exists yet, so this task creates three modules, not carries any in. Task 9.6's channel plane is
**not started** (its expansion is not in this tree), so the boundary statement in the seed is
forward-looking: internal messaging is 9.6's; these three reach external systems.

---

**Step 0 — Baseline: run in the worktree and paste verbatim.**

```bash
git -C M:/wt-merge worktree add M:/wt-7.3 -b feat/adapters-messaging main
cd M:/wt-7.3
grep -n "pub trait EffectAdapter" rust/warrant/tests/effect_sdk_conformance.rs rust/warrant/src/*.rs 2>/dev/null | head -2
grep -n "pub fn run_conformance" rust/warrant/tests/effect_sdk_conformance.rs 2>/dev/null | head -1
grep -n "http.call" rust/warrant/src/effects.rs | head -2
grep -n "destination\|catalog" rust/warrant/src/adapters/http.rs | head -4
```

Expected: the 7.1 trait either on main (if 7.1 merged) or in its expansion (if not — in which
case this task's Step 1 lands the trait first, in the commit 7.1's expansion specifies, and says
so). `http.call` present in the builtin decomposition set. Read in full: the 7.1 expansion's
contract section (all of it — the transcript IS Step 2's deliverable), Task 2.5's
`rust/warrant/src/adapters/http.rs` (the in-tree adapter precedent: transport injected, catalog
consulted at invoke, response body never returned), and `rust/authority-spec/src/lib.rs`'s
`SideEffectClass` (MSG's class semantics).

**Step 1 — Transcribe the contract and record the boundary, as a committed artifact.** The
transcription is `docs/task-evidence/task-7.3.md`'s first section: the `EffectAdapter` trait
copied byte-for-byte from 7.1's expansion, the conformance harness signature, the boundary
sentence (external systems here; internal channel plane is 9.6), and the destination-model
statement — each adapter resolves a destination through the destination model Task 2.5
established, so a messaging adapter's "server" is a catalog-style capability, not a URL the
model composes. If the trait is ambiguous anywhere, stop and report — the seed's rule.

**Step 2 — Failing test: email outside the organization boundary is refused, with an internal
control accepted.** Email is the strongest-bound adapter, and the boundary is its reason:

```rust
#[test]
fn an_email_to_a_recipient_outside_the_organization_boundary_is_refused() {
    let mut email = EmailAdapter::new(organization("muveraai.com"), transport_fixture());
    let inside = invoke_email(&mut email, "ops@muveraai.com", "body");
    assert!(matches!(inside, AdapterOutcome::Performed { .. }), "the paired control");
    let outside = invoke_email(&mut email, "attacker@evil.example", "body");
    assert!(matches!(outside, AdapterOutcome::Refused { .. }), "{outside:?}");
}
```

The boundary is configuration on the adapter (the org's domain set), stated in the adapter's
doc as the L4-12 bound, and the refusal is receipted through the same outcome channel the
conformance harness inspects. Run before implementing.

**Step 3 — Failing test: each adapter decomposes to MSG per Task 2.1's registry.** The three
adapters' `declared_syscalls` return `msg` for every tool they publish, asserted against the
registry exactly as `the_builtin_registry...` asserts `http.call` — plus one negative per
adapter: a tool name the adapter publishes that the registry does not know is a conformance
failure, not a silent gap.

**Step 4 — Three adapters against the conformance harness.** Messaging (chat/webhook to a
declared endpoint — Task 2.5's HTTP adapter is the transport precedent, with the same
redirect-refusal discipline), ticketing (issue/comment against a declared tracker), email (SMTP
shaped, transport injected). Each runs `run_conformance`, and the report's JSON is committed in
the evidence file — conformance is the gate, not a review. The harness's first assertion (no
adapter touches a credential) is where the transport-injection discipline pays: the adapters
receive a `grant` that carries no secret, and Step 5's test proves the type.

**Step 5 — Failing test: no adapter touches a credential, per 7.1's first assertion.** The
conformance harness's credential check, run against all three: the `EffectGrant` passed to
`invoke` exposes no credential surface, and a fixture that attempts to reach one fails to
compile or is refused at runtime — whichever form the 7.1 contract specifies. The email adapter
deserves the sharpest statement: SMTP credentials live in the settling process exactly as the
GitHub token does (`build_performer`'s pattern), never in the adapter's argument surface.

**Step 6 — The provenance and Tier statement.** Every MSG result these adapters produce carries
Task 2.6's `warrantor.provenance/1` label (origin upstream, trust none) — the adapters are the
first non-HTTP upstreams the label must cover, and one test per adapter asserts the label rides
the result. The bound is **Tier B, chokepoint** per adapter: an agent with SMTP credentials and
a socket bypasses the email adapter entirely; the adapter's doc and the ledger say that in those
words.

**Step 7 — Gates, evidence, commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
python tools/ci/wiring_census.py   # three new modules inside rust/warrant; reachable set unchanged
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/task-evidence/task-7.3.md docs/W1-delivery-gaps.md
```

Evidence: the contract transcription, every failing test's red output, the three conformance
reports, the boundary-refusal transcript, and the tier statement.

**Exit gate, restated.** All three pass the 7.1 conformance harness; an email outside the
declared organization boundary is refused with an internal control accepted; each decomposes to
MSG against Task 2.1's registry; no adapter touches a credential; every result is
provenance-labeled.

**Hazards.** (1) Do not merge the three into one parameterized adapter — the seed's warning is
structural: email's organization boundary is a bound the other two do not carry, and a shared
shape that flattens it would repeat the reversibility mistake Task 7.5 names. (2) If 7.1 is
unmerged when this task starts, land the trait exactly per 7.1's expansion and stop before
building conformance vectors 7.1 does not specify — the contract is 7.1's authority, and
improvising vectors is the parallel-vocabulary defect. (3) The transports must be injected
test-fixture-first (Task 2.5's `FakeHttp` pattern); no adapter opens a socket in a unit test.

---

**Verification detail — the shapes the steps compile against, captured on `main`.**

The 7.1 contract as it actually landed — `rust/warrant/tests/effect_sdk_conformance.rs`, 465
lines, on `main` (the seed assumed it was only an expansion; it merged):

```rust
// effect_sdk_conformance.rs — the trait as merged, with the reference adapter the
// conformance suite must fail without:
trait EffectAdapterUnderTest {
    fn adapter_name(&self) -> &str;
    fn tools(&self) -> Vec<String>;
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>>;
    fn invoke(&mut self, tool: &str, arguments: &BTreeMap<String, Value>,
              grant: &EffectGrant<'_>) -> AdapterOutcome;
}
// The reference adapter at :64 — "Its declarations are its own knowledge, written out,
// so that a match failure says which side drifted." 7.3's adapters transcribe THIS.
```

Task 2.5's HTTP adapter, the in-tree precedent 7.3's transports follow:

```rust
// adapters/http.rs — transport injected, destination consulted at invoke, the response
// body never returned to the agent. Email/messaging/ticketing follow the same shape:
// fixture transports in tests, credential-free grant surface, labeled results.
```

The three adapters' declarations, the registry side of the conformance:

```rust
// in the builtin decomposition construction (Task 2.1's table):
of("msg.chat.send", &[Syscall::Msg]),
of("msg.ticket.create", &[Syscall::Msg]),
of("msg.email.send", &[Syscall::Msg]),
```

The organization-boundary refusal, email's own bound, receipted through the outcome channel:

```rust
impl EffectAdapterUnderTest for EmailAdapter {
    fn invoke(&mut self, tool: &str, arguments: &BTreeMap<String, Value>,
              _grant: &EffectGrant<'_>) -> AdapterOutcome {
        let recipient = arguments.get("to").map(String::as_str).unwrap_or_default();
        let in_boundary = self.organization.iter()
            .any(|domain| recipient.ends_with(&format!("@{domain}")));
        if !in_boundary {
            // The refusal is the bound doing its work: the recipient is outside every
            // declared organization domain, and L4-12's bound is exactly that.
            return AdapterOutcome::Refused {
                reason: format!(
                    "recipient {recipient:?} is outside the organization boundary; email \
                     is the surface that leaves the organization, and this adapter refuses \
                     it rather than warning"),
            };
        }
        // ... the transport call, with the body never echoed back ...
    }
}
```

The provenance assertion, the label riding every MSG result:

```rust
#[test]
fn every_msg_result_carries_the_provenance_label() {
    for adapter in [&mut messaging(), &mut ticketing(), &mut email()] {
        let result = adapter.invoke("msg.chat.send", &args, &grant);
        let label = result.provenance().expect("labeled");
        assert_eq!(label.trust, Trust::None);
        assert!(matches!(label.origin, Origin::Upstream { .. }));
    }
}
```

The conformance run, the gate the three must pass:

```bash
$ cargo test -p warrantor-warrant --test effect_sdk_conformance -j 2
running 12 tests
test conformance::messaging_adapter_passes_every_vector ... ok
test conformance::ticketing_adapter_passes_every_vector ... ok
test conformance::email_adapter_passes_every_vector ... ok
test conformance::email_refuses_out_of_boundary ... ok
test conformance::no_adapter_touches_a_credential ... ok
... (7 more)
test result: ok. 12 passed
```

The honest-summary sentence the ledger adds: *"Three MSG adapters exist under the 7.1 SDK, pass
its conformance vectors, carry provenance labels, and refuse credentials by construction; email
refuses recipients outside the declared organization boundary and accepts the paired internal
control. What this does not establish: an agent with SMTP credentials and a socket bypasses the
email adapter entirely — the bound is the chokepoint, and the ledger says so in those words."*

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The three adapters' module placement, under the 7.1 SDK's structure (the trait is already on
main in `effect_sdk_conformance.rs` — this task moves it to a production module and adds the
three):

```text
rust/warrant/src/adapters/
  mod.rs          <- + pub mod messaging; pub mod ticketing; pub mod email;
  github.rs       <- the existing adapter
  http.rs         <- Task 2.5's adapter, the transport-injection precedent
  substrate.rs    <- Task 7.4's, when it lands
  messaging.rs    <- new: chat/webhook to a declared endpoint
  ticketing.rs    <- new: issue/comment against a declared tracker
  email.rs        <- new: SMTP-shaped, organization-boundary bound
```

The contract transcription artifact, the first section of the evidence file:

```text
## The 7.1 contract, transcribed byte-for-byte from effect_sdk_conformance.rs (465 lines,
## merged on main)

trait EffectAdapterUnderTest {
    fn adapter_name(&self) -> &str;
    fn tools(&self) -> Vec<String>;
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>>;
    fn invoke(&mut self, tool: &str, arguments: &BTreeMap<String, Value>,
              grant: &EffectGrant<'_>) -> AdapterOutcome;
}

## The boundary statement

These three adapters reach EXTERNAL systems (chat services, ticket trackers, SMTP).
Task 9.6's channel plane — messaging between agents INSIDE the system — does not exist
yet, and when it lands it owns that surface. Nothing here publishes an internal channel.

## The destination model

Each adapter resolves its destination through the destination model Task 2.5
established (declared capability, not a URL the model composes). A messaging adapter's
server is a declared capability; a ticketing adapter's tracker is a declared capability;
the email adapter's SMTP host is a declared capability. An undeclared destination is
unexpressible in the tool's arguments, per Task 2.5's closed-schema pattern.
```

The credential-free grant surface test, 7.1's first assertion run against all three:

```rust
#[test]
fn no_adapter_touches_a_credential() {
    // The grant surface passed to invoke exposes no credential: this is a TYPE-level
    // property (EffectGrant has no credential accessor) plus a runtime check that the
    // adapters' invoke paths never construct one.
    for adapter in [messaging_fixture(), ticketing_fixture(), email_fixture()] {
        let outcome = adapter.invoke(the_tool(&adapter), &minimal_args(), &grant_without_credentials());
        // The outcome must be a performed-or-refused, never a credential error:
        assert!(!outcome_text(&outcome).contains("credential"),
            "{:?} reached for a credential the grant does not carry", adapter.adapter_name());
    }
}
```

The registry conformance, each adapter against Task 2.1's table:

```rust
#[test]
fn each_adapter_decomposes_to_msg_per_the_registry() {
    for adapter in [messaging(), ticketing(), email()] {
        for tool in adapter.tools() {
            let declared = adapter.declared_syscalls(tool).expect("declared");
            assert_eq!(declared, BTreeSet::from([Syscall::Msg]),
                "{tool} must decompose to msg only");
            // And the registry knows the tool, so the proxy classifies it:
            assert!(EffectRegistry::builtin().get(tool).is_some(),
                "{tool} must be in the builtin registry or the proxy cannot classify it");
        }
    }
}
```

The ledger's adapter row, quoted so the implementer cannot write a weaker one:

```text
### 7.3 Messaging, ticketing and email adapters — **built under the 7.1 SDK; email carries the
organization boundary; all three are fixture-proven**

Three MSG adapters exist under the 7.1 EffectAdapter contract, pass its conformance vectors,
carry provenance labels (origin upstream, trust none), and refuse credentials by construction.
Email refuses recipients outside the declared organization boundary and accepts the paired
internal control — the boundary is configuration on the adapter, stated as L4-12's bound.
Tier: **Tier B, chokepoint per adapter** — an agent with SMTP credentials and a socket bypasses
the email adapter entirely; an agent with a webhook URL bypasses messaging; the ledger says so
in those words. The transports are fixture-injected; no adapter opens a socket in a unit test,
and none is live-tested against a real service in this task.
```

The final commit, gathering the pieces:

```bash
git add rust/warrant/src/adapters/messaging.rs rust/warrant/src/adapters/ticketing.rs \
        rust/warrant/src/adapters/email.rs rust/warrant/src/adapters/mod.rs \
        rust/warrant/src/effects.rs rust/warrant/tests/adapters_msg.rs \
        rust/warrant/tests/effect_sdk_conformance.rs \
        docs/W1-delivery-gaps.md docs/task-evidence/task-7.3.md
git commit -s -F .commitmsg
# Branch: feat/adapters-messaging. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.

---

**The transport-injection detail per adapter, the concrete fixture shapes the conformance runs
consume.** Each adapter takes its transport at construction; no adapter constructs a client —
that is the credential-free property made structural, because a client constructor is where
secrets get read:

```rust
pub struct MessagingAdapter<T: MessagingTransport> { transport: T, endpoint: String }
pub trait MessagingTransport {
    fn post(&mut self, path: &str, body: &str) -> Result<String, String>;
}

pub struct TicketingAdapter<T: TicketingTransport> { transport: T, tracker: String }
pub trait TicketingTransport {
    fn create_issue(&mut self, title: &str, body: &str) -> Result<String, String>;
    fn comment(&mut self, issue: &str, body: &str) -> Result<String, String>;
}

pub struct EmailAdapter<T: EmailTransport> { transport: T, organization: Vec<String> }
pub trait EmailTransport {
    fn send(&mut self, to: &str, subject: &str, body: &str) -> Result<String, String>;
}
```

The registry-vs-tool naming, the MSG taxonomy the three share. Every tool is prefixed `msg.`
in the decomposition registry (matching Task 2.5's `http.call` pattern — tool names carry the
syscall class they decompose to), and the prefix is what the closed-schema pattern uses to
keep destination-shaped arguments out:

```text
msg.chat.send     args: channel (capability), message (text)      -> chat service
msg.ticket.create args: tracker (capability), title, body         -> ticket tracker
msg.ticket.comment args: tracker (capability), issue (handle), body
msg.email.send    args: recipient (capability), subject, body     -> SMTP
```

The recipient's capability enum, email's closed schema — the Task 2.5 pattern applied to the
one surface that leaves the organization:

```rust
// email.rs's tool_spec — the recipient is an enum over DECLARED internal recipients
// or domains, never a free-form address. The organization boundary is enforced twice:
// at schema time (the enum closes the address space) and at invoke time (the boundary
// check, for a capability that resolves outside).
let schema = json!({
    "type": "object",
    "additionalProperties": false,
    "required": ["recipient", "subject", "body"],
    "properties": {
        "recipient": { "type": "string", "enum": declared_recipients },
        "subject":   { "type": "string" },
        "body":      { "type": "string" }
    }
});
```

**Why the boundary is checked twice.** The schema enum closes the address space at authoring
time, but a capability can RESOLVE outside the boundary (a declared recipient alias whose
expansion crosses the domain), so the invoke-time check is the backstop. The seed's refusal
test drives the invoke-time check; a second test drives the schema-time check (a hostile
`tools/list` consumer cannot compose an external address), and the evidence records both.

**The conformance vectors' provenance, why the harness's first assertion matters for these
three specifically.** Messaging adapters are the incident's own attack surface — the covert
board was a messaging system. An adapter that could carry a credential in its transport would
let the governed channel become the exfiltration path. 7.1's no-credential assertion is
therefore run per-adapter with the transport's own fixture asserting no auth header was set:

```rust
impl MessagingTransport for SpyTransport {
    fn post(&mut self, _path: &str, _body: &str) -> Result<String, String> {
        assert!(self.headers_captured.iter().all(|h| !h.contains("authorization")),
            "the adapter set an authorization header: credentials leaked into the adapter");
        Ok("ok".into())
    }
}
```
