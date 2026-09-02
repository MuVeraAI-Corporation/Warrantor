# Alibaba Open Agent Auth artifact and standards-conformance review

Status: pinned artifact reproduced; supporting comparator retained; production-enforcement and
standards-conformance claims bounded  
Reviewed: 2026-08-30  
Repository: <https://github.com/alibaba/open-agent-auth>  
Pinned commit: d75da121a66f8b2ae5be009a98e050fd1dc4c1e6  
Pinned commit date: 2026-03-15T11:01:03+08:00  
License: Apache-2.0  
Primary protocol: <https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/>  
Current WIMSE WPT draft: <https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/>  
W3C VC baseline: <https://www.w3.org/TR/vc-data-model-2.0/>  

## Decision

**Retain Open Agent Auth as supporting W2/W4/W6 and MCP prior art, consume selected protocol and
test ideas, but reject the reviewed beta as a production authority, delegation, MCP enforcement or
immutable-audit boundary.** It is a substantial, unusually test-rich Java prototype. The complete
13-module build passed; the aggregate reports contained 6,617 tests, 6,510 executed passes and 107
default-skipped integration tests. With six sample services running, a dedicated protocol profile
then executed 226 tests with zero failures, errors or skips. Weighted JaCoCo coverage across the
module reports was 84.61% line and 67.61% branch.

Those results do not establish the stronger security claims. When the repository's broader
authorization, JWKS, security and five-layer integration classes were enabled against the same
running services, 107 tests executed and 13 failed. The failures included absent OpenID discovery,
missing ETag behavior, invalid authorization requests returning 200, malformed token requests
returning 500 and PAR behavior that did not match its own expected contract. The protocol profile
and the broader integration gate therefore measure different surfaces; the former cannot be used
to erase the latter.

Artifact inspection found more consequential authority gaps. Delegation-record documentation says
that every authorization-server signature is verified, but the implementation checks only that the
signature string is non-empty. Layer-four identity consistency silently succeeds when the optional
binding store is absent. The WPT implementation binds tokens to a workload key and optionally to
other token hashes, but not to the exact target URI or HTTP request required by the current WIMSE
WPT draft. Agent-supplied Rego can be registered without parsing or semantic review. The MCP server
surface is a validation wrapper rather than a demonstrated transport-level interception hook. The
default audit store is deletable in-memory state, and the JWT evidence format is not demonstrated
to conform to W3C Verifiable Credentials Data Model 2.0 or current VC JOSE/COSE.

The current project roadmap itself places agent-to-agent authorization and delegation in future
work. Open Agent Auth therefore does not disprove Warrantor's narrower proposed differentiation
around exact multi-principal intersection, complete chain integrity, holder binding, non-bypassable
forwarding, action/effect receipts, durable revocation and cross-stack conformance. It does disprove
any suggestion that signed agent-operation tokens, user-consent policy references, workload-key
binding, MCP authorization wrappers or semantic audit records are empty categories.

Warrantor should track the IETF work directly, reuse negative and interoperability vectors, and
build only the missing assurance seams. It should not fork the entire framework or advertise
compatibility until current-draft, independent-implementation and complete-mediation gates pass.

## Source standing, version and independence

The reviewed head had 33 commits. It is an Alibaba-authored public repository and the same project
supplies the implementation, documentation, conformance tests and sample services. No independent
security assessment, standards certification, second interoperating implementation, production
deployment evidence or formal verification was located in this wave.

Version signals are internally inconsistent:

- the root Maven version is `0.1.0-beta.1-SNAPSHOT`;
- the README badge and prose call the release `v0.1.0-beta.1` and public beta;
- the changelog heading is `1.0.0.beta.1`;
- the security policy says `1.0.0.x` is supported and versions below `1.0.0` are unsupported; and
- artifacts are not published to Maven Central and must be installed locally.

The most conservative interpretation is a pre-1.0 public beta whose support status is ambiguous.
The README explicitly warns against mission-critical use until 1.0 even while using
“enterprise-grade” and “feature-complete” language. Those labels are aspirations, not independent
operational evidence.

The repository cites an Agent Operation Authorization Internet-Draft. The current reviewed draft
is an individual, intended-Standards-Track proposal, not an IETF consensus standard. The current
WIMSE workload proof draft also changed after the pinned repository commit. Compatibility must be
versioned by exact draft revision and tested; “IETF-aligned” is not equivalent to “IETF standard.”

## Reproduction environment

The public source was cloned and checked out without modification. Toolchains were obtained from
official distributions and checksums were verified before use.

| Component | Pinned reproduction input |
|---|---|
| Repository | `d75da121a66f8b2ae5be009a98e050fd1dc4c1e6` |
| Apache Maven | 3.9.16; official archive checksum verified |
| Eclipse Temurin JDK | 17.0.20.1+1; SHA-256 `3808d1d15e3ec6bd5b84057fb5d84c33d8a1536a258146bcea2e603fc726e08e` |
| Aggregate build | `clean verify` with the repository aggregate-report profile |
| Live services | Six sample services on ports 8081–8086, `mock-llm` profile |
| OPA integration | Not run; no OPA binary/service was available and the class requires port 8181 |
| Browser E2E | Not run; Chrome/Chromium was unavailable |

Maven 3.9.16 was itself checked against the Apache SHA-512 value
`831a8591fe20c8243b1dbe7d71e3244f31d1665b0804b2e825e38cbbe5ce0cafb8338851f90780735568773e0a6cd07bbec107cda0b896b008b861075358b6f6`.
The missing Maven Failsafe plugin version generated a build-model warning and remains a
reproducibility concern even though the reviewed build completed.

## Reproduction receipt

| Surface | Reproduced result | Assurance interpretation |
|---|---:|---|
| Full 13-module build | Passed in approximately 6 minutes | Strong buildability evidence at the pinned commit |
| Default Surefire reports | 6,617 tests; 0 failures; 0 errors; 107 skipped | 6,510 executed passes; default success excludes important integration paths |
| Core module | 3,704 tests; 9 skipped | Broad first-party unit coverage |
| Framework module | 1,271 tests; none skipped | Broad first-party framework coverage |
| MCP adapter module | 114 tests; none skipped | Wrapper behavior is tested; complete transport mediation is not |
| Starter module | 1,071 tests; none skipped | Configuration/wiring coverage, not deployment assurance |
| Sample modules | 359 tests; none skipped | Demonstration-path coverage |
| Aggregate line coverage | 84.61% | Supports an over-80% line statement for reported modules |
| Aggregate branch coverage | 67.61% | Does not support an unqualified over-80% coverage statement |
| Live protocol profile | 226 tests; 0 failures/errors/skips | Strong self-conformance across the six sample services |
| Broader live integration gate | 107 tests; 13 failures; 0 errors/skips | Current sample deployment does not satisfy its own broader integration expectations |
| Targeted delegation/identity/policy registry suite | 53 tests; 0 failures/errors/skips | Reconfirms the reviewed code paths; some passing expectations explicitly encode placeholder signatures and fail-open no-store behavior |
| OPA live tests | 7 tests not executed | External PDP integration remains unverified |
| Browser E2E | Not executed | Human login/consent and full browser flow remain unverified in this review |

The CI workflow enforces only 50% overall coverage and 60% for changed files. The README's
“test coverage > 80%” is defensible only when explicitly limited to aggregate line coverage in this
reproduced configuration. It is not a branch-coverage, mutation-coverage, integration-success or
security-efficacy guarantee.

## Green protocol profile versus red integration gate

The live protocol profile started all six sample applications and executed OAuth token exchange,
token endpoint, OIDC discovery, JWKS, PAR, ID-token, dynamic registration, interoperability and
WIMSE credential checks. All 226 checks passed. This is meaningful first-party conformance evidence
for the endpoints and expectations selected by that profile.

The broader integration selection then exercised four different classes against the same sample
deployment:

- `FiveLayerValidationIntegrationTest` passed its 29 checks;
- `SecurityIntegrationTest` passed its 38 checks;
- `JwksEndpointIntegrationTest` contributed four failures; and
- `OAuth2AuthorizationFlowIntegrationTest` contributed nine failures.

The combined total was 107 tests, 94 passes and 13 failures. The material failure classes were:

| Failure class | Observed result | Why it matters |
|---|---|---|
| OIDC discovery | `/.well-known/openid-configuration` returned 404 | Discovery and JWKS consistency are not available at the endpoint expected by the project's own integration contract |
| JWKS conditional caching | ETag absent; conditional request expectations failed | Key distribution/caching behavior is incomplete relative to the authored tests |
| Authorization redirect | Valid and invalid requests produced 200 where 302 or 400 was expected | Error and redirect semantics can blur allow/deny state and client behavior |
| Invalid client/redirect | Requests expected to be rejected returned 200 | Sample-path negative authorization behavior is inconsistent with the test contract |
| Token endpoint errors | Invalid or missing grants returned 500 rather than 400 | Malformed input escapes into server error semantics |
| PAR flow | Valid PAR request returned 400 and the subsequent request URI was absent | The broader PAR integration path is not coherent with the deployed sample configuration |

Some failures may be profile, endpoint or test-harness drift rather than exploitable production
defects. That distinction does not make the gate green. A release claim must identify the intended
configuration, make every applicable suite pass there, and delete or quarantine obsolete tests
rather than letting two first-party suites certify incompatible contracts.

## Authority and delegation findings

### 1. Delegation signatures are checked for presence, not validity

`OperationAuthorizationValidator.verifyDelegationChain` documents four tasks, including verification
of every authorization-server signature. `verifyDelegationRecord` checks the delegator token ID,
identity object and non-future timestamp, then accepts any non-empty `as_signature`. Its tests use
literal values such as `signature_001` as successful inputs.

The outer AOAT JWT signature can authenticate the current token bytes. It does not independently
establish that every embedded delegation record was signed by its alleged authorization server,
that the issuer was authorized for the hop, or that a verifier can validate the chain after records
are separated, transformed or composed. The current AOAT draft requires each entry to be verifiable
and says cumulative delegated scope must not exceed original authorization.

Required Warrantor treatment:

1. define canonical bytes for every hop and verify issuer key, algorithm, purpose, validity and
   status;
2. link each hop to the previous token/record and intended recipient holder key;
3. enforce monotonically narrowing cumulative scope, policy, time, quota and output authority;
4. require an expected root and complete-chain commitment; and
5. fail closed on missing keys, unsupported algorithms, unknown critical fields, incomplete chains
   or unverifiable records.

### 2. There is no exact multi-principal intersection engine

The reviewed validator does not compute the intersection of initiating principal, delegator,
agent, resource owner, tenant, environment and current-risk authority. It does not define conflict
or deny precedence, cumulative narrowing across hops, cross-hop context continuity, quota
consumption or policy-version composition. Presence of a `delegation_chain` array is therefore not
equivalence to W6.

The README roadmap separately lists agent-to-agent authorization, delegation support and related
flows as future work. This is strong internal evidence that the beta should not be presented as a
completed delegation-chain product.

### 3. AOAT validates a signed container more strongly than its semantics

The AOAT path performs real outer-token signature, expiry, issuer/audience and required-field work.
Several semantic requirements remain weak or absent: future `iat`, unique/replay-protected `jti`,
non-empty subject semantics, identity-to-binding continuity and exact policy meaning are not all
enforced as one coherent authority decision. A signed reference to `policy_id` authenticates the
identifier, not the semantics, existence, version, availability or faithful evaluation of that
policy.

## Identity and request binding findings

### 1. Layer four fails open when its binding store is absent

`FiveLayerVerifierFactory` accepts a nullable binding-instance store and always constructs
`IdentityConsistencyValidator` with it. When null, the validator logs a warning, skips both user and
workload identity consistency checks, and returns success. Unit tests explicitly expect validation
to pass regardless of the WIT subject when no store is configured.

This is not merely reduced assurance hidden from the result; the named five-layer verifier reports
layer four success. A security profile should either require the binding store and fail startup, or
return an explicit `not_evaluated`/`indeterminate` result that policy can reject. It should never
translate unavailable identity evidence into a positive consistency decision.

### 2. WPT binds keys and tokens, not the exact HTTP request

The generator creates `jti`, `exp`, `wth` and optional other-token hashes and signs with the key
identified by the WIT confirmation claim. That is useful proof-of-possession structure. The
generator does not accept or populate an intended target URI. The validator's required-claim check
requires only `wth`; it does not enforce target audience, unique replay state, exact media type or a
reasonable short lifetime as one current-draft profile.

The current WIMSE WPT draft requires the target URI audience and binds presented transaction or
other tokens through `tth`/`oth` when applicable. Without exact method, target, canonical request
arguments/body, token set and replay state, a valid WPT can authenticate possession without proving
that the authorized request is the one forwarded. Warrantor must bind the decision and the real
forwarded operation under one immutable operation ID and digest.

### 3. Draft drift is an interoperability risk

Parser and serializer comments list fields such as `aud`, `tth` and `oth`, but support for parsing a
field is not equivalent to requiring it. Warrantor should maintain revision-specific conformance
profiles, reject ambiguous cross-revision tokens and run fixtures from at least one independent
implementation. It should not inherit an older-draft interpretation through copied source.

## Policy and consent findings

### 1. Agent-originated policy is accepted without a trusted compiler boundary

The framework can transform an agent operation proposal into Rego and register that text. The
in-memory registry validates that the policy and creator strings are non-empty, but it does not
parse Rego, restrict built-ins, prove input completeness, establish deny precedence, type-check
fields, version the target semantics or statically reject unsafe constructs at registration.

The lightweight evaluator is a limited Rego-shaped parser, while the OPA path depends on an
external service. Treating both as “Rego” does not establish semantic equivalence. W4 should own a
closed, typed intermediate representation, emit explicit loss/unsupported diagnostics, and run
differential decisions across target engines.

### 2. Human consent is not automatically policy comprehension

The default operation text renderer can show an original prompt where one is present and otherwise
falls back to a short policy-text fragment. A consent page that says an operation was authorized
does not prove that the user saw the exact resource, method, data fields, recipient, cost, expiry,
delegation ability or output channel enforced by the policy.

Warrantor should sign a human-review projection and a machine policy under the same policy digest,
record locale/version/rendering, and test that every material machine constraint appears in the
review projection. Ambiguity or truncation must fail closed for high-risk actions.

### 3. The policy input is useful but does not prove complete mediation

The MCP/HTTP validator can expose method, URI, headers and body to policy. This is a strong input
shape for exact tool-and-argument authorization. It still requires a non-bypassable enforcement
point and proof that the bytes evaluated are the bytes forwarded. A caller can otherwise validate
one representation and invoke another path or mutate the request after the decision.

## MCP mediation findings

The adapter supplies a generic `callTool` client wrapper, a credential-header customizer and a
server-side authorization wrapper/interceptor. The reviewed main source does not contain a concrete
MCP transport registration proving that every request on a real server is routed through
`OpenAgentAuthMcpServer`. Direct clients, alternate transports, another route or application code
that calls the underlying tool registry can bypass an SDK wrapper unless the host integration
prevents it.

The wrapper records denial paths, but the reviewed class does not establish immutable records for
every successful and failed access attempt. “Intercepts all requests,” “seamless integration” and
“audit all access attempts” must remain unverified until a complete runnable transport fixture
proves:

- wrapper omission prevents startup or access;
- raw JSON-RPC, streaming, batch, cancellation and protocol-error paths are mediated;
- the authorized tool name and canonical arguments equal the forwarded call;
- redirects, retries and nested/sub-agent calls cannot escape the decision;
- result/output policy is applied before data leaves the boundary; and
- one signed receipt links request, policy decision, forward, result and effect.

For Warrantor, consume the header/token projection ideas and negative tests, not the assumption that
an SDK helper is a security boundary.

## Audit and Verifiable Credential findings

### 1. Signed evidence is useful but not demonstrated VCDM 2.0 conformance

The JWT evidence encoder uses a VC-like claim with scalar `type` and older
`issuanceDate`/`expirationDate` fields. The reviewed encoding does not supply the required VCDM 2.0
JSON-LD context or demonstrate the current `vc+jwt` secured format and processing rules. The
verifier checks cryptographic signature, algorithm policy, selected issuer/time conditions and
configured required claims; it does not implement full VCDM processing, credential status, schema
validation or semantic truth verification.

The correct claim is “signed JWT audit evidence modeled after Verifiable Credentials,” unless and
until an official/current conformance suite passes. W3C verification authenticates issuer and
integrity under a proof mechanism; it does not prove that an asserted user intent, policy decision,
resource effect or narrative is true.

### 2. The default audit store is not immutable

`AuditFactory` defaults to `InMemoryAuditStorage`. The API permits deletion by age, and the
implementation exposes `clear`. State disappears on restart. The AOAT itself may be tamper-evident
while signed, but the surrounding event population is neither durable, append-only nor
completeness-proven.

Warrantor must separate:

- authentic individual record;
- durable append-only storage;
- ordered/linked history;
- authorized redaction and retention;
- independently witnessed registration; and
- authenticated expected-set reconciliation for missing or late records.

Calling one of these “immutable audit” does not establish the others.

## Supply-chain and operational findings

| Boundary | Reviewed evidence | Required disposition |
|---|---|---|
| Release maturity | Public beta; local Maven install; 1.0/security audit/Maven Central are roadmap items | Do not use as a supported production dependency without an owned fork/profile and acceptance gate |
| Security support | Version labels conflict with the support table | Obtain explicit supported-version statement and patch process before adoption |
| Build model | Full Maven build succeeds; Failsafe version warning remains | Pin every build plugin and preserve a locked toolchain/container |
| CI dependencies | GitHub Actions are tag-pinned rather than immutable commit-pinned | Pin full reviewed SHAs and minimize token permissions |
| CI permissions | Workflows grant contents/checks/pull-request write permissions | Split read-only validation from narrowly scoped release/comment operations |
| Coverage | Strong line coverage; 50% CI threshold and integration failures | Gate security-critical branches, negative paths and live integration separately |
| Runtime validation | Sample logs warn that no Bean Validation provider is present | Fail startup when required validation providers or authority stores are unavailable |
| Persistence | Important registries/audit paths have in-memory implementations | Require durable transactional stores, recovery, migration, backup and concurrency tests |
| Key custody | Sample keys and local services demonstrate flow | Integrate managed/HSM-backed custody, rotation, compromise recovery and verifier trust policy |
| Independent assurance | No located external audit or interop certification | Require independent review and a second implementation before high-assurance claims |

The mock-LLM sample profile also disables some administrative access controls for demonstration.
That is acceptable for a clearly marked sample, but it cannot be evidence for deployment security.

## Warrantor feature-level comparison

| Warrantor area | Open Agent Auth overlap | Remaining material difference |
|---|---|---|
| W1 Notary core | Signed JWTs, keys/JWKS and audit records | No Warrantor notary, expected-set reconciliation, transparency/witness profile or durable receipt service |
| W2 Evidence before commit | User input, policy reference, AOAT/WIT/WPT and signed audit context precede access in the intended flow | No demonstrated exact decision-to-forward-to-effect binding, complete evidence population or current VCDM conformance |
| W3 Containment | Expiry, policy rejection and validation failures can deny operations | No kill-switch conformance, measured residual-action bound, complete process/network mediation or partition/restart semantics |
| W4 Policy compiler | Rego/OPA/RAM/ACL choices and request context | No typed cross-target IR, equivalence proof, loss report or deterministic multi-engine conformance |
| W5 Egress broker | HTTP/MCP authorization can gate a cooperating path | No default-deny kernel/network broker, child-process/DNS coverage, response egress mediation or bypass proof |
| W6 Delegation intersection | AOAT delegation records, identity tokens and policy references | No exact multi-principal algebra; embedded signatures are not verified; no holder-bound complete chain or atomic durable consumption |
| MCP gateway | Client/server helpers and policy input | No demonstrated transport-level complete mediation or evaluated-bytes/forwarded-bytes proof |
| Evaluation receipts | Generic audit structures could carry evaluation data | No evaluation-specific authority, grader, dataset, model/runtime, result-set completeness or cross-harness profile |
| Machine-checked invariants | Large unit/conformance suite | No formal model/proof, refinement mapping or independent invariant corpus |

## Claim adjudication

### CLM-0001 — integrated non-bypassable alliance layer

Open Agent Auth is strong bounding evidence that multiple identity, operation-authorization,
policy, consent, MCP and audit concepts are already integrated in public code. It is not evidence
that an Open Secure AI Alliance member supplied the exact claimed layer, and artifact inspection
does not establish non-bypassability or incident exchange. Move it from challenging to bounding
evidence and retain the broader claim as unresolved pending a dated member-contribution inventory.

### CLM-0003 — nobody builds a W6-equivalent delegation intersection engine

The artifact contains delegation-shaped structures, but does not implement the exact claimed
intersection engine and lists agent-to-agent delegation as future work. It bounds the novelty space
rather than establishing equivalence. The universal wording should still be retired because other
reviewed sources cover multi-principal ceilings, chain narrowing and delegation protocols. W6's
defensible differentiator is an explicit algebra plus holder-bound, complete, cross-stack,
receipt-linked and independently checked implementation.

## Required Warrantor actions

### Adopt

- AOAT/WIT/WPT as important standards-development and interoperability inputs;
- separate workload identity, proof of key possession, human operation authority and policy
  evaluation as useful architectural layers;
- the project's negative OAuth/OIDC/JWKS/WIMSE fixtures as one seed corpus;
- explicit protocol discovery and version metadata; and
- exact operation/tool arguments as policy inputs.

### Modify

- define a Warrantor profile over exact draft/RFC revisions and publish conversion-loss rules;
- require target/method/canonical request/result digests and holder proof in the operation binding;
- replace nullable security dependencies with startup-fatal requirements or explicit indeterminate
  results;
- independently verify every delegation hop and compute cumulative authority intersection;
- compile a typed policy IR to OPA/Cedar/AuthZEN targets with differential conformance;
- bind human consent rendering to the exact machine-policy digest;
- integrate at the real MCP/HTTP forwarding boundary and prove wrapper-bypass resistance; and
- wrap signed events in durable, reconciled and independently verifiable receipt-set semantics.

### Defer

- claiming AOAT/WPT interoperability until revision-specific tests pass against a second
  implementation;
- production dependency adoption until a supported release, stable artifact distribution and
  independent security review exist;
- W3C VC terminology until current conformance is demonstrated; and
- OPA and browser-flow conclusions until their live suites run in a pinned environment.

### Reject

- treating non-empty embedded delegation signatures as verified;
- calling a skipped identity check “passed”;
- treating proof of workload-key possession as proof of the exact HTTP effect;
- accepting agent-proposed policy text without a trusted compiler/reviewer boundary;
- equating an MCP SDK wrapper with complete mediation;
- describing a deletable in-memory event list as an immutable audit trail;
- using the green protocol profile to suppress the red broader integration gate; and
- marketing the current beta as a W6-equivalent production enforcement system.

## Release-blocking conformance vectors to import

1. Non-empty garbage `as_signature` must fail verification.
2. A valid hop signed by an unauthorized, expired, revoked or wrong-purpose key must fail.
3. Reordered, missing, duplicated or disconnected delegation records must fail complete-chain
   validation.
4. A child scope, policy, expiry, quota or output contract broader than any ancestor must fail.
5. Missing identity binding store must prevent high-assurance verifier startup or return
   indeterminate, never success.
6. WPT with absent/wrong target audience, reused `jti`, overlong lifetime or mismatched token hash
   must fail.
7. Policy registration must reject invalid syntax, unsafe built-ins, unknown semantic fields and
   target-incompatible constructs.
8. Human review must fail if the signed projection omits a machine-enforced material constraint.
9. A raw MCP request that bypasses the wrapper must be denied at the transport/tool boundary.
10. Mutating tool name or arguments after policy evaluation must invalidate the forward.
11. Success, denial, timeout, cancellation and partial effect must each produce linked, reconciled
    evidence.
12. Deleted, missing, reordered and replayed audit events must be detected independently of
    individual signature validity.
13. OIDC discovery, JWKS ETag, PAR, invalid-client, redirect and token-error paths must pass one
    authoritative live profile.
14. Current AOAT and WPT draft fixtures must pass against at least two independent implementations.

## Final recommendation

Open Agent Auth is one of the most relevant public implementation comparators in the current
library, but relevance is not production maturity. Score it as **supporting** rather than essential
or high-quality: technical depth and reproducibility are strong, while source independence,
standards stability, support clarity, complete mediation and broader integration correctness are
weak.

The strategic response is not to compete by renaming its layers. Warrantor should consume the
emerging protocol vocabulary and prove what the beta does not: exact cumulative authority,
holder-bound complete chains, fail-closed security configuration, evaluated-to-forwarded request
identity, cross-engine policy semantics, durable effect receipts, bounded revocation and
independent conformance.
