# Commercial attack-to-policy and patent prior-art review

Status: completed bounded wave; implementation and legal follow-up gates remain  
Snapshot: 2026-08-31  
Primary claim: CLM-0009  
Secondary claim: CLM-0002  
Scope: commercial WAF/RASP/XDR/SOAR response, current primary documentation, and technically
material patent disclosures  
Research rule: product documentation establishes documented features, not independent efficacy;
patents establish disclosed mechanisms and chronology, not implementation, validity, infringement
or freedom to operate

## Executive decision

The repository's statement that no system converts a successful adversarial evaluation finding
into production denial policy is false at its stated universal scope.

This wave adds two independent reasons the claim cannot survive:

1. **Shipping product behavior.** F5 BIG-IP ASM imports web-application scanner findings, maps
   automatically resolvable findings into policy changes, allows per-finding review, can place the
   changes in staging, applies them to a production WAF policy and directs the operator to retest.
   This is a direct finding-to-production-policy workflow, even though it is web-specific and does
   not supply Warrantor's complete evidence model.
2. **Older public disclosure.** US8572750B2, with a 2011-09-30 priority date, describes a scanner
   finding loop that creates a generic virtual-patch schema from exploit request/response evidence,
   lowers it to device-specific interfaces, passes through change control, deploys it to security
   infrastructure and rescans until the vulnerability is no longer exploitable. That is prior-art
   evidence, not proof the invention was implemented.

Commercial products also supply most lifecycle pieces separately:

- Microsoft Defender converts correlated alerts and evidence verdicts into containment and
  remediation with approval, action history, undo/release, current policy status, block events and
  time-bounded isolation.
- Datadog converts security signals into temporary application blocks, distributes policy to
  instrumented services, exposes matching/blocked traces, supports monitoring/blocking/disabled
  states, allows policy-version pinning and provides a global off switch.
- Splunk SOAR invokes production actions from event-triggered playbooks and supports quorum,
  veto, escalation, delegated approval and fail-closed approval expiry.
- Google Security Operations, CrowdStrike Fusion and Microsoft Sentinel confirm the breadth of
  current event-triggered SOAR and approval workflows, but were not promoted because Splunk and
  Defender supply stronger distinct lifecycle evidence in this wave.

Three older patent records further narrow component novelty:

- US7895649B1 claims automatic attack-response generation, response verification values and
  automatic aging/removal.
- EP3035637B1 claims response selection, filtering by corporate/legal/government policy, optional
  approval, prerequisite-aware execution and residual-threat replanning.
- US11516242B2, retained as a candidate rather than promoted, describes label-targeted distributed
  virtual patches, automatic assignment based on application/version, dynamic removal and traffic
  reporting.

The remaining defensible opportunity is not an individual arrow from finding to response. It is a
strict composition:

> authenticated reproduced agent-evaluation finding → least-authority action-class candidate →
> target-capability/equivalence proof → authenticated per-candidate approval → immutable
> monitor/canary/enforce transition → independently reconcilable effect evidence → receipted
> rollback or mandatory expiry → regression and safety-case closure.

No reviewed source jointly supplies every property in that sentence. This is a bounded literature
result, not a universal nonexistence assertion.

## Decisions

| Decision object | Disposition | Reason |
|---|---|---|
| CLM-0009 universal nonexistence wording | **Retire permanently** | Direct shipping counterexample and older public disclosure |
| CLM-0002 "all six are unclaimed/no implementation anywhere" | **Remain contradicted** | F5 adds another current implementation counterexample; patents separately defeat broad unclaimed-mechanism rhetoric |
| Generic virtual patching | **Consume** | Mature standards/guidance, current products and extensive older prior art |
| Generic SOAR/playbook engine | **Consume** | CACAO, OpenC2 and multiple commercial platforms already cover it |
| Generic alert-to-containment | **Consume** | Defender, Datadog, Falco Talon, Sentinel and other products implement it |
| Generic human approval workflow | **Consume/profile** | Splunk supplies richer approval semantics than the current repository fragments |
| Warrantor R10 evidence-bound composition | **Build narrowly** | Residual technical/product gap remains, but each component must be described precisely |
| Current experimental candidate/approval fragments | **Quarantine from production** | Missing authenticated durable binding, narrowness, rollout, rollback, expiry and regression closure |
| Patent/FTO conclusion | **Defer to counsel** | This research is technical prior-art triage, not legal advice or an exhaustive family/claim opinion |

## Research question and test

The question was not "does this vendor automate security?" That framing would produce a long,
low-value marketing list. Each source was tested against nine dimensions derived from R10.

### R10 commercial comparison dimensions

1. **Finding source and reproduction** — Does the input identify a concrete successful attack,
   vulnerability or evaluated failure, and can the system reproduce or validate it?
2. **Candidate derivation and narrowness** — Is a new rule/action inferred, or is a preconfigured
   playbook merely selected? What constrains overbreadth?
3. **Production action and target lowering** — Does the result reach a real enforcement point?
   Can an abstract decision be lowered to target-specific syntax and capability?
4. **Authorization and approval** — Who can authorize the candidate, what exact bytes/semantics are
   approved, and what happens on denial, timeout or delegation?
5. **Staging and blast-radius control** — Are monitor, simulation, staging, canary, scope ceiling
   and emergency-stop states explicit?
6. **Effect evidence and reconciliation** — Does the system record only the requested action, or
   also the deployed policy revision, current state and observed external effect?
7. **Rollback and expiry** — Can the action be undone, does it expire, and is renewal tied to fresh
   evidence rather than a clock or operator habit?
8. **Regression and safety-case closure** — Does the original attack become a durable regression
   case, and are false-positive/utility regressions tested automatically?
9. **Portability and completeness** — Can the same intent be represented across engines without
   silent semantic loss, and can missing records/actions be detected?

### Evidence labels

- **Implemented/documented** — current product documentation describes a shipping capability.
- **Configured** — automation executes only after an operator defines a rule/playbook mapping.
- **Disclosed** — a patent describes or claims a mechanism; no implementation inference is made.
- **Partial** — a materially relevant mechanism exists but does not meet the complete R10 property.
- **Not found** — not located in the reviewed public scope; never interpreted as proof of absence.

## Comparison matrix

| System/source | Finding | New candidate | Production action | Approval | Stage/blast radius | Effect evidence | Rollback/expiry | Regression | Portability/completeness |
|---|---|---|---|---|---|---|---|---|---|
| F5 BIG-IP ASM | Scanner XML and verified findings | **Implemented** for automatically resolvable vulnerabilities | **Implemented** WAF policy update | Per-finding operator choice; not cryptographic | **Resolve and Stage**, transparent/blocking, seven-day readiness | Illegal requests/logs and retest; no independent receipt | Manual policy change; no mandatory evidence-renewed expiry found | Retest directed; no automatic durable corpus | Generic XML input and declarative JSON output, but F5 semantics |
| Microsoft Defender | Alerts, incident graph, evidence verdicts | Proprietary detector/action selection | **Implemented** containment/remediation policy | Automatic or approval-gated; RBAC and action center | Detector audit/staged rollout; scope/exclusions; action-specific safeguards | Action history, current policy state, triggering alert and block events | Undo/release; automatic device-isolation time window | Continuous model validation, not customer-specific attack regression | Cross-product Microsoft plane; no portable policy/receipt contract |
| Datadog AAP/Workload Protection | Security signal or runtime-rule match | Configured rule/action; some managed rules | **Implemented** SDK/WAF deny and kill/isolate actions | Configuration permission; automatic or manual response | Monitoring/blocking/disabled, preview traces, scope and global off | Blocked traces and response table; no complete signed set | Temporary deny duration, unblock, disable; connector-specific rollback | Cleanup/validation guidance, not automatic regression synthesis | Multiple WAF targets but vendor-specific signal/policy semantics |
| Splunk SOAR | Event, label, analyst/API invocation | Configured playbook/action | **Implemented** via asset connectors | **Strong:** quorum, veto, escalation, delegation, SLA expiry | Prompt/branch/error controls; no generic canary policy state | Action/playbook records; connector effect semantics vary | Approval expires without run; action rollback varies by connector | No automatic attack-to-regression closure found | Broad connector ecosystem, no target-equivalence proof |
| Google Security Operations | Alert/case/playbook data | Configured playbook branch/action | Implemented through SOAR actions | Manual question/external approval link and timeout | Fail-stop default, timeout/fallback branches | Playbook results; completeness unverified | Workflow-specific | Not found | Google SOAR representation |
| CrowdStrike Fusion SOAR | Detection, incident, schedule or on-demand trigger | Configured workflow | Implemented through Falcon/third-party actions | Human-input action documented for high-impact containment | Conditions, loops and timeout; no portable canary state | Workflow execution; effect completeness unverified | Workflow-specific | Not found | Falcon/Foundry-specific |
| Microsoft Sentinel | Incident/alert creation or update | Configured automation rule/playbook | Logic Apps and response actions | Manual or automatic run; RBAC | Ordered rules/conditions; target-specific safeguards | Logic Apps run history; not a complete portable receipt | Playbook-specific | Not found | Broad connectors but Microsoft-specific orchestration |
| Wallarm virtual patch | Operator-defined signs/regex/endpoint | Manual rule creation | **Implemented** block even in monitoring/safe-blocking mode | Operator/RBAC configuration | Narrow endpoint/regex scope; allowlist exception | Product event/log evidence | Manual rule lifecycle | Not found | Wallarm rule model |
| US8572750B2 | Baseline plus mutated scanner requests/responses | **Disclosed:** derive patterns and generic virtual-patch schema | **Disclosed:** lower to IPS/firewall/AAA/device interfaces | Change-management point can approve/deny | Existing-control check and repeated scan; modern canary absent | Logs/history and confirming rescan disclosed | Loop ends when vulnerability no longer exploitable; no mandatory expiry | Repeated scanner validation disclosed | Generic schema to different device interfaces; equivalence proof absent |
| US7895649B1 | Aggregated packet flows and detected attack | **Disclosed:** automatically generated response message | **Disclosed:** distributed sensor rule/response files | Not a central feature | Priority/stage-aware messages; no human canary | Verification value/signature disclosed | **Automatic aging/removal disclosed** | Later-stage response generation, not regression corpus | Multiple sensors/files; semantic equivalence absent |
| EP3035637B1 | Detected anomaly/threat information | **Disclosed:** select mitigation scheme and filter allowed actions | **Disclosed:** orchestrated response actions | **Disclosed:** manual, automatic or omitted | Policy prohibits/adds actions; prerequisite ordering | Monitor residual threat and replan | Replanning rather than rollback/expiry | Effectiveness can update threat-response knowledge; no corpus contract | Imports external response knowledge; no portable engine profile |
| US11516242B2 | Known vulnerable app/version and observed communication | Assign existing virtual patch; rules may be auto-generated by strategy | Distributed host/midpoint proxy and traffic filters | Administrator/configuration | Label scope, relevance and dynamic add/remove | Allowed/blocked traffic logs and graph | Dynamic removal when patch no longer applies | Not found | Label-targeted distributed enforcement, not cross-engine proof |

## Deep review 1 — F5 BIG-IP ASM / Advanced WAF

Primary sources:

- [Using Vulnerability Assessment Tools with a Security Policy](https://techdocs.f5.com/en-us/bigip-14-1-0/big-ip-asm-getting-started/using-vulnerability-assessment-tools-for-a-security-policy.html)
- [Getting Started with Declarative Policies](https://techdocs.f5.com/en-us/bigip-16-0-0/big-ip-declarative-security-policy/declarative-policy-getting-started.html)

Both current chapters are marked updated 2026-07-07. The scanner chapter says it applies to BIG-IP
ASM releases through 21.0.0. It names HP WebInspect, IBM AppScan, Qualys, Quotium Seeker, Trustwave
App Scanner and WhiteHat Sentinel and supports other scanners through standard XML and a generic
schema.

### Exact workflow

1. Create or select a security policy associated with the web application.
2. Associate a supported scanner or the generic scanner.
3. Import recent XML output or retrieve supported service output.
4. Review verified findings and their resolution classification:
   - automatically resolvable;
   - manually resolvable;
   - not straightforwardly resolvable;
   - ignored, pending, mitigated or mitigated in staging.
5. For an automatically resolvable finding:
   - **Resolve** updates policy directly;
   - **Resolve and Stage** updates policy while keeping affected entities nonblocking during tuning;
   - **Ignore** records the operator decision.
6. Inspect the changes ASM plans to make before acceptance.
7. Apply the policy.
8. Retest or rescan the application.
9. Review learning suggestions, traffic samples, violations, false-positive indicators and
   enforcement readiness.
10. Move transparent/staged policy elements to blocking when ready.

### Why this directly contradicts CLM-0009

The repository wording does not restrict "adversarial evaluation" to an LLM-agent benchmark. A web
vulnerability scanner actively mutates requests, demonstrates a successful exploit condition and
produces a finding. F5 consumes that finding, modifies a production denial policy for the relevant
web request class, stages it, applies it and retests. Narrower agent-specific semantics may still be
novel, but the universal statement is not.

### Strong controls worth consuming

- Per-vulnerability acceptance or ignore decision.
- Planned-change review before policy modification.
- Distinction between automatic and manual resolvability.
- Staged, transparent and blocking states.
- Traffic samples and violation evidence during tuning.
- Enforcement-readiness period.
- Retest/rescan after policy application.
- Declarative JSON policy suitable for Git and CI/CD.

### Critical safety failure mode

F5 explicitly documents that Real Traffic Policy Builder can conflict with and override scanner
results. Examples include removing CSRF protection, allowing executable upload or methods the
scanner disallowed, and disabling signatures. This is not a minor operational note. It demonstrates
that two individually reasonable learning channels can compose into weaker protection.

Warrantor must add the following negative vectors:

- scanner-derived denial followed by traffic-learning allow;
- learned legitimate traffic that is actually adversarial poisoning;
- signature disable after a verified exploit;
- override without preserving the original finding and approver decision;
- target policy where staging and blocking semantics differ;
- retest that exercises only the original payload and misses equivalent variants;
- candidate broadening or narrowing after approval;
- policy import where the deployed revision differs from the reviewed JSON.

### F5 boundary

The product does not remove Warrantor's residual design need. It does not document:

- a principal-authenticated evaluation receipt;
- an agent action-class type system;
- a content-addressed candidate approved by signature;
- one-shot operation permits;
- cross-PDP semantic equivalence;
- an independently verifiable deployed-effect receipt;
- expiry that requires fresh reproduction;
- automatic conversion of the finding into a portable regression/safety case;
- authenticated expected-set reconciliation proving no finding, approval or effect record is missing.

## Deep review 2 — Microsoft Defender AIR and Attack Disruption

Primary sources:

- [Automatic attack disruption](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption)
- [Automated investigations](https://learn.microsoft.com/en-us/defender-endpoint/automated-investigations)
- [Action center](https://learn.microsoft.com/en-us/defender-xdr/m365d-action-center)
- [Configuration and safeguards](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption)
- [Details, results and policy status](https://learn.microsoft.com/en-us/defender-xdr/autoad-results)

### Mechanism

AIR begins from an alert or operator request, expands investigation to related entities/devices,
and assigns malicious, suspicious or no-threat verdicts to evidence. The same incriminated entity on
ten or more devices causes expansion to require approval. Depending on automation settings,
remediation such as quarantine, service stop or scheduled-task removal can occur automatically or
await the operations team.

Attack Disruption operates at incident rather than single-indicator level. Microsoft documents
correlation across endpoint, identity, email, collaboration and SaaS signals; identifies assets
controlled by an attacker; and automatically applies response actions. These include containment
policy across onboarded endpoints, device isolation, account disable, user containment, session
revocation and preview integration with external identity/cloud systems.

### Evidence and lifecycle controls

- Action center records pending and completed actions and their source.
- Operators can approve or reject pending actions.
- Supported completed actions can be undone or assets released.
- Incident activities identify triggering alert, time, action and current policy status.
- Current policy status distinguishes active, inactive, not-applicable and unavailable state.
- Advanced-hunting events expose actual blocks caused by containment, not only the initial request.
- Automatic device isolation is scoped and automatically undone after a defined time window;
  operators can release earlier.
- Microsoft describes pre-release validation, staged detector deployment, ongoing review and 24x7
  response for anomalous model behavior.

### Evidence distinction Warrantor should preserve

| Evidence object | Defender example | Why it is not interchangeable |
|---|---|---|
| Detection | Alert or correlated incident | Says a threat was inferred, not what action was authorized |
| Decision | Verdict and selected remediation | Says what the service decided, not that enforcement succeeded |
| Requested action | Contain/isolate/disable | Says what was requested, not the current policy state |
| Policy state | Active or inactive containment | Says current state, not which traffic/effect was blocked |
| Effect event | Contained-device/user block event | Shows a particular effect, not completeness of all effects |
| Reversal | Release/undo/time-window end | Says protection ended, not whether every enforcement point converged |

### Boundary and follow-up

Microsoft's documented confidence and performance claims are first-party and were not independently
reproduced. The detector ensemble, evidence corpus, action-selection logic and completeness boundary
are proprietary. A sacrificial-tenant experiment should test:

- incident correlation and false-positive threshold;
- ten-device expansion approval;
- full versus semi automation;
- approval expiry and Action center history;
- every supported undo path and irreversible action;
- defined isolation duration and actual release convergence;
- exclusions and conflicting automation that re-enables accounts;
- partial product deployment and degraded action coverage;
- failed action after successful decision;
- action history versus current policy status versus observed block events;
- export/reconciliation completeness.

AIR's separate investigation experience changes on 2026-09-01. Microsoft says detection and
response remain in the default protection stack, but implementation planning must recheck the live
experience rather than copying the 2026-08 workflow blindly.

## Deep review 3 — Datadog application and workload response

Primary sources:

- [App and API Protection policies](https://docs.datadoghq.com/security/application_security/threat_protection/policies/)
- [Account-theft response guide](https://docs.datadoghq.com/security/application_security/guide/manage_account_theft_appsec/)
- [Workload Protection response](https://docs.datadoghq.com/security/workload_protection/respond_and_report/)

### Implemented path

Datadog AAP can attach automatic IP or authenticated-user blocking to a detection rule. When a
signal is raised, the implicated entity can be blocked temporarily or permanently across protected
services. Remote Configuration distributes policy to compatible agents/SDKs. Workflows can also
push indicators to AWS WAF, Cloudflare or Fastly.

The In-App WAF offers monitoring, blocking and disabled modes. Operators can clone managed policy,
create custom policy, auto-update it or pin a version. The account-theft guide recommends previewing
matching traces before saving a blocking custom rule. Blocked traces are visible in Trace Explorer.
The denylist permits unblock or duration extension. A global control can disable all request
blocking quickly.

Workload Protection attaches kill, process/container termination or network-isolation actions to
runtime Agent rules and records automated and manual responses.

### Why it matters

Datadog covers several R10 properties in a commercially realistic way:

- event-to-enforcement mapping;
- temporary duration;
- monitor/block/disable transitions;
- target/service scope;
- remote policy distribution;
- preview using real traces;
- blocked-effect telemetry;
- version pinning versus auto-update;
- emergency stop;
- cleanup and unblock guidance.

It does **not** establish safe new-policy synthesis. A configured rule selects a configured response,
and automatic denylisting usually blocks the implicated entity. That is different from inferring a
new least-authority semantic predicate for an agent action class.

### Datadog-specific negative vectors

- denylist capacity exceeded while UI accepts entries;
- Remote Configuration delay or partial SDK compatibility;
- protected and unprotected services split the true enforcement set;
- trace sampling/redaction hides an effect;
- auto-updated managed policy changes after approval;
- pinned policy omits urgent fixes;
- permanent IP block outlives address ownership;
- automatic block of a shared NAT or recycled identity;
- global off switch activated without signed reason and bounded authority;
- blocking at SDK but not perimeter, or perimeter but not SDK;
- deletion/expiry not converged across all services;
- response table says completed while the external WAF action failed.

## Deep review 4 — Splunk SOAR approval semantics

Primary sources:

- [Approve actions before they run](https://help.splunk.com/en/splunk-soar/soar-cloud/use-soar-cloud/get-started-using-splunk-soar-cloud/approve-actions-before-they-run-in-splunk-soar-cloud)
- [Create a playbook](https://help.splunk.com/en/splunk-soar/soar-cloud/build-playbooks/use-the-playbook-editor-to-create-and-view-playbooks-to-automate-analyst-workflows/create-a-new-playbook-in-splunk-soar-cloud)
- [Playbook automation API](https://help.splunk.com/en/splunk-soar/soar-cloud/python-playbook-api-reference/automation-api/playbook-automation-api)

### Approval model

Splunk distinguishes read-only actions from actions that change an asset. Approvers are configured
per asset. Write actions can require a minimum number of primary approvals, and any denial stops the
action. Failure to reach quorum within the SLA escalates to secondary and then executive approvers.
If the final approval window expires, the action does not run. The API can add a reviewer gate.

Delegation is explicit. An approver can delegate to users or roles and relinquishes that portion of
the vote; all delegates must approve to reconstruct the original vote. A second delegation level is
allowed, with restrictions preventing circular or conflicting assignment.

This is significantly richer than a boolean `approved` field. Warrantor's approval schema needs:

- candidate/operation digest;
- target and write/read classification;
- required quorum and authority set;
- veto semantics;
- deadline and escalation schedule;
- delegation graph and attenuated vote weight;
- deny reason;
- timeout and fail-closed nonexecution record;
- exactly-once consumption of the approval;
- final operation/effect reconciliation.

### What Splunk does not provide in reviewed scope

- new candidate derivation from an arbitrary evaluation finding;
- proof the connector's read/write label matches real side effects;
- target-independent policy equivalence;
- monitor/canary/enforce as a generic policy lifecycle;
- cryptographic binding across finding, playbook version, approval and exact connector request;
- proof the connected asset performed the claimed external effect;
- automatic rollback/expiry for every action;
- regression and safety-case closure.

## Commercial breadth without source inflation

The following sources were reviewed or opened but retained as candidates rather than promoted.

| Candidate | Distinct value | Why not promoted in this wave |
|---|---|---|
| [Wallarm virtual patch](https://docs.wallarm.com/5.x/user-guides/rules/vpatch-rule/) | Endpoint/regex blocking even when broader node mode is monitoring/safe blocking | Operator-defined rule; current-version/date canonicalization unresolved; F5 is stronger finding-to-policy evidence |
| [Google Security Operations playbook flows](https://docs.cloud.google.com/chronicle/docs/soar/respond/working-with-playbooks/using-flows-in-playbooks) | Manual question, external approval link, timeout/fallback and fail-stop behavior | Splunk supplies a deeper approval model; no new finding-to-policy synthesis |
| [CrowdStrike Fusion SOAR](https://developer.crowdstrike.com/ngsiem/fusion-soar/) | Event/incident/schedule triggers and Falcon/third-party actions | Approval detail partly depends on an older first-party blog; no distinct R10 closure |
| [Microsoft Sentinel automation](https://learn.microsoft.com/en-us/azure/sentinel/automation/automation) | Incident/alert automation rules and Logic Apps response | Defender provides stronger Microsoft-specific lifecycle evidence; this remains an adapter candidate |
| [US11516242B2](https://patents.google.com/patent/US11516242B2/en) | Label-scoped distributed virtual patch, dynamic add/remove and traffic logs | Assigns known patches more than deriving a new finding-specific candidate; retained for claim chart |
| [Contrast Protect 3.9.7](https://docs.contrastsecurity.com/Contrast_Documentation_3_9_7-en.pdf) | In-process RASP blocking and attack remediation data | Located full manual is older; current version/mechanism needs verification |
| [Waratek runtime patching](https://waratek.com/wp-content/uploads/2022/10/20200306-Waratek-RASP-NL-Intro.pdf) | Commercial runtime virtual-patching baseline | Older marketing-heavy whitepaper; no independently inspectable finding-to-policy lifecycle |

This treatment is deliberate. Listing every vendor as a ranked source would inflate quantity while
adding little evidence. The candidates remain discoverable and have explicit promotion gates.

## Patent prior-art review

### Legal and evidentiary boundary

Patent research answers a different question from product research.

It can support:

- a public priority/publication chronology;
- that a mechanism was disclosed or claimed;
- inventors and recorded assignee history;
- exact claim language;
- search leads through classifications, citations and patent families.

It cannot by itself support:

- that the mechanism was implemented;
- that it worked, scaled or was safe;
- that claims are valid, enforceable or infringed;
- that aggregator legal status is legally conclusive;
- freedom to operate;
- an exhaustive novelty opinion.

Every product-facing patent decision requires official register/family review and qualified counsel.

### US8572750B2 — scanner evidence to device-specific virtual patch

Primary record: [US8572750B2](https://patents.google.com/patent/US8572750B2/en)

Recorded metadata inspected in this wave:

- title: *Web Application Exploit Mitigation in an Information Technology Environment*;
- priority: 2011-09-30;
- publication/grant: 2013-10-29;
- inventors: Ashish Patel and Tamer Aboualy;
- original assignee shown: IBM;
- current assignee shown by Google Patents: Finjan Blue;
- aggregator status shown: active with adjusted expiration in 2031.

Mechanism:

1. Capture baseline requests/responses.
2. Create and execute mutated variant requests.
3. Identify corrupt/different responses that demonstrate a vulnerability.
4. Preserve variant request/response pairs and scan metadata.
5. Map request elements to a generic virtual-patch schema.
6. Generate exploit-vector permutations and generalize them to logical patterns/signatures.
7. Check whether current infrastructure already blocks the vulnerability.
8. Convert the generic schema to interfaces for relevant network/software devices.
9. Pass changes through a change-management control point.
10. Deploy to IPS, firewall, AAA or other security infrastructure.
11. Ask the scanner to confirm through rescan.
12. Repeat until the vulnerability is no longer exploitable.

This disclosure is closer to R10 than a generic SOAR playbook because the candidate is derived from
reproduced exploit behavior and generalized before target lowering. Its gaps are equally important:
no code, no metrics, no cryptographic evidence chain, no explicit least-authority proof, no
monitor/canary/rollback/expiry state, no agent semantics and no regression corpus contract.

### US7895649B1 — automatic generation, verification and aging

Primary record: [US7895649B1](https://patents.google.com/patent/US7895649B1/en)

Recorded metadata inspected:

- title: *Dynamic Rule Generation for an Enterprise Intrusion Detection System*;
- priority: 2003-04-04;
- publication/grant: 2011-02-22;
- original assignee shown: Raytheon;
- current assignee shown by Google Patents: Everfox Holdings;
- aggregator status shown: active with adjusted expiration in 2027.

The issued claims describe:

- attack detection from aggregated sensor packet flows;
- automatic response-message generation;
- distribution to sensor response-message files;
- response-message generation date;
- comparison to an aging date and automatic removal when too old;
- verification value/hash/digital signature and sensor-side verification/rejection;
- messages for detected attack stages and later stages.

The crucial correction is conceptual: policy integrity and time-bounded removal are not new
primitives. Warrantor may still contribute an exact renewal predicate, durable linearizable state,
authority semantics and reconciliation protocol, but it must not market "signed generated policy"
or "policy expiry" as unprecedented.

### EP3035637B1 — policy-filtered adaptive response

Primary record: [EP3035637B1](https://patents.google.com/patent/EP3035637B1/en)

Recorded metadata inspected:

- title: *Policy-Based Network Security*;
- priority: 2014-12-19;
- publication/grant: 2020-04-22;
- inventors: Faye I. Francy and Gregory J. Small;
- assignee shown: Boeing;
- aggregator status shown: active.

The disclosure describes:

- analyzing activity and identifying a threat;
- selecting an existing mitigation scheme, importing one from external sources or manually
  creating one;
- filtering candidate actions by corporate, legal or governmental directives;
- removing prohibited actions and adding required actions;
- manual, automatic or omitted approval;
- dependency-aware action scheduling;
- execution and monitoring;
- checking whether the threat remains;
- selecting a new plan when the previous plan did not resolve it;
- sharing effectiveness information back into response knowledge.

This is important for W4 and W6 positioning. Policy-constrained action selection and approval are
old. The residual opportunity is a formally specified multi-principal authority intersection bound
to an exact agent operation, not generic organizational policy filtering.

### Patent claim-chart queue

| Warrantor/R10 feature | Closest record | Required counsel/technical follow-up |
|---|---|---|
| Exploit evidence → generalized candidate | US8572750B2 | Chart independent claims and family; compare exact candidate derivation |
| Generic candidate → target-specific policy | US8572750B2 | Compare W4 IR, target capability profiles and equivalence evidence |
| Change control/approval | US8572750B2; EP3035637B1 | Separate claimed approval from signed per-candidate authority |
| Automatic response-rule generation | US7895649B1 | Compare response-message scope and Warrantor action-class predicates |
| Integrity-protected response distribution | US7895649B1 | Compare verification value with DSSE/in-toto and expected-set reconciliation |
| Automatic policy aging/removal | US7895649B1 | Compare fixed aging with evidence-renewed expiry and convergence proof |
| Policy-filtered allowed actions | EP3035637B1 | Compare generic directives with W6 exact authority intersection |
| Residual-threat monitoring and replanning | EP3035637B1 | Compare effect oracle, rollback and safety-case state machine |
| Label-scoped distributed virtual patch | US11516242B2 | Compare target scope, dynamic relevance and distributed removal |

## Revised novelty statement

### Prohibited wording

- "Nothing ties a successful attack to production denial."
- "No implementation anywhere converts findings into policy."
- "Warrantor invented virtual patching for agent actions."
- "No system signs or expires generated response policy."
- "No product combines automated response with approval and rollback."
- "No prior art covers policy-filtered adaptive response."

### Defensible working wording

> In a bounded review completed on 2026-08-31, we found mature scanner-to-WAF virtual patching,
> event-to-response engines, commercial approval/rollback/expiry controls and older patent
> disclosures covering automatic rule generation, signed/verified distribution, aging, policy
> filtering and adaptive replanning. We did not find one reviewed system that jointly binds a
> reproduced AI-agent evaluation finding, least-authority action-class candidate, authenticated
> per-candidate approval, target-equivalence evidence, staged enforcement, independently
> reconcilable effects, evidence-renewed expiry and regression/safety-case closure. Warrantor's
> research and product hypothesis is that this exact composition is valuable and testable.

This wording must retain its date, reviewed-source qualifier and exact feature list. Removal of any
of those bounds recreates the false universal claim.

## Product architecture recommendation

### Build only the R10 assurance spine

```text
evaluation producer
    │ authenticated finding + reproduction bundle
    ▼
finding verifier ── reject unverifiable/non-reproducible/ambiguous findings
    │
    ▼
deterministic candidate builder ── least-authority typed action predicate
    │                               blast-radius ceiling
    ▼
target compiler ── F5 / Datadog / Defender / SOAR / AuthZEN / Cedar / Rego profiles
    │               explicit loss and unsupported-capability report
    ▼
independent validator ── semantic differential + negative corpus + impact preview
    │
    ▼
approval authority ── exact digest, quorum/veto/delegation, deadline, one-shot permit
    │
    ▼
state machine ── monitor → canary → enforce → rollback | expire
    │
    ▼
effect reconciler ── requested action ≠ deployed revision ≠ current state ≠ observed effect
    │
    ▼
regression/safety-case builder ── original exploit + variants + utility + expiry-renewal gate
```

### Consume adapters and substrates

| Layer | Preferred substrate | Warrantor-owned boundary |
|---|---|---|
| WAF virtual patch | F5/OWASP and customer-installed WAF | Finding/candidate/approval/effect receipts and semantic target profile |
| App/runtime response | Datadog or existing RASP/ADR | Authority, exact scope, expiration convergence and evidence completeness |
| XDR containment | Microsoft Defender or installed XDR | Portable incident/action mapping and external evidence reconciliation |
| SOAR approval/orchestration | Splunk, Sentinel, Google/CrowdStrike; CACAO/OpenC2 | Candidate identity, quorum authority, one-shot permit and effect proof |
| PDP/PEP | AuthZEN with Cedar/Rego/Cerbos/OpenFGA profiles | Canonical IR, loss report and cross-engine differential conformance |
| Evidence envelope | DSSE/in-toto; optional SCITT/COSE receipt | Predicate semantics, authority, expected-set and completeness protocol |

### Reject these build paths

- Another generic SOAR/playbook language.
- Another generic WAF signature format.
- An LLM that emits raw target policy directly into enforcement.
- Approval represented as an unauthenticated boolean or queue state.
- Wildcard action/resource denials from a single finding.
- Unkeyed hashes labeled as signatures.
- Policy deployment considered successful when an API returns success.
- Fixed-duration policy considered safely expired without enforcement-set reconciliation.
- Product logs considered complete merely because they are exportable.

## Minimum typed records

### Finding record

- stable finding identifier;
- evaluator and grader identity/credential;
- principal/task/agent/runtime/model identity;
- exact attack input, preconditions and expected invariant;
- observed action and external effect;
- native evidence digests and expected-set manifest;
- reproduction recipe and reproduction result;
- confidence, severity and false-positive status;
- privacy/redaction commitments.

### Candidate record

- finding digest;
- semantic action class and resource class;
- subject/principal/delegation constraints;
- parameters and result/effect constraints;
- environment/time/session bounds;
- negative/positive examples;
- blast-radius ceiling;
- derivation algorithm/version;
- target-independent digest;
- unsupported assumptions.

### Target compilation record

- canonical candidate digest;
- target name/version/profile digest;
- compiled policy bytes/digest;
- semantic loss and unsupported capabilities;
- differential test vector results;
- impact-preview data;
- policy/data revision assumptions;
- independent validator identity.

### Approval record

- candidate and target compilation digest;
- approver identity, role and authority basis;
- quorum, veto and delegation graph;
- approval/denial reason;
- deadline, escalation and expiry;
- allowed rollout states and blast radius;
- one-shot permit identity;
- signature and credential status.

### Deployment/effect record

- requested transition;
- target and enforcement-set manifest;
- exact deployed revision per target;
- start/end/convergence time;
- partial failure and retry state;
- current active/inactive policy state;
- sampled and expected effect evidence;
- independent observation source;
- rollback/expiry trigger and completion;
- expected-set reconciliation result.

### Regression/safety-case record

- original finding and reproduction;
- generalized equivalent attacks;
- legitimate utility/false-positive suite;
- poisoning and override cases;
- target-specific negative vectors;
- renewal/expiry decision;
- residual risk and approved exception;
- release/safety-case linkage.

## Release-blocking conformance corpus

### Finding and candidate safety

1. Unauthenticated finding.
2. Valid signature from unauthorized evaluator.
3. Missing expected evidence object.
4. Finding cannot be reproduced.
5. Original attack succeeds but observed effect is absent.
6. Single malicious parameter produces wildcard action denial.
7. Candidate blocks legitimate sibling action.
8. Candidate matches only original payload and misses equivalent mutation.
9. Candidate inference changes when source records are reordered.
10. Candidate generated from product telemetry that an attacker can poison.

### Approval safety

11. Approval digest differs from compiled target policy.
12. Candidate mutates after approval.
13. Approval replayed for a second deployment.
14. Approver credential revoked after signature but before enforcement.
15. Quorum reconstructed with an unauthorized delegate.
16. Veto lost during escalation.
17. Deadline expires while action is queued.
18. Read-only connector classification hides a write side effect.
19. Approval service crashes after authorize but before one-shot consume.
20. Two concurrent deployments consume one approval.

### Staging and target semantics

21. Monitor mode silently blocks.
22. Canary scope expands on retry.
23. F5 traffic learning weakens a scanner-derived denial.
24. Datadog auto-update changes policy after approval.
25. Defender exclusion prevents one enforcement point from applying containment.
26. SOAR connector transforms arguments after approval.
27. Cerbos and OpenFGA target policies disagree on the same vector.
28. Unsupported target capability is silently dropped.
29. Partial deployment is reported as complete.
30. Policy revision read during verification differs from revision used at enforcement.

### Effects, rollback and expiry

31. API success but policy not active.
32. Policy active but external effect still succeeds.
33. Block event exists but expected enforcement point never received policy.
34. Rollback request succeeds but stale node continues blocking.
35. Expiry clock moves backward or is unavailable.
36. Fixed-duration isolation ends while attack remains reproducible.
37. Renewal occurs without fresh reproduction.
38. Permanent deny survives source vulnerability remediation.
39. Emergency global off invoked without sufficient authority.
40. Reconciliation omits a failed target from the expected set.

### Regression and evidence completeness

41. Original attack is not added to regression corpus.
42. Regression passes because effect oracle is missing.
43. Security passes but legitimate task utility collapses.
44. Product log retention deletes evidence before audit.
45. Export includes actions but not current policy status.
46. Duplicate/retried effect records inflate apparent coverage.
47. Evidence signature is valid but producer omitted a failed result.
48. Policy expires but safety case still claims active mitigation.
49. New target-profile version changes semantics without rerunning corpus.
50. Source finding is later reclassified false positive but derived policies remain active.

## Acceptance metrics

| Metric | Definition | Initial release gate |
|---|---|---|
| Candidate overbreadth | legitimate operations denied / legitimate operations tested | zero on mandatory utility suite |
| Attack coverage | equivalent reproduced attacks denied / equivalent attacks tested | 100% on mandatory finding family |
| Semantic parity | targets with identical expected decisions/effects / targets compiled | 100% for declared common profile |
| Approval binding | deployed policy digests matching approved digest / deployments | 100% |
| Enforcement convergence | expected enforcement points at intended revision / expected set | 100% before state is `enforced` |
| Effect reconciliation | observed expected effects / effect obligations | 100% or explicit failed state |
| Rollback convergence | enforcement points returned to intended state within SLO / expected set | 100% |
| Expiry correctness | expired policies inactive everywhere and reflected in safety case | 100% |
| Regression closure | active policies with linked finding, attack and utility regression set | 100% |
| Evidence completeness | expected records present, unique and authenticated / expected records | 100% |
| Residual action bound | unauthorized effects after revoke/expire | zero within published measured bound |
| Independent verification | deployments verifiable without vendor control-plane trust alone | 100% for supported assurance profile |

No threshold should be marketed before a real two-target reproduction records latency, partial
failure and recovery behavior.

## Implementation sequence

### Phase 0 — claims and schema correction

1. Remove CLM-0009 from product, investor, academic and content claims.
2. Keep the bounded residual statement with date and feature list.
3. Freeze the six record types above.
4. Add patent source class and legal-evidence caveat to the research protocol.
5. Commission a counsel-reviewed claim/family/status chart.

### Phase 1 — deterministic vertical slice

1. Use one reproducible attack finding; no LLM rule generator.
2. Derive one typed least-authority candidate deterministically.
3. Compile to two independent PDP targets.
4. Run differential positive/negative/utility vectors.
5. Require a signed per-target approval digest.
6. Execute monitor → canary → enforce.
7. Observe exact external effect independently.
8. Roll back and expire across the expected enforcement set.
9. Add attack and utility cases to regression corpus.
10. Produce an independently verifiable receipt set.

### Phase 2 — commercial adapters

Priority order:

1. **F5 adapter** — direct finding-to-policy comparator and strongest novelty pressure.
2. **Datadog adapter** — temporary block, preview, trace and global-off semantics.
3. **Splunk/CACAO adapter** — approval, delegation and orchestration semantics.
4. **Microsoft Defender adapter** — cross-product containment, current policy state and effect events.

Each adapter must publish:

- supported R10 fields and states;
- semantic loss;
- required license/service version;
- mutable vendor behavior assumptions;
- effect oracle;
- rollback/expiry behavior;
- export and reconciliation completeness;
- exact conformance corpus result.

### Phase 3 — bounded synthesis research

Only after deterministic Phase 1 is green:

- compare symbolic, template, retrieval and LLM candidate generation;
- constrain generation to typed grammar and target-independent IR;
- require proof/solver checks for scope ceiling;
- generate adversarial equivalents and legitimate counterexamples;
- separate generator confidence from approval authority;
- forbid direct production writes;
- publish failure and abstention rates.

## Business and procurement implications

### Category definition

Do not create a category around "automated security response" or "AI virtual patching." Those
markets already contain mature WAF, RASP, XDR and SOAR vendors.

The defensible category hypothesis is:

> **portable evidence and authority control for attack-informed policy change across existing
> enforcement systems.**

### Enterprise buyer value

- reduces manual translation between evaluation/security findings and deployed controls;
- preserves who authorized what exact rule and why;
- prevents automatic remediation from exceeding blast-radius authority;
- allows existing F5, Datadog, Defender and SOAR investments to remain in place;
- makes monitor/canary/enforce/rollback/expiry observable as one state machine;
- supplies audit evidence beyond vendor-local logs;
- tests semantic drift across policy engines;
- turns incident learning into regression and safety-case evidence.

### Procurement questions Warrantor must answer

1. Which existing control planes are supported and at what versions?
2. Does Warrantor require inline availability for every action?
3. What happens when Warrantor or a vendor control plane is unavailable?
4. Can the customer retain evidence in its own storage and key domain?
5. How are false positives, exclusions and emergency bypasses governed?
6. What exact data leaves the customer's region or trust domain?
7. Can an approver prove which target policy bytes were authorized?
8. How is enforcement-set completeness measured?
9. Which actions are reversible, and which require compensating action?
10. How are connector updates, semantic drift and vendor API retirement handled?
11. What patent/FTO diligence has been completed?
12. What independent conformance evidence exists?

### Commercial model recommendation

Charge for the assurance plane, not generic automation:

- target adapter and conformance subscriptions;
- signed evidence retention/reconciliation;
- policy-differential testing;
- regulated approval profiles;
- incident-to-regression closure;
- independent verifier and audit export;
- enterprise support and assurance SLAs.

Do not promise cost savings or response-time reduction until the deterministic and commercial
adapter pilots produce customer-specific measurements.

## Regional implications

### North America

- Strong product availability makes integration/competition pressure highest.
- Patent chronology and US claim review are immediately relevant.
- Buyer differentiation must emphasize evidence portability, independent verification and
  cross-vendor control rather than automatic response.

### India

- Favor deployable profiles that work with existing enterprise/security-service-provider tooling.
- Preserve customer-controlled evidence storage and export.
- Validate regional availability and data-location terms for every closed cloud service.
- Avoid assuming global product documentation implies identical local feature or support coverage.

### Saudi Arabia, UAE and Qatar

- Position Warrantor as an assurance layer over controls selected by sovereign/regulated buyers.
- Keep approval, key control, evidence retention and policy artifacts deployable in the customer's
  trust domain.
- Verify local service-region, tenancy, support and contracting constraints per vendor.
- Use product logs as inputs, not the sole audit record.
- Do not claim that a commercial vendor's global feature is available or legally sufficient in a
  GCC deployment without current local terms and sector review.

This wave did not verify current regional product availability or procurement terms. That belongs
in the business/regional evidence lane, not in technical feature inference.

## Academic research program

### Research question 1 — least-authority candidate synthesis

Can a system generalize a single successful agent attack into the narrowest policy that blocks a
measured family of equivalent attacks without reducing legitimate task utility?

Hypotheses:

- typed symbolic/template synthesis will have lower overbreadth than unconstrained LLM policy;
- combined attack and legitimate counterexample generation will reduce false positives;
- generator confidence will not predict cross-engine semantic parity reliably.

### Research question 2 — approval semantics

Can a signed, delegated, quorum approval be bound atomically to one exact cross-engine policy
deployment under retries, crashes and revocation?

Baselines:

- Splunk quorum/veto/delegation/expiry;
- EP3035637 policy filter and optional approval;
- current repository approval queues;
- transaction/one-shot permit designs.

### Research question 3 — effect completeness

How can a verifier distinguish requested action, deployed revision, current policy state and
observed external effect while detecting missing enforcement points and omitted failure records?

### Research question 4 — expiry and renewal

Is renewal based on fixed time, continued attack observation or fresh controlled reproduction safer
under adaptive attackers and partial observability?

Baselines:

- US7895649 fixed aging/removal;
- Datadog temporary block;
- Defender time-bounded isolation;
- evidence-renewed Warrantor design.

### Research question 5 — learning-channel conflict

When scanner evidence, real-traffic learning and analyst exceptions modify the same policy, which
precedence and proof obligations prevent a later channel from silently weakening a verified fix?

F5's documented scanner/Policy Builder conflict is the concrete motivating case.

### Evaluation design

- two independent PDPs plus one WAF/runtime target;
- public attack findings with private adaptive equivalents;
- legitimate utility suite and mutation score;
- controlled retries, crashes, partitions and clock faults;
- blind candidate adjudication;
- measured propagation, rollback and expiry convergence;
- native vendor logs plus independent effect observer;
- full expected-set reconciliation;
- exact versioned artifacts and signed run receipts.

## Content program

Evidence-supported themes:

1. **Virtual patching already exists; the missing layer is verifiable composition.**
2. **Why an approval button is not an authorization proof.**
3. **Requested action, active policy and external effect are three different facts.**
4. **The F5 conflict case: when security learning silently weakens scanner protection.**
5. **Temporary blocking is not evidence-renewed expiry.**
6. **SOAR versus policy synthesis: configured playbooks do not solve safe generalization.**
7. **What patents can and cannot prove about AI-security novelty.**
8. **Why Warrantor should integrate F5, Defender, Datadog and Splunk rather than replace them.**
9. **From one exploit to a regression safety case.**
10. **The authority-to-effect chain enterprises should demand from autonomous response.**

Every publication must identify vendor claims as first-party and patents as disclosures. Avoid
efficacy claims until independent execution exists.

## Reading paths

### Executive and product leaders

1. Executive decision and Decisions.
2. Revised novelty statement.
3. Product architecture recommendation.
4. Business and procurement implications.
5. Regional implications.

### Security and platform architects

1. R10 commercial comparison dimensions.
2. Comparison matrix.
3. Four commercial deep reviews.
4. Product architecture and typed records.
5. Release-blocking conformance corpus.

### Engineers and implementers

1. F5, Defender, Datadog and Splunk exact workflows.
2. Minimum typed records.
3. Fifty negative vectors.
4. Acceptance metrics.
5. Implementation sequence and adapter order.

### Academic researchers

1. Patent prior-art review and legal boundary.
2. Revised novelty statement.
3. Academic research program.
4. Evaluation design and metrics.

### Risk, audit, legal and compliance teams

1. Evidence labels and legal/evidentiary boundary.
2. Evidence distinction for Defender.
3. Patent claim-chart queue.
4. Approval/deployment records and completeness metrics.
5. Procurement questions.

### Marketing, partnerships and content teams

1. Prohibited and defensible wording.
2. Category definition.
3. Commercial adapter strategy.
4. Content program.
5. Regional evidence caveats.

## Source promotion decisions

### Promoted

| ID | Band | Score | Role |
|---|---:|---:|---|
| `f5-big-ip-asm-vulnerability-assessment-2026` | High quality | 83 | Direct shipping counterexample |
| `microsoft-defender-automated-response-2026` | High quality | 82 | Strongest XDR lifecycle comparator |
| `datadog-application-security-automated-response-current` | High quality | 80 | Runtime/app temporary block, preview and off-switch comparator |
| `splunk-soar-approval-automation-2026` | High quality | 80 | Strongest approval/delegation/expiry comparator |
| `us8572750-web-exploit-mitigation` | Supporting | 77 | Direct historical scanner-to-virtual-patch disclosure |
| `us7895649-dynamic-rule-generation` | Supporting | 74 | Historical generation/integrity/aging disclosure |
| `ep3035637-policy-based-network-security` | Supporting | 76 | Historical policy-filter/approval/replanning disclosure |

The patent scores measure technical prior-art fitness, not implementation quality or legal
conclusion strength.

### Not promoted

Wallarm, Google Security Operations, CrowdStrike Fusion, Microsoft Sentinel, US11516242B2,
Contrast Protect and Waratek remain explicit candidates with promotion/version/legal-status gates.
They must not be counted as ranked evidence in library totals.

## Residual gaps and next bounded work

### Technical

- Independent hands-on execution of the four promoted commercial systems.
- Current Contrast/Waratek product contracts and one independent RASP/ADR evaluation.
- Cross-target F5/Datadog/Defender/SOAR effect-reconciliation experiment.
- Two-PDP deterministic R10 vertical slice.
- Exact SAFE/incident-exchange crosswalk for finding, incident, action and effect records.

### Patent/legal

- Family, prosecution, citations and independent-claim charts.
- Official USPTO/EPO status and assignment verification.
- India, Saudi, UAE and Qatar patent-family relevance.
- Counsel-led validity, design-around and freedom-to-operate assessment.

### Business/regional

- Current local availability, licensing, data location and support terms.
- Buyer interviews on willingness to pay for independent evidence/reconciliation.
- Procurement acceptance of adapters versus inline Warrantor enforcement.
- Measured integration and operating cost.

### Evidence quality

- Independent product efficacy and false-positive evidence.
- Public export schemas and retention/completeness guarantees.
- Exact rollback/expiry convergence measurements.
- Closed-system capability uncertainty.

## Final recommendation

Retire CLM-0009 and any derivative first/only language now. Keep the product, but define it as a
portable assurance and authority spine across installed policy and response controls.

The highest-value next implementation is deliberately small:

1. one reproduced finding;
2. one deterministic least-authority candidate;
3. two PDP targets;
4. one commercial enforcement adapter;
5. one signed quorum approval;
6. monitor, canary and enforce;
7. independently observed effect;
8. rollback and evidence-renewed expiry;
9. attack plus legitimate regression suite;
10. complete independently verifiable receipt set.

Until that passes, Warrantor has a well-supported research hypothesis and sharper market position,
not a demonstrated complete attack-to-policy assurance system.
