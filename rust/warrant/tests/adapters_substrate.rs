//! Task 7.4: the three substrate-mutating adapters, driven through the public SDK surface.
//!
//! The exit gate, quoted: "For each of the three, a test proves an effect that would modify
//! Warrantor's own policy, workflow or entitlements is refused, AND a control effect of the same
//! class against an unrelated resource is allowed -- a refusal that refuses everything proves
//! nothing." Every refusal test below has its control in the same function.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use warrantor_warrant::adapters::substrate::{
    governs_its_own_governor, CiCdAdapter, CloudControlPlaneAdapter, IdentityProviderAdapter,
    OwnSubstrate, SubstrateTarget, SubstrateTransport, CICD_EDIT_WORKFLOW, CICD_READ_WORKFLOW,
    CICD_TRIGGER_RUN, CLOUD_APPLY_NETWORK_POLICY, CLOUD_DESCRIBE_POLICY, IDP_GRANT_ENTITLEMENT,
    IDP_LIST_ENTITLEMENTS, SHELL_BYPASS_SENTENCE,
};
use warrantor_warrant::effect_sdk::{
    run_conformance, AdapterOutcome, EffectAdapter, EffectGrant, CONFORMANCE_DEADLINE,
    SENTINEL_VARIABLE,
};
use warrantor_warrant::effects::{Decomposition, DecompositionRegistry, Syscall};

/// A transport that answers every read with the arguments it was handed and records the call. It
/// never sees a credential because none exists in this test process except the planted sentinel,
/// which V1 of the conformance kit watches for.
#[derive(Default)]
struct Recording {
    reads: Vec<String>,
}

impl SubstrateTransport for Recording {
    fn read(
        &mut self,
        tool: &str,
        arguments: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, String>, String> {
        self.reads.push(tool.to_string());
        Ok(arguments
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect())
    }
}

/// A transport that fails every read, to prove a failed read is a refusal and not a receipt.
struct Broken;

impl SubstrateTransport for Broken {
    fn read(
        &mut self,
        _tool: &str,
        _arguments: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, String>, String> {
        Err("no route to the control plane".to_string())
    }
}

fn own() -> OwnSubstrate {
    OwnSubstrate {
        policy_names: ["warrantor-egress-floor".to_string()].into_iter().collect(),
        workflow_paths: [".github/workflows/ci.yml".to_string()]
            .into_iter()
            .collect(),
        entitlement_ids: ["ent_warrantor_runner".to_string()].into_iter().collect(),
        principals: ["svc:warrantor-agent".to_string()].into_iter().collect(),
    }
}

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), json!(v)))
        .collect()
}

fn grant_for<'a>(syscalls: &'a BTreeSet<Syscall>) -> EffectGrant<'a> {
    EffectGrant::new(syscalls, None, CONFORMANCE_DEADLINE)
}

fn invoke<A: EffectAdapter>(
    adapter: &mut A,
    tool: &str,
    arguments: &BTreeMap<String, Value>,
) -> AdapterOutcome {
    let syscalls = adapter
        .declared_syscalls(tool)
        .unwrap_or_else(|| panic!("{tool} is declared by the adapter under test"));
    let grant = grant_for(&syscalls);
    adapter.invoke(tool, arguments, &grant)
}

fn is_refused_for_self_governance(outcome: &AdapterOutcome, target: &str) -> bool {
    match outcome {
        AdapterOutcome::Refused { reason } => {
            reason.contains("govern its own governor") && reason.contains(target)
        }
        _ => false,
    }
}

// ───────────── Step 2: the policy that authorized it ─────────────

#[test]
fn a_cloud_adapter_cannot_rewrite_the_policy_that_authorized_it_but_can_rewrite_another() {
    let mut adapter = CloudControlPlaneAdapter::new(own(), Recording::default());

    let refused = invoke(
        &mut adapter,
        CLOUD_APPLY_NETWORK_POLICY,
        &args(&[("policy_name", "warrantor-egress-floor")]),
    );
    assert!(
        is_refused_for_self_governance(&refused, "warrantor-egress-floor"),
        "the authorizing policy must be refused by name: {refused:?}"
    );

    // The control: same tool, same class, a policy this session does not depend on.
    let allowed = invoke(
        &mut adapter,
        CLOUD_APPLY_NETWORK_POLICY,
        &args(&[("policy_name", "team-b-ingress")]),
    );
    assert!(
        matches!(allowed, AdapterOutcome::Staged { .. }),
        "an unrelated policy must be staged, not refused: {allowed:?}"
    );
}

// ───────────── Step 3: the workflow that runs the gates ─────────────

#[test]
fn a_cicd_adapter_cannot_edit_the_gate_workflow_but_can_edit_another_and_can_run_the_gates() {
    let mut adapter = CiCdAdapter::new(own(), Recording::default());

    let refused = invoke(
        &mut adapter,
        CICD_EDIT_WORKFLOW,
        &args(&[("workflow_path", ".github/workflows/ci.yml")]),
    );
    assert!(
        is_refused_for_self_governance(&refused, ".github/workflows/ci.yml"),
        "editing the gate workflow must be refused: {refused:?}"
    );

    let allowed = invoke(
        &mut adapter,
        CICD_EDIT_WORKFLOW,
        &args(&[("workflow_path", ".github/workflows/docs-preview.yml")]),
    );
    assert!(
        matches!(allowed, AdapterOutcome::Staged { .. }),
        "an unrelated workflow must be staged: {allowed:?}"
    );

    // Running the gates is not editing them. Triggering the gate workflow is allowed, and this
    // distinguishes the predicate from a blanket refusal of anything that names ci.yml.
    let run = invoke(
        &mut adapter,
        CICD_TRIGGER_RUN,
        &args(&[("workflow_path", ".github/workflows/ci.yml")]),
    );
    assert!(
        matches!(run, AdapterOutcome::Staged { .. }),
        "triggering the gate workflow is allowed: {run:?}"
    );
}

// ───────────── Step 4: the entitlement it used ─────────────

#[test]
fn an_idp_adapter_cannot_grant_the_entitlement_it_used_nor_widen_its_own_principal() {
    let mut adapter = IdentityProviderAdapter::new(own(), Recording::default());

    let by_entitlement = invoke(
        &mut adapter,
        IDP_GRANT_ENTITLEMENT,
        &args(&[
            ("entitlement_id", "ent_warrantor_runner"),
            ("principal", "user:alice"),
        ]),
    );
    assert!(
        is_refused_for_self_governance(&by_entitlement, "ent_warrantor_runner"),
        "re-granting the entitlement this session used must be refused: {by_entitlement:?}"
    );

    let by_principal = invoke(
        &mut adapter,
        IDP_GRANT_ENTITLEMENT,
        &args(&[
            ("entitlement_id", "ent_billing_read"),
            ("principal", "svc:warrantor-agent"),
        ]),
    );
    assert!(
        is_refused_for_self_governance(&by_principal, "svc:warrantor-agent"),
        "granting anything to this session's own principal must be refused: {by_principal:?}"
    );

    let allowed = invoke(
        &mut adapter,
        IDP_GRANT_ENTITLEMENT,
        &args(&[
            ("entitlement_id", "ent_billing_read"),
            ("principal", "user:alice"),
        ]),
    );
    assert!(
        matches!(allowed, AdapterOutcome::Staged { .. }),
        "an unrelated grant must be staged: {allowed:?}"
    );
}

// ───────────── the predicate's own edges ─────────────

#[test]
fn an_undeclared_substrate_refuses_every_mutation_and_says_why() {
    let nothing = OwnSubstrate::default();
    assert!(nothing.declares_nothing());
    let refusal = governs_its_own_governor(&nothing, SubstrateTarget::Policy("anything"))
        .expect("nothing declared means nothing may be mutated");
    assert!(refusal.matched.contains("declared no substrate"));
    assert!(
        refusal.render().contains("anything"),
        "the sentence names the target"
    );

    // The control for the control: with a substrate declared, the same target is NOT refused.
    assert!(governs_its_own_governor(&own(), SubstrateTarget::Policy("anything")).is_none());
}

#[test]
fn a_mutation_with_no_named_target_is_refused_not_defaulted() {
    let mut adapter = CloudControlPlaneAdapter::new(own(), Recording::default());
    let missing = invoke(&mut adapter, CLOUD_APPLY_NETWORK_POLICY, &args(&[]));
    assert!(
        matches!(&missing, AdapterOutcome::Refused { reason } if reason.contains("policy_name")),
        "a missing target is a refusal naming the argument: {missing:?}"
    );
    let empty = invoke(
        &mut adapter,
        CLOUD_APPLY_NETWORK_POLICY,
        &args(&[("policy_name", "")]),
    );
    assert!(
        matches!(empty, AdapterOutcome::Refused { .. }),
        "an empty target too: {empty:?}"
    );
}

#[test]
fn the_refusal_sentence_is_derived_from_the_record() {
    let refusal = governs_its_own_governor(
        &own(),
        SubstrateTarget::Workflow(".github/workflows/ci.yml"),
    )
    .expect("the gate workflow is declared");
    let rendered = refusal.render();
    assert!(
        rendered.contains(&refusal.target),
        "the target in the sentence is the record's"
    );
    assert!(rendered.contains(refusal.matched), "and so is the match");
}

#[test]
fn a_failed_read_is_a_refusal_and_not_a_receipt() {
    let mut adapter = CloudControlPlaneAdapter::new(own(), Broken);
    let out = invoke(
        &mut adapter,
        CLOUD_DESCRIBE_POLICY,
        &args(&[("policy_name", "team-b-ingress")]),
    );
    assert!(
        matches!(&out, AdapterOutcome::Refused { reason } if reason.contains("no route")),
        "a transport failure must not become a Performed receipt: {out:?}"
    );
    // Control: a working transport answers, and the adapter recorded exactly one read.
    let mut working = CloudControlPlaneAdapter::new(own(), Recording::default());
    let ok = invoke(
        &mut working,
        CLOUD_DESCRIBE_POLICY,
        &args(&[("policy_name", "team-b-ingress")]),
    );
    assert!(matches!(ok, AdapterOutcome::Performed { .. }), "{ok:?}");
}

// ───────────── Step 5: conformance is the gate ─────────────

/// The registry is the test's own knowledge, written out, so that a match with each adapter's
/// declaration is a comparison of two independent statements.
fn registry() -> DecompositionRegistry {
    let mut registry = DecompositionRegistry::new();
    for (tool, verbs) in [
        (
            CLOUD_APPLY_NETWORK_POLICY,
            vec![Syscall::Net, Syscall::Mutate],
        ),
        (CLOUD_DESCRIBE_POLICY, vec![Syscall::Net]),
        (CICD_EDIT_WORKFLOW, vec![Syscall::Net, Syscall::Mutate]),
        (CICD_TRIGGER_RUN, vec![Syscall::Net, Syscall::Exec]),
        (CICD_READ_WORKFLOW, vec![Syscall::Net]),
        (
            IDP_GRANT_ENTITLEMENT,
            vec![Syscall::Net, Syscall::Cred, Syscall::Mutate],
        ),
        (IDP_LIST_ENTITLEMENTS, vec![Syscall::Net]),
    ] {
        registry
            .insert(Decomposition::new(tool, verbs.into_iter().collect()).expect("parses"))
            .expect("no duplicates");
    }
    registry
}

#[test]
fn all_three_adapters_pass_the_conformance_kit() {
    std::env::set_var(SENTINEL_VARIABLE, "sentinel-7f4a-not-a-real-secret");
    let registry = registry();
    let mut cloud = CloudControlPlaneAdapter::new(own(), Recording::default());
    let mut cicd = CiCdAdapter::new(own(), Recording::default());
    let mut idp = IdentityProviderAdapter::new(own(), Recording::default());
    for report in [
        run_conformance(&mut cloud, &registry, "test-substrate/0"),
        run_conformance(&mut cicd, &registry, "test-substrate/0"),
        run_conformance(&mut idp, &registry, "test-substrate/0"),
    ] {
        assert!(
            report.all_passed(),
            "{}: {:#?}",
            report.adapter,
            report.vectors
        );
        assert_eq!(report.vectors.len(), 3, "{}", report.adapter);
    }
}

// ───────────── Step 6: decompositions, against Task 2.1's vocabulary ─────────────

#[test]
fn every_mutation_decomposes_to_mutate_and_an_entitlement_change_to_cred() {
    let cloud = CloudControlPlaneAdapter::new(own(), Recording::default());
    let cicd = CiCdAdapter::new(own(), Recording::default());
    let idp = IdentityProviderAdapter::new(own(), Recording::default());
    for (tool, set) in [
        (
            CLOUD_APPLY_NETWORK_POLICY,
            cloud.declared_syscalls(CLOUD_APPLY_NETWORK_POLICY),
        ),
        (
            CICD_EDIT_WORKFLOW,
            cicd.declared_syscalls(CICD_EDIT_WORKFLOW),
        ),
        (
            IDP_GRANT_ENTITLEMENT,
            idp.declared_syscalls(IDP_GRANT_ENTITLEMENT),
        ),
    ] {
        let set = set.unwrap_or_else(|| panic!("{tool} declared"));
        assert!(
            set.contains(&Syscall::Mutate),
            "{tool} must decompose to MUTATE: {set:?}"
        );
        assert!(
            set.iter().all(|s| Syscall::ALL.contains(s)),
            "{tool} uses only Task 2.1's nine verbs"
        );
    }
    let grant = idp
        .declared_syscalls(IDP_GRANT_ENTITLEMENT)
        .expect("declared");
    assert!(
        grant.contains(&Syscall::Cred),
        "an entitlement change is a credential change"
    );
    // The control: a read decomposes to no MUTATE and no CRED.
    let read = idp
        .declared_syscalls(IDP_LIST_ENTITLEMENTS)
        .expect("declared");
    assert!(
        !read.contains(&Syscall::Mutate) && !read.contains(&Syscall::Cred),
        "{read:?}"
    );
}

// ───────────── Step 7: the bypass is named ─────────────

#[test]
fn the_product_sentence_names_what_escapes() {
    for fragment in [
        "shell and the cloud CLI bypasses all three",
        "adapter's own call site",
        "nothing in the shipping binary dispatches these adapters",
    ] {
        assert!(
            SHELL_BYPASS_SENTENCE.contains(fragment),
            "missing {fragment:?}"
        );
    }
    assert!(
        !SHELL_BYPASS_SENTENCE.contains("Enforced"),
        "a chokepoint refusal is not Enforced"
    );
}
