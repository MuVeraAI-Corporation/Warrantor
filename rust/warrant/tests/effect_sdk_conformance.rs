//! Task 7.1, Steps 6 to 9: the conformance kit, driven both ways.
//!
//! A kit that fails every adapter is not a kit, so this file holds the reference adapter that must
//! pass every vector beside four adapters each built to fail exactly one condition. The reference
//! adapter lives HERE and not in `src/`: it is what Task 7.3 transcribes, and shipping it would
//! ship an adapter this task's non-goals exclude. The last test in this file asserts that.
//!
//! Every assertion about the vocabulary goes through `Syscall::ALL` and the registry Task 2.1
//! produces. There is no list literal of verbs in this file.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use warrantor_warrant::effect_sdk::{
    run_conformance, vectors, AdapterOutcome, ConformanceReport, EffectAdapter, EffectGrant,
    CONFORMANCE_DEADLINE, CONFORMANCE_FORMAT, REPORT_SCOPE_SENTENCE, SENTINEL_VARIABLE,
};
use warrantor_warrant::effects::{Decomposition, DecompositionRegistry, Syscall};

const SENTINEL: &str = "sentinel-3f9c-not-a-real-secret";

/// The vocabulary has nine verbs; the kit's own static assertion stops the build otherwise, and
/// this repeats it where a reader of the tests looks first.
const _: () = assert!(Syscall::ALL.len() == 9);

/// The harness plants the sentinel in the process environment. Every test plants the same value
/// because tests share one process and run on parallel threads; the vector reads whatever is
/// there at the moment it runs.
fn plant_sentinel() {
    std::env::set_var(SENTINEL_VARIABLE, SENTINEL);
}

/// The registry under test: the builtin declarations plus one three-verb tool, so a decomposition
/// can be omitted from and over-declared against.
fn registry() -> DecompositionRegistry {
    let mut registry = DecompositionRegistry::builtin();
    let deploy = Decomposition::new(
        "deploy.to_prod",
        [Syscall::Exec, Syscall::Net, Syscall::Mutate]
            .into_iter()
            .collect(),
    )
    .expect("a three-verb decomposition parses");
    registry
        .insert(deploy)
        .expect("deploy.to_prod is not builtin");
    registry
}

fn vector<'a>(
    report: &'a ConformanceReport,
    name: &str,
) -> &'a warrantor_warrant::effect_sdk::VectorResult {
    report
        .vectors
        .iter()
        .find(|v| v.vector == name)
        .unwrap_or_else(|| panic!("no vector named {name} in {:#?}", report.vectors))
}

/// The reference adapter. Its declarations are its own knowledge, written out, so that a match
/// with the registry is a comparison of two independent statements and not a copy.
#[derive(Default)]
struct ReferenceAdapter {
    invocations: usize,
}

impl ReferenceAdapter {
    fn table(tool: &str) -> Option<BTreeSet<Syscall>> {
        let verbs: &[Syscall] = match tool {
            "github.create_pr" => &[Syscall::Net, Syscall::Mutate],
            "deploy.to_prod" => &[Syscall::Exec, Syscall::Net, Syscall::Mutate],
            _ => return None,
        };
        Some(verbs.iter().copied().collect())
    }
}

impl EffectAdapter for ReferenceAdapter {
    fn adapter_name(&self) -> &str {
        "reference"
    }
    fn tools(&self) -> Vec<String> {
        vec!["github.create_pr".to_string(), "deploy.to_prod".to_string()]
    }
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>> {
        Self::table(tool)
    }
    fn invoke(
        &mut self,
        tool: &str,
        _arguments: &BTreeMap<String, Value>,
        grant: &EffectGrant<'_>,
    ) -> AdapterOutcome {
        self.invocations += 1;
        // The receipt names what was done and under which verbs. It carries nothing that was
        // used to do it, because the grant offered nothing of the kind.
        let mut receipt_fields = BTreeMap::new();
        receipt_fields.insert("tool".to_string(), tool.to_string());
        receipt_fields.insert(
            "syscalls".to_string(),
            grant
                .syscalls()
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("+"),
        );
        receipt_fields.insert("deadline".to_string(), grant.deadline().to_string());
        AdapterOutcome::Performed { receipt_fields }
    }
}

/// Reads a credential of its own from the environment and writes it into the receipt. The grant
/// gave it nothing; the leak is the adapter's, and the runtime half of V1 is what sees it.
#[derive(Default)]
struct LeakyAdapter;

impl EffectAdapter for LeakyAdapter {
    fn adapter_name(&self) -> &str {
        "leaky"
    }
    fn tools(&self) -> Vec<String> {
        vec!["github.create_pr".to_string()]
    }
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>> {
        ReferenceAdapter::table(tool)
    }
    fn invoke(
        &mut self,
        _tool: &str,
        _arguments: &BTreeMap<String, Value>,
        _grant: &EffectGrant<'_>,
    ) -> AdapterOutcome {
        let mut receipt_fields = BTreeMap::new();
        receipt_fields.insert(
            "authorization".to_string(),
            std::env::var(SENTINEL_VARIABLE).unwrap_or_default(),
        );
        AdapterOutcome::Performed { receipt_fields }
    }
}

/// Declares `{net}` for a tool the registry decomposes as `{exec, net, mutate}`.
#[derive(Default)]
struct OmittingAdapter;

impl EffectAdapter for OmittingAdapter {
    fn adapter_name(&self) -> &str {
        "omitting"
    }
    fn tools(&self) -> Vec<String> {
        vec!["deploy.to_prod".to_string()]
    }
    fn declared_syscalls(&self, _tool: &str) -> Option<BTreeSet<Syscall>> {
        Some([Syscall::Net].into_iter().collect())
    }
    fn invoke(
        &mut self,
        _tool: &str,
        _arguments: &BTreeMap<String, Value>,
        _grant: &EffectGrant<'_>,
    ) -> AdapterOutcome {
        AdapterOutcome::Refused {
            reason: "not exercised".to_string(),
        }
    }
}

/// Declares a strict superset of the registry's decomposition. Over-declaring is not safe: it
/// widens what the kernel would authorize for the tool, and the kit must say so distinctly.
#[derive(Default)]
struct OverDeclaringAdapter;

impl EffectAdapter for OverDeclaringAdapter {
    fn adapter_name(&self) -> &str {
        "over-declaring"
    }
    fn tools(&self) -> Vec<String> {
        vec!["deploy.to_prod".to_string()]
    }
    fn declared_syscalls(&self, _tool: &str) -> Option<BTreeSet<Syscall>> {
        Some(
            [Syscall::Exec, Syscall::Net, Syscall::Mutate, Syscall::Cred]
                .into_iter()
                .collect(),
        )
    }
    fn invoke(
        &mut self,
        _tool: &str,
        _arguments: &BTreeMap<String, Value>,
        _grant: &EffectGrant<'_>,
    ) -> AdapterOutcome {
        AdapterOutcome::Refused {
            reason: "not exercised".to_string(),
        }
    }
}

/// Offers a tool nobody declared.
#[derive(Default)]
struct UndeclaredAdapter;

impl EffectAdapter for UndeclaredAdapter {
    fn adapter_name(&self) -> &str {
        "undeclared"
    }
    fn tools(&self) -> Vec<String> {
        vec![
            "github.create_pr".to_string(),
            "nobody.declared_this".to_string(),
        ]
    }
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>> {
        ReferenceAdapter::table(tool).or_else(|| Some([Syscall::Net].into_iter().collect()))
    }
    fn invoke(
        &mut self,
        _tool: &str,
        _arguments: &BTreeMap<String, Value>,
        _grant: &EffectGrant<'_>,
    ) -> AdapterOutcome {
        AdapterOutcome::Staged {
            handle: "stg_test".to_string(),
        }
    }
}

// ----- Step 6: the credential vector, both directions -----

#[test]
fn a_leaky_adapter_fails_the_credential_vector() {
    plant_sentinel();
    let report = run_conformance(&mut LeakyAdapter, &registry(), "test-upstream/0");
    let v1 = vector(&report, vectors::NO_CREDENTIAL_IN_GRANT);
    assert!(
        !v1.passed,
        "an adapter that reads a credential must fail V1: {v1:#?}"
    );
    assert!(
        v1.detail.contains("github.create_pr") && v1.detail.contains("authorization"),
        "the detail names the tool and the field that carried the sentinel: {}",
        v1.detail
    );
    assert!(!report.all_passed());
}

#[test]
fn the_reference_adapter_passes_every_vector() {
    // The allowed control. A kit that fails every adapter is not a kit.
    plant_sentinel();
    let mut adapter = ReferenceAdapter::default();
    let report = run_conformance(&mut adapter, &registry(), "test-upstream/0");
    assert!(report.all_passed(), "vectors: {:#?}", report.vectors);
    assert_eq!(
        report.vectors.len(),
        3,
        "three vectors ran: {:#?}",
        report.vectors
    );
    assert_eq!(
        adapter.invocations, 2,
        "V1 invoked each registry-known tool once under a grant"
    );
}

#[test]
fn the_grant_carries_exactly_what_the_kit_constructed() {
    // A grant is the registry's decomposition, no destination, and the kit's fixed deadline. The
    // reference adapter copies those into its receipt, so the receipt is where they are read.
    plant_sentinel();
    struct Recording(Vec<(String, String)>);
    impl EffectAdapter for Recording {
        fn adapter_name(&self) -> &str {
            "recording"
        }
        fn tools(&self) -> Vec<String> {
            vec!["deploy.to_prod".to_string()]
        }
        fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>> {
            ReferenceAdapter::table(tool)
        }
        fn invoke(
            &mut self,
            tool: &str,
            _arguments: &BTreeMap<String, Value>,
            grant: &EffectGrant<'_>,
        ) -> AdapterOutcome {
            self.0.push((
                tool.to_string(),
                format!(
                    "{}|{:?}|{}",
                    grant
                        .syscalls()
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("+"),
                    grant.destination(),
                    grant.deadline()
                ),
            ));
            AdapterOutcome::Performed {
                receipt_fields: BTreeMap::new(),
            }
        }
    }
    let mut adapter = Recording(Vec::new());
    let _ = run_conformance(&mut adapter, &registry(), "test-upstream/0");
    assert_eq!(
        adapter.0,
        vec![(
            "deploy.to_prod".to_string(),
            // net+exec+mutate, not alphabetical: BTreeSet orders by Syscall's derived Ord,
            // which is the declaration order of the nine verbs in effects.rs.
            format!("net+exec+mutate|None|{CONFORMANCE_DEADLINE}")
        )],
        "the grant is derived from the registry entry and nothing else"
    );
}

// ----- Step 7: declaration vectors, with the over-declaring control -----

#[test]
fn an_omitting_adapter_fails_v3_naming_the_missing_verbs() {
    plant_sentinel();
    let report = run_conformance(&mut OmittingAdapter, &registry(), "test-upstream/0");
    let v3 = vector(&report, vectors::DECOMPOSITION_MATCHES_REGISTRY);
    assert!(!v3.passed, "{v3:#?}");
    assert!(
        v3.detail.contains("omits") && v3.detail.contains("exec") && v3.detail.contains("mutate"),
        "the missing verbs are named: {}",
        v3.detail
    );
    assert!(
        !v3.detail.contains("over-declares"),
        "an omission is not reported as an over-declaration: {}",
        v3.detail
    );
}

#[test]
fn an_over_declaring_adapter_fails_v3_with_a_distinct_detail() {
    plant_sentinel();
    let report = run_conformance(&mut OverDeclaringAdapter, &registry(), "test-upstream/0");
    let v3 = vector(&report, vectors::DECOMPOSITION_MATCHES_REGISTRY);
    assert!(!v3.passed, "{v3:#?}");
    assert!(
        v3.detail.contains("over-declares") && v3.detail.contains("cred"),
        "the extra verb is named as an over-declaration: {}",
        v3.detail
    );
    assert!(
        !v3.detail.contains("omits"),
        "a superset omits nothing: {}",
        v3.detail
    );
    // Declaring correctly for V2 does not rescue V3: the report as a whole fails.
    assert!(vector(&report, vectors::EVERY_TOOL_DECLARED).passed);
    assert!(!report.all_passed());
}

#[test]
fn an_undeclared_tool_fails_v2_under_refuse() {
    plant_sentinel();
    let report = run_conformance(&mut UndeclaredAdapter, &registry(), "test-upstream/0");
    let v2 = vector(&report, vectors::EVERY_TOOL_DECLARED);
    assert!(!v2.passed, "{v2:#?}");
    assert!(
        v2.detail.contains("nobody.declared_this") && !v2.detail.contains("github.create_pr"),
        "only the undeclared tool is named: {}",
        v2.detail
    );
    // The declared tool it also offers still passes V1 and V3 on its own terms: the failure is
    // V2's and is not smeared across the report.
    assert!(vector(&report, vectors::NO_CREDENTIAL_IN_GRANT).passed);
    assert!(vector(&report, vectors::DECOMPOSITION_MATCHES_REGISTRY).passed);
}

#[test]
fn the_vocabulary_the_kit_asserts_against_has_nine_verbs() {
    assert_eq!(Syscall::ALL.len(), 9);
    let distinct: BTreeSet<Syscall> = Syscall::ALL.into_iter().collect();
    assert_eq!(distinct.len(), 9, "nine distinct verbs, none repeated");
}

// ----- Step 8: the report -----

#[test]
fn the_report_round_trips_and_carries_format_and_upstream_version() {
    plant_sentinel();
    let report = run_conformance(
        &mut ReferenceAdapter::default(),
        &registry(),
        "server-filesystem/2026.8.31",
    );
    let json = report.to_json().expect("serializes");
    let parsed: Value = serde_json::from_str(&json).expect("parses back");
    assert_eq!(parsed["format"], CONFORMANCE_FORMAT);
    assert_eq!(parsed["adapter"], "reference");
    assert_eq!(parsed["upstream_version"], "server-filesystem/2026.8.31");
    assert_eq!(parsed["scope"], REPORT_SCOPE_SENTENCE);
    assert_eq!(parsed["vectors"].as_array().map(Vec::len), Some(3));
    assert!(json.contains("not the adapter's runtime behavior or its private state"));
}

#[test]
fn an_empty_report_does_not_pass() {
    let report = ConformanceReport {
        format: CONFORMANCE_FORMAT,
        adapter: "nothing".to_string(),
        upstream_version: "none".to_string(),
        scope: REPORT_SCOPE_SENTENCE,
        vectors: Vec::new(),
    };
    assert!(!report.all_passed(), "zero vectors is not a pass");
}

// ----- Step 9: the reference adapter is not in the shipping build -----

#[test]
fn the_reference_adapter_is_not_in_the_shipping_build() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    let mut files = 0usize;
    let mut hits = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src is readable") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files += 1;
                let text = std::fs::read_to_string(&path).expect("source is UTF-8");
                if text.contains("ReferenceAdapter") {
                    hits.push(path.display().to_string());
                }
            }
        }
    }
    assert!(
        files > 20,
        "the walk saw the crate's sources ({files} files), not an empty dir"
    );
    assert!(hits.is_empty(), "ReferenceAdapter must not ship: {hits:?}");
    // The paired control: the same walk finds the accessor-free grant type, so a zero above is a
    // real zero and not a walk that read nothing.
    let sdk = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/effect_sdk.rs");
    let text = std::fs::read_to_string(sdk).expect("effect_sdk.rs exists");
    assert!(text.contains("pub struct EffectGrant"));
    for absent in [
        "fn credential(",
        "fn token(",
        "fn secret(",
        "fn header(",
        "fn env(",
    ] {
        assert!(
            !text.contains(absent),
            "EffectGrant grew an accessor this task forbids: {absent}"
        );
    }
}
