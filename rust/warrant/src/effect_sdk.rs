//! L4-25, the SDK half — the effect adapter trait and its conformance kit.
//!
//! An adapter is the code that performs one family of effects on behalf of a warrant: a messaging
//! adapter, a cloud control-plane adapter, a package-registry adapter. Tasks 7.3 through 7.6 write
//! them. This module writes none. It fixes the surface every adapter is handed and the vectors
//! every adapter must pass, so that the first adapter is transcribed from a contract rather than
//! invented.
//!
//! **What this is: Tier C, observed.** [`run_conformance`] proves that an adapter, under vectors
//! the harness constructs, declares every tool it offers, declares each tool's decomposition
//! exactly as the registry does, and writes no planted secret into anything it returns. It proves
//! nothing about a shipped adapter at runtime, and it cannot see an adapter's private state: the
//! [`EffectGrant`] surface has no credential accessor, but an adapter that holds a token in its own
//! struct is invisible to the kit, and the report says so in its own text
//! ([`REPORT_SCOPE_SENTENCE`]). A passing report is not a safety claim. It is a list of vectors
//! that ran and what each one observed.
//!
//! **No new trust root.** A [`ConformanceReport`] is a local JSON document. It establishes that the
//! adapter passed these vectors on the machine that ran them, and nothing about who wrote the
//! adapter, whether the binary shown is the binary run, or whether the upstream changed underneath.
//! The report carries the upstream version the caller observed and claims coverage for no other.
//!
//! **What is deliberately absent from [`EffectGrant`]:** `credential()`, `token()`, `secret()`,
//! `header()`, `env()`. An adapter is handed the syscalls it may exercise, the destination if one
//! is bound, and the deadline. Adding an accessor is a source-gate failure in
//! `rust/warrant/tests/effect_sdk_conformance.rs`.
//!
//! The vocabulary the kit asserts against is [`Syscall::ALL`], owned by Task 2.1. This module
//! defines no list of its own; a second list would be the nine-invented-decompositions defect at
//! one remove.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::effects::{DecompositionRegistry, Syscall, UnclassifiedPolicy};

/// The format tag every report carries, so a reader can refuse a document it does not know.
pub const CONFORMANCE_FORMAT: &str = "warrantor.adapter-conformance/1";

/// The sentence every report renders about itself. It is the kit's honest scope and it is not
/// optional: a report without it could be read as a statement about runtime behavior.
pub const REPORT_SCOPE_SENTENCE: &str = "this report describes the adapter surface under test \
                                         vectors, not the adapter's runtime behavior or its \
                                         private state.";

/// The environment variable the harness plants a sentinel in before running the kit. Vector V1's
/// runtime half searches everything the adapter returns for this value. When the variable is
/// unset the vector does not pass: a kit that passes with nothing planted has measured nothing.
pub const SENTINEL_VARIABLE: &str = "WARRANTOR_CONFORMANCE_SENTINEL";

/// The deadline the kit hands every grant. Conformance runs against no clock; the value exists so
/// an adapter that reads the deadline sees a number rather than a surprise, and so a test can
/// assert the grant carried exactly what the kit constructed.
pub const CONFORMANCE_DEADLINE: u64 = 4_102_444_800;

/// The vocabulary has nine verbs. If anyone reintroduces a five-value list, this line stops the
/// build rather than letting the kit assert against the wrong table.
const _: () = assert!(Syscall::ALL.len() == 9);

/// What an adapter is handed for one invocation. It has no credential accessor, and adding one
/// is a source-gate failure in `rust/warrant/tests/effect_sdk_conformance.rs`.
#[derive(Debug)]
pub struct EffectGrant<'a> {
    syscalls: &'a BTreeSet<Syscall>,
    destination: Option<&'a str>,
    deadline: u64,
}

impl<'a> EffectGrant<'a> {
    /// Build a grant from a declared decomposition, an optional bound destination, and a deadline.
    /// The kit is the only caller in this crate; a shipping caller arrives with Task 7.3.
    pub fn new(
        syscalls: &'a BTreeSet<Syscall>,
        destination: Option<&'a str>,
        deadline: u64,
    ) -> Self {
        Self {
            syscalls,
            destination,
            deadline,
        }
    }

    /// The effect syscalls this invocation may exercise, exactly as the registry declares them.
    pub fn syscalls(&self) -> &BTreeSet<Syscall> {
        self.syscalls
    }

    /// The destination the warrant bound, when the effect has one.
    pub fn destination(&self) -> Option<&str> {
        self.destination
    }

    /// The Unix second after which the grant is void.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }
}

/// What an adapter reports back. The receipt fields of a performed effect are the only channel an
/// adapter has to the evidence chain, which is why the kit reads them for a planted secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterOutcome {
    /// The effect happened. The fields become the receipt's `details`.
    Performed {
        /// Key-value facts about what was done, and nothing that was used to do it.
        receipt_fields: BTreeMap<String, String>,
    },
    /// The adapter refused, with a sentence for the operator.
    Refused {
        /// Why.
        reason: String,
    },
    /// The effect was staged for a later settle and this is its handle.
    Staged {
        /// The handle a settle can redeem.
        handle: String,
    },
}

/// The surface an adapter implements. Nothing here hands the adapter a credential; what it needs
/// to authenticate is its own concern and outside what the kit can see.
pub trait EffectAdapter {
    /// A stable name for reports.
    fn adapter_name(&self) -> &str;
    /// Every tool this adapter offers, as published tool names.
    fn tools(&self) -> Vec<String>;
    /// The decomposition the adapter declares for one of its tools, or `None` if it declares
    /// nothing for it. The kit compares this with the registry and accepts no difference in
    /// either direction.
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>>;
    /// Perform, refuse, or stage one invocation under a grant.
    fn invoke(
        &mut self,
        tool: &str,
        arguments: &BTreeMap<String, Value>,
        grant: &EffectGrant<'_>,
    ) -> AdapterOutcome;
}

/// One vector's outcome. `detail` says what was observed, never what was concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VectorResult {
    /// The vector's stable name.
    pub vector: &'static str,
    /// Whether the vector's condition held for this adapter.
    pub passed: bool,
    /// What the kit saw, in enough words to reproduce it.
    pub detail: String,
}

/// The kit's output: which vectors ran against which adapter, under which upstream version, and
/// what each observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConformanceReport {
    /// [`CONFORMANCE_FORMAT`].
    pub format: &'static str,
    /// The adapter's own name.
    pub adapter: String,
    /// The upstream version the caller observed. The report covers this version and no other.
    pub upstream_version: String,
    /// [`REPORT_SCOPE_SENTENCE`], rendered into every report.
    pub scope: &'static str,
    /// Every vector, in the order it ran.
    pub vectors: Vec<VectorResult>,
}

impl ConformanceReport {
    /// True only if every vector passed. An empty vector list does not pass.
    pub fn all_passed(&self) -> bool {
        !self.vectors.is_empty() && self.vectors.iter().all(|v| v.passed)
    }

    /// Render as JSON.
    ///
    /// # Errors
    /// The serializer's message, if it has one.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }
}

/// The vector names, so a test can find a result by name rather than by position.
pub mod vectors {
    /// V1: nothing the adapter returns carries the planted sentinel.
    pub const NO_CREDENTIAL_IN_GRANT: &str = "no-credential-in-grant";
    /// V2: every tool the adapter offers is declared in the registry.
    pub const EVERY_TOOL_DECLARED: &str = "every-tool-declared";
    /// V3: the adapter's declared decomposition equals the registry's, tool by tool.
    pub const DECOMPOSITION_MATCHES_REGISTRY: &str = "decomposition-matches-registry";
}

/// Run every vector against one adapter and return what was observed.
///
/// `upstream_version` is whatever the caller observed of the system the adapter fronts. The kit
/// does not ask the adapter, because an adapter reporting its own upstream's version would be a
/// claim the kit cannot check.
pub fn run_conformance<A: EffectAdapter>(
    adapter: &mut A,
    registry: &DecompositionRegistry,
    upstream_version: &str,
) -> ConformanceReport {
    let tools = adapter.tools();
    let mut results = vec![
        v1_no_credential_in_grant(adapter, registry, &tools),
        v2_every_tool_declared(registry, &tools),
    ];
    results.push(v3_decomposition_matches_registry(adapter, registry, &tools));
    ConformanceReport {
        format: CONFORMANCE_FORMAT,
        adapter: adapter.adapter_name().to_string(),
        upstream_version: upstream_version.to_string(),
        scope: REPORT_SCOPE_SENTENCE,
        vectors: results,
    }
}

fn render(syscalls: &BTreeSet<Syscall>) -> String {
    syscalls
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("+")
}

fn v1_no_credential_in_grant<A: EffectAdapter>(
    adapter: &mut A,
    registry: &DecompositionRegistry,
    tools: &[String],
) -> VectorResult {
    let sentinel = match std::env::var(SENTINEL_VARIABLE) {
        Ok(value) if !value.is_empty() => value,
        _ => {
            return VectorResult {
                vector: vectors::NO_CREDENTIAL_IN_GRANT,
                passed: false,
                detail: format!(
                    "no sentinel was planted ({SENTINEL_VARIABLE} is unset or empty); the runtime \
                     half did not run, and a vector that did not run does not pass"
                ),
            }
        }
    };
    let mut invoked = 0usize;
    let mut leaks: Vec<String> = Vec::new();
    for tool in tools {
        let Some(decomposition) = registry.get(tool) else {
            continue; // V2 reports it; there is no grant to hand it
        };
        let grant = EffectGrant::new(decomposition.syscalls(), None, CONFORMANCE_DEADLINE);
        let arguments: BTreeMap<String, Value> = BTreeMap::new();
        invoked += 1;
        let returned: Vec<(String, String)> = match adapter.invoke(tool, &arguments, &grant) {
            AdapterOutcome::Performed { receipt_fields } => receipt_fields.into_iter().collect(),
            AdapterOutcome::Refused { reason } => vec![("refused.reason".to_string(), reason)],
            AdapterOutcome::Staged { handle } => vec![("staged.handle".to_string(), handle)],
        };
        for (key, value) in returned {
            if key.contains(&sentinel) || value.contains(&sentinel) {
                leaks.push(format!("{tool}: field {key:?}"));
            }
        }
    }
    if invoked == 0 {
        return VectorResult {
            vector: vectors::NO_CREDENTIAL_IN_GRANT,
            passed: false,
            detail: "no tool the adapter offers is known to the registry, so nothing could be \
                     invoked under a grant; the vector did not run"
                .to_string(),
        };
    }
    if leaks.is_empty() {
        VectorResult {
            vector: vectors::NO_CREDENTIAL_IN_GRANT,
            passed: true,
            detail: format!(
                "{invoked} tool(s) invoked under a grant with no credential accessor; the planted \
                 sentinel appeared in nothing the adapter returned"
            ),
        }
    } else {
        VectorResult {
            vector: vectors::NO_CREDENTIAL_IN_GRANT,
            passed: false,
            detail: format!(
                "the planted sentinel appeared in what the adapter returned: {}",
                leaks.join(", ")
            ),
        }
    }
}

fn v2_every_tool_declared(registry: &DecompositionRegistry, tools: &[String]) -> VectorResult {
    let undeclared: Vec<&str> = tools
        .iter()
        .filter(|tool| registry.classify(tool, UnclassifiedPolicy::Refuse).is_err())
        .map(String::as_str)
        .collect();
    if tools.is_empty() {
        VectorResult {
            vector: vectors::EVERY_TOOL_DECLARED,
            passed: false,
            detail: "the adapter offers no tools; there is nothing to declare and nothing to \
                     conform"
                .to_string(),
        }
    } else if undeclared.is_empty() {
        VectorResult {
            vector: vectors::EVERY_TOOL_DECLARED,
            passed: true,
            detail: format!(
                "all {} tool(s) are declared in the registry under UnclassifiedPolicy::Refuse",
                tools.len()
            ),
        }
    } else {
        VectorResult {
            vector: vectors::EVERY_TOOL_DECLARED,
            passed: false,
            detail: format!(
                "undeclared under UnclassifiedPolicy::Refuse: {}",
                undeclared.join(", ")
            ),
        }
    }
}

fn v3_decomposition_matches_registry<A: EffectAdapter>(
    adapter: &A,
    registry: &DecompositionRegistry,
    tools: &[String],
) -> VectorResult {
    let mut compared = 0usize;
    let mut mismatches: Vec<String> = Vec::new();
    for tool in tools {
        let Some(decomposition) = registry.get(tool) else {
            continue;
        };
        compared += 1;
        let expected = decomposition.syscalls();
        match adapter.declared_syscalls(tool) {
            None => mismatches.push(format!(
                "{tool}: declares nothing; the registry has {}",
                render(expected)
            )),
            Some(declared) => {
                let omitted: BTreeSet<Syscall> = expected.difference(&declared).copied().collect();
                let extra: BTreeSet<Syscall> = declared.difference(expected).copied().collect();
                if !omitted.is_empty() {
                    mismatches.push(format!("{tool}: omits {}", render(&omitted)));
                }
                if !extra.is_empty() {
                    mismatches.push(format!(
                        "{tool}: over-declares {} (widening what the kernel would authorize)",
                        render(&extra)
                    ));
                }
            }
        }
    }
    if compared == 0 {
        VectorResult {
            vector: vectors::DECOMPOSITION_MATCHES_REGISTRY,
            passed: false,
            detail: "no tool the adapter offers is known to the registry; nothing was compared"
                .to_string(),
        }
    } else if mismatches.is_empty() {
        VectorResult {
            vector: vectors::DECOMPOSITION_MATCHES_REGISTRY,
            passed: true,
            detail: format!(
                "{compared} tool(s) declare exactly the registry's decomposition, verb for verb"
            ),
        }
    } else {
        VectorResult {
            vector: vectors::DECOMPOSITION_MATCHES_REGISTRY,
            passed: false,
            detail: mismatches.join("; "),
        }
    }
}
