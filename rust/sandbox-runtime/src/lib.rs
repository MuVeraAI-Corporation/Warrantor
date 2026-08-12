//! # warrantor-sandbox-runtime (R8)
//!
//! A Wasmtime execution boundary with signed policy, deterministic fuel, guest-memory limits,
//! an explicit Warrantor host ABI, and durable audit-before-dispatch for every host capability call.
//! WASI and undeclared imports are not linked, so ambient filesystem, network, environment, and
//! process authority do not exist.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use thiserror::Error;
use warrantor_trust_core::verification;
use wasmtime::{
    format_err, Caller, Config, Engine, Error as WasmtimeError, ExternType, Linker, Module,
    Result as WasmtimeResult, Store, StoreLimits, StoreLimitsBuilder, Trap,
};

/// Signed sandbox policy wire format.
pub const SANDBOX_POLICY_FORMAT: &str = "osaf.sandbox/1";
/// Filesystem host ABI module.
pub const FILESYSTEM_ABI_MODULE: &str = "warrantor.fs";
/// Network host ABI module.
pub const NETWORK_ABI_MODULE: &str = "warrantor.net";
/// Process host ABI module.
pub const PROCESS_ABI_MODULE: &str = "warrantor.process";

/// Capability class visible in audit evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Read one policy-indexed guest filesystem resource.
    FilesystemRead,
    /// Connect to one policy-indexed network origin.
    NetworkConnect,
    /// Spawn one policy-indexed executable without a shell.
    ProcessSpawn,
}

impl Capability {
    fn abi(self) -> (&'static str, &'static str) {
        match self {
            Self::FilesystemRead => (FILESYSTEM_ABI_MODULE, "read"),
            Self::NetworkConnect => (NETWORK_ABI_MODULE, "connect"),
            Self::ProcessSpawn => (PROCESS_ABI_MODULE, "spawn"),
        }
    }
}

/// Signed limits and exact capability allowlists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Exact policy format.
    pub format: String,
    /// Stable policy identifier.
    pub id: String,
    /// Authenticated agent SPIFFE ID.
    pub subject: String,
    /// Policy expiry in epoch seconds.
    pub expires_at: u64,
    /// Maximum accepted binary module size.
    pub max_module_bytes: u64,
    /// Fuel assigned to one execution.
    pub max_fuel: u64,
    /// Hard wall-clock ceiling for one execution, in milliseconds.
    ///
    /// **Fuel is not a time bound and cannot be made into one.** Fuel counts instructions;
    /// the wall-clock cost of an instruction is not constant. A guest doing bulk memory
    /// work consumes fuel slowly and time quickly, so a zero-capability module under the
    /// default 1,000,000-fuel policy was measured blocking `execute()` for 25 minutes on a
    /// release build (41 on debug) before "sandbox fuel exhausted" was finally returned.
    ///
    /// A caller who set a fuel budget believing it bounded execution had no such bound. This
    /// is enforced separately via Wasmtime epoch interruption.
    ///
    /// `#[serde(default = ...)]` so policies signed before this field existed still
    /// deserialize -- but they deserialize with a real deadline, not an absent one, because
    /// an old policy is exactly the case that has no protection today.
    #[serde(default = "default_max_wall_clock_ms")]
    pub max_wall_clock_ms: u64,
    /// Maximum bytes of guest linear memory.
    pub max_memory_bytes: u64,
    /// Maximum elements across each guest table.
    pub max_table_elements: u32,
    /// Exact normalized absolute resources addressable by filesystem indices.
    pub readable_files: Vec<String>,
    /// Exact HTTP(S) origins addressable by network indices.
    pub network_origins: Vec<String>,
    /// Exact executable names addressable by process indices. Empty by default.
    pub allowed_commands: Vec<String>,
}

/// Default wall-clock ceiling for one guest execution (5 seconds).
///
/// Chosen to be generous for legitimate work while bounding the pathological case by three
/// orders of magnitude: the measured worst case under the default fuel budget alone was 25
/// minutes.
#[must_use]
pub const fn default_max_wall_clock_ms() -> u64 {
    5_000
}

/// How often the epoch ticker advances the engine epoch.
///
/// Deadline resolution is one tick, so this bounds overshoot. 10ms costs one cheap atomic
/// increment per tick on a single shared thread.
const EPOCH_TICK: std::time::Duration = std::time::Duration::from_millis(10);

impl SandboxPolicy {
    /// Construct a zero-host-authority policy with bounded compute and memory.
    #[must_use]
    pub fn locked_down(id: impl Into<String>, subject: impl Into<String>, expires_at: u64) -> Self {
        Self {
            format: SANDBOX_POLICY_FORMAT.into(),
            id: id.into(),
            subject: subject.into(),
            expires_at,
            max_module_bytes: 4 * 1024 * 1024,
            max_fuel: 1_000_000,
            max_wall_clock_ms: default_max_wall_clock_ms(),
            max_memory_bytes: 64 * 1024 * 1024,
            max_table_elements: 1_024,
            readable_files: vec![],
            network_origins: vec![],
            allowed_commands: vec![],
        }
    }

    fn validate(&self) -> Result<(), SandboxError> {
        if self.format != SANDBOX_POLICY_FORMAT {
            return Err(SandboxError::InvalidPolicy(format!(
                "format must be {SANDBOX_POLICY_FORMAT}"
            )));
        }
        if self.id.is_empty() || !self.subject.starts_with("spiffe://") {
            return Err(SandboxError::InvalidPolicy(
                "policy id and SPIFFE subject are required".into(),
            ));
        }
        if self.max_module_bytes == 0
            || self.max_fuel == 0
            || self.max_memory_bytes < 65_536
            || self.max_table_elements == 0
        {
            return Err(SandboxError::InvalidPolicy(
                "module, fuel, memory, and table limits must be non-zero and memory at least one page"
                    .into(),
            ));
        }
        validate_unique("readable_files", &self.readable_files)?;
        validate_unique("network_origins", &self.network_origins)?;
        validate_unique("allowed_commands", &self.allowed_commands)?;
        if self
            .readable_files
            .iter()
            .any(|path| normalize_guest_path(path).as_deref() != Some(path.as_str()))
        {
            return Err(SandboxError::InvalidPolicy(
                "readable_files must contain normalized absolute paths".into(),
            ));
        }
        if self
            .network_origins
            .iter()
            .any(|origin| !valid_origin(origin))
        {
            return Err(SandboxError::InvalidPolicy(
                "network_origins must contain normalized HTTP(S) origins".into(),
            ));
        }
        Ok(())
    }

    /// Deterministic digest correlated into every audit event.
    ///
    /// # Errors
    /// Returns a policy error when validation or serialization fails.
    pub fn digest(&self) -> Result<String, SandboxError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| SandboxError::InvalidPolicy(error.to_string()))?;
        Ok(sha256_digest(&bytes))
    }
}

fn validate_unique(field: &str, values: &[String]) -> Result<(), SandboxError> {
    let mut unique = BTreeSet::new();
    if values.iter().any(|value| {
        value.is_empty() || value.contains(['\0', '\r', '\n']) || !unique.insert(value.as_str())
    }) {
        return Err(SandboxError::InvalidPolicy(format!(
            "{field} contains an empty, duplicate, or unsafe value"
        )));
    }
    Ok(())
}

fn normalize_guest_path(path: &str) -> Option<String> {
    if !path.starts_with('/') || path.contains(['\0', '\\']) {
        return None;
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            value => components.push(value),
        }
    }
    Some(format!("/{}", components.join("/")))
}

fn valid_origin(origin: &str) -> bool {
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    matches!(scheme, "http" | "https")
        && !authority.is_empty()
        && !authority.contains(['/', '?', '#', '@'])
        && !authority.chars().any(char::is_whitespace)
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Policy plus raw Ed25519 signature over T1 canonical CBOR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSandboxPolicy {
    /// Signed policy body.
    pub policy: SandboxPolicy,
    /// Raw 64-byte signature.
    pub signature: Vec<u8>,
}

/// Signature-verification boundary.
pub trait PolicyVerifier: Send + Sync {
    /// Verify this exact policy body.
    fn verify(&self, policy: &SandboxPolicy, signature: &[u8]) -> Result<(), String>;
}

/// T1 canonical-CBOR Ed25519 verifier.
pub struct TrustCorePolicyVerifier {
    verifying_key: VerifyingKey,
}

impl TrustCorePolicyVerifier {
    /// Construct from a trusted issuer key.
    #[must_use]
    pub const fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }
}

impl PolicyVerifier for TrustCorePolicyVerifier {
    fn verify(&self, policy: &SandboxPolicy, signature: &[u8]) -> Result<(), String> {
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| "sandbox policy signature must be 64 bytes".to_string())?;
        verification::verify(
            policy,
            &Signature::from_bytes(&signature_bytes),
            &self.verifying_key,
        )
        .map_err(|error| error.to_string())
    }
}

/// Execution request. Modules must be WebAssembly binaries, never host paths.
#[derive(Debug, Clone)]
pub struct ExecutionRequest {
    /// Authenticated SPIFFE identity.
    pub subject: String,
    /// Binary WebAssembly module bytes.
    pub module: Vec<u8>,
    /// Exported `() -> i32` function to invoke.
    pub entrypoint: String,
}

/// Audit event classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// Execution was admitted before compilation.
    ExecutionIntent,
    /// Module import was rejected during admission.
    ImportDenied,
    /// A host capability call was durably recorded before dispatch.
    CapabilityIntent,
    /// Execution completed or trapped.
    ExecutionFinal,
}

/// Redacted immutable runtime evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event classification.
    pub kind: AuditKind,
    /// Signed policy digest.
    pub policy_digest: String,
    /// Module content digest.
    pub module_digest: String,
    /// Authenticated subject.
    pub subject: String,
    /// Capability, for import and host-call events.
    pub capability: Option<Capability>,
    /// Policy resource value, or rejected import name.
    pub resource: Option<String>,
    /// Stable outcome (`pending`, `allowed`, `denied`, `succeeded`, `failed`).
    pub outcome: String,
    /// Stable failure class without guest secrets.
    pub failure_class: Option<String>,
}

/// Durable audit boundary.
pub trait AuditSink: Send + Sync {
    /// Append an event and return its immutable sequence number.
    fn append(&self, event: &AuditEvent) -> Result<u64, String>;
}

/// Host capability backend. The runtime never invokes this before durable intent audit.
pub trait HostCapabilityBackend: Send + Sync {
    /// Read a policy-selected filesystem resource.
    fn filesystem_read(&self, resource: &str) -> Result<i32, String>;
    /// Connect to a policy-selected HTTP(S) origin.
    fn network_connect(&self, origin: &str) -> Result<i32, String>;
    /// Spawn a policy-selected command without a shell.
    fn process_spawn(&self, command: &str) -> Result<i32, String>;
}

/// Backend that denies all host authority.
pub struct DenyHostBackend;

impl HostCapabilityBackend for DenyHostBackend {
    fn filesystem_read(&self, _resource: &str) -> Result<i32, String> {
        Err("filesystem backend disabled".into())
    }

    fn network_connect(&self, _origin: &str) -> Result<i32, String> {
        Err("network backend disabled".into())
    }

    fn process_spawn(&self, _command: &str) -> Result<i32, String> {
        Err("process backend disabled".into())
    }
}

struct StoreState {
    limits: StoreLimits,
    policy: SandboxPolicy,
    policy_digest: String,
    module_digest: String,
    audit_sink: Arc<dyn AuditSink>,
    host_backend: Arc<dyn HostCapabilityBackend>,
}

/// Successful bounded execution result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    /// Entrypoint return value.
    pub value: i32,
    /// Fuel consumed by compilation-independent guest execution.
    pub fuel_consumed: u64,
    /// Module content digest.
    pub module_digest: String,
    /// Immutable sequence of the execution intent event.
    pub intent_sequence: u64,
    /// Immutable sequence of the final event.
    pub final_sequence: u64,
}

/// Capability-scoped Wasmtime runtime.
pub struct SandboxRuntime {
    engine: Engine,
    policy_verifier: Arc<dyn PolicyVerifier>,
    audit_sink: Arc<dyn AuditSink>,
    host_backend: Arc<dyn HostCapabilityBackend>,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl SandboxRuntime {
    /// Construct the runtime with all enforcement dependencies.
    ///
    /// # Errors
    /// Returns an engine configuration error if Wasmtime cannot initialize.
    pub fn new(
        policy_verifier: Arc<dyn PolicyVerifier>,
        audit_sink: Arc<dyn AuditSink>,
        host_backend: Arc<dyn HostCapabilityBackend>,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, SandboxError> {
        let mut config = Config::new();
        config
            .consume_fuel(true)
            // Fuel bounds instructions, not time. Epoch interruption is what makes a
            // wall-clock deadline enforceable; without it a slow-but-frugal guest runs for
            // as long as it likes inside its fuel budget.
            .epoch_interruption(true)
            .max_wasm_stack(512 * 1024)
            .wasm_multi_memory(false)
            .wasm_memory64(false)
            .cranelift_nan_canonicalization(true);
        let engine = Engine::new(&config)
            .map_err(|error| SandboxError::RuntimeUnavailable(error.to_string()))?;

        // One detached ticker per engine advances the epoch so deadlines can fire.
        //
        // It holds a Weak reference: when the engine is dropped the upgrade fails and the
        // thread exits, so a long-lived process that creates runtimes does not accumulate
        // threads. A strong reference here would keep every engine alive forever.
        {
            let weak = engine.weak();
            std::thread::Builder::new()
                .name("warrantor-sandbox-epoch".into())
                .spawn(move || {
                    while let Some(engine) = weak.upgrade() {
                        std::thread::sleep(EPOCH_TICK);
                        engine.increment_epoch();
                    }
                })
                .map_err(|error| {
                    SandboxError::RuntimeUnavailable(format!("epoch ticker: {error}"))
                })?;
        }
        Ok(Self {
            engine,
            policy_verifier,
            audit_sink,
            host_backend,
            now,
        })
    }

    /// Verify, admit, instantiate, and invoke one untrusted WebAssembly module.
    ///
    /// # Errors
    /// Fails closed on invalid policy/signature/subject, audit outage, rejected imports,
    /// compilation/instantiation failure, host denial, resource exhaustion, or guest trap.
    pub fn execute(
        &self,
        signed_policy: &SignedSandboxPolicy,
        request: &ExecutionRequest,
    ) -> Result<ExecutionResult, SandboxError> {
        let policy = &signed_policy.policy;
        policy.validate()?;
        self.policy_verifier
            .verify(policy, &signed_policy.signature)
            .map_err(SandboxError::PolicySignatureInvalid)?;
        let now = (self.now)();
        if now >= policy.expires_at {
            return Err(SandboxError::PolicyExpired {
                expires_at: policy.expires_at,
                now,
            });
        }
        if request.subject != policy.subject {
            return Err(SandboxError::SubjectMismatch);
        }
        validate_request(policy, request)?;
        let policy_digest = policy.digest()?;
        let module_digest = sha256_digest(&request.module);
        let intent_sequence = self.append(AuditEvent {
            kind: AuditKind::ExecutionIntent,
            policy_digest: policy_digest.clone(),
            module_digest: module_digest.clone(),
            subject: request.subject.clone(),
            capability: None,
            resource: None,
            outcome: "pending".into(),
            failure_class: None,
        })?;

        let module = match Module::new(&self.engine, &request.module) {
            Ok(module) => module,
            Err(error) => {
                self.append_final_failure(
                    &policy_digest,
                    &module_digest,
                    &request.subject,
                    "module_rejected",
                )?;
                return Err(SandboxError::ModuleRejected(error.to_string()));
            }
        };
        if let Err(error) = self.validate_imports(
            policy,
            &module,
            &policy_digest,
            &module_digest,
            &request.subject,
        ) {
            self.append_final_failure(
                &policy_digest,
                &module_digest,
                &request.subject,
                "import_denied",
            )?;
            return Err(error);
        }

        let limits = StoreLimitsBuilder::new()
            .memory_size(
                usize::try_from(policy.max_memory_bytes)
                    .map_err(|_| SandboxError::InvalidPolicy("memory limit too large".into()))?,
            )
            .table_elements(policy.max_table_elements as usize)
            .instances(1)
            .memories(1)
            .tables(1)
            .build();
        let mut store = Store::new(
            &self.engine,
            StoreState {
                limits,
                policy: policy.clone(),
                policy_digest: policy_digest.clone(),
                module_digest: module_digest.clone(),
                audit_sink: Arc::clone(&self.audit_sink),
                host_backend: Arc::clone(&self.host_backend),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(policy.max_fuel)
            .map_err(|error| SandboxError::RuntimeUnavailable(error.to_string()))?;
        // Wall-clock deadline, in ticks. Rounded UP so a sub-tick budget still yields at
        // least one tick rather than a deadline of zero, which would trap immediately.
        let ticks = policy
            .max_wall_clock_ms
            .div_ceil(EPOCH_TICK.as_millis().max(1) as u64)
            .max(1);
        store.set_epoch_deadline(ticks);
        let mut linker = Linker::new(&self.engine);
        define_host_abi(&mut linker)?;
        let execution = (|| -> WasmtimeResult<i32> {
            let instance = linker.instantiate(&mut store, &module)?;
            let entrypoint = instance.get_typed_func::<(), i32>(&mut store, &request.entrypoint)?;
            entrypoint.call(&mut store, ())
        })();
        let remaining_fuel = store.get_fuel().unwrap_or(0);
        let fuel_consumed = policy.max_fuel.saturating_sub(remaining_fuel);
        let (outcome, failure_class) = match &execution {
            Ok(_) => ("succeeded", None),
            Err(error) if error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) => {
                ("failed", Some("fuel_exhausted".to_string()))
            }
            // Distinct from fuel_exhausted on purpose. "Ran too long" and "executed too many
            // instructions" are different guest behaviours and want different operator
            // responses -- one raises the time budget, the other the fuel budget.
            Err(error) if error.downcast_ref::<Trap>() == Some(&Trap::Interrupt) => {
                ("failed", Some("deadline_exceeded".to_string()))
            }
            Err(error) => (
                "failed",
                Some(classify_execution_failure(error).to_string()),
            ),
        };
        let final_sequence = self.append(AuditEvent {
            kind: AuditKind::ExecutionFinal,
            policy_digest,
            module_digest: module_digest.clone(),
            subject: request.subject.clone(),
            capability: None,
            resource: None,
            outcome: outcome.into(),
            failure_class,
        })?;
        let value = execution.map_err(|error| {
            if error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
                SandboxError::FuelExhausted
            } else {
                SandboxError::ExecutionFailed(error.to_string())
            }
        })?;
        Ok(ExecutionResult {
            value,
            fuel_consumed,
            module_digest,
            intent_sequence,
            final_sequence,
        })
    }

    fn validate_imports(
        &self,
        policy: &SandboxPolicy,
        module: &Module,
        policy_digest: &str,
        module_digest: &str,
        subject: &str,
    ) -> Result<(), SandboxError> {
        for import in module.imports() {
            let capability = capability_for_import(import.module(), import.name());
            let allowed = capability.is_some_and(|capability| {
                matches!(import.ty(), ExternType::Func(_))
                    && capability_resources(policy, capability)
                        .is_some_and(|items| !items.is_empty())
            });
            if !allowed {
                self.append(AuditEvent {
                    kind: AuditKind::ImportDenied,
                    policy_digest: policy_digest.into(),
                    module_digest: module_digest.into(),
                    subject: subject.into(),
                    capability,
                    resource: Some(format!("{}::{}", import.module(), import.name())),
                    outcome: "denied".into(),
                    failure_class: Some("import_not_authorized".into()),
                })?;
                return Err(SandboxError::ImportDenied {
                    module: import.module().into(),
                    name: import.name().into(),
                });
            }
        }
        Ok(())
    }

    fn append(&self, event: AuditEvent) -> Result<u64, SandboxError> {
        self.audit_sink
            .append(&event)
            .map_err(SandboxError::AuditUnavailable)
    }

    fn append_final_failure(
        &self,
        policy_digest: &str,
        module_digest: &str,
        subject: &str,
        failure_class: &str,
    ) -> Result<u64, SandboxError> {
        self.append(AuditEvent {
            kind: AuditKind::ExecutionFinal,
            policy_digest: policy_digest.into(),
            module_digest: module_digest.into(),
            subject: subject.into(),
            capability: None,
            resource: None,
            outcome: "failed".into(),
            failure_class: Some(failure_class.into()),
        })
    }
}

fn validate_request(
    policy: &SandboxPolicy,
    request: &ExecutionRequest,
) -> Result<(), SandboxError> {
    if request.entrypoint.is_empty()
        || request.entrypoint.len() > 128
        || request.entrypoint.contains(['\0', '\r', '\n'])
    {
        return Err(SandboxError::InvalidRequest(
            "entrypoint is empty, too long, or unsafe".into(),
        ));
    }
    let module_length = u64::try_from(request.module.len()).unwrap_or(u64::MAX);
    if module_length > policy.max_module_bytes {
        return Err(SandboxError::ModuleTooLarge {
            actual: module_length,
            maximum: policy.max_module_bytes,
        });
    }
    if !request.module.starts_with(b"\0asm") {
        return Err(SandboxError::InvalidRequest(
            "module must be a binary WebAssembly module".into(),
        ));
    }
    Ok(())
}

fn capability_for_import(module: &str, name: &str) -> Option<Capability> {
    [
        Capability::FilesystemRead,
        Capability::NetworkConnect,
        Capability::ProcessSpawn,
    ]
    .into_iter()
    .find(|capability| capability.abi() == (module, name))
}

fn capability_resources(policy: &SandboxPolicy, capability: Capability) -> Option<&[String]> {
    Some(match capability {
        Capability::FilesystemRead => &policy.readable_files,
        Capability::NetworkConnect => &policy.network_origins,
        Capability::ProcessSpawn => &policy.allowed_commands,
    })
}

fn define_host_abi(linker: &mut Linker<StoreState>) -> Result<(), SandboxError> {
    for capability in [
        Capability::FilesystemRead,
        Capability::NetworkConnect,
        Capability::ProcessSpawn,
    ] {
        let (module, name) = capability.abi();
        linker
            .func_wrap(
                module,
                name,
                move |caller: Caller<'_, StoreState>, index: i32| {
                    dispatch_capability(caller, capability, index)
                },
            )
            .map_err(|error| SandboxError::RuntimeUnavailable(error.to_string()))?;
    }
    Ok(())
}

fn dispatch_capability(
    caller: Caller<'_, StoreState>,
    capability: Capability,
    index: i32,
) -> WasmtimeResult<i32> {
    let state = caller.data();
    let resources = capability_resources(&state.policy, capability)
        .ok_or_else(|| format_err!("{CAPABILITY_UNMAPPED_MARKER}"))?;
    let resource = usize::try_from(index)
        .ok()
        .and_then(|index| resources.get(index))
        .cloned();
    let (resource_for_event, outcome, failure_class) = resource.as_ref().map_or_else(
        || {
            (
                format!("index:{index}"),
                "denied".to_string(),
                Some("resource_index_denied".to_string()),
            )
        },
        |resource| (resource.clone(), "allowed".to_string(), None),
    );
    state
        .audit_sink
        .append(&AuditEvent {
            kind: AuditKind::CapabilityIntent,
            policy_digest: state.policy_digest.clone(),
            module_digest: state.module_digest.clone(),
            subject: state.policy.subject.clone(),
            capability: Some(capability),
            resource: Some(resource_for_event),
            outcome,
            failure_class,
        })
        .map_err(|message| format_err!("capability audit unavailable: {message}"))?;
    let resource = resource.ok_or_else(|| format_err!("{CAPABILITY_DENIED_MARKER}"))?;
    match capability {
        Capability::FilesystemRead => state.host_backend.filesystem_read(&resource),
        Capability::NetworkConnect => state.host_backend.network_connect(&resource),
        Capability::ProcessSpawn => state.host_backend.process_spawn(&resource),
    }
    .map_err(|message| format_err!("{BACKEND_DENIED_MARKER}: {message}"))
}

/// Marker in the error raised when a capability's resource index is not in the granted list.
/// Shared with [`classify_execution_failure`] so the producer and the classifier cannot drift.
const CAPABILITY_DENIED_MARKER: &str = "capability resource index denied";
/// Marker for a capability whose policy carries no resource mapping at all.
const CAPABILITY_UNMAPPED_MARKER: &str = "capability has no resource mapping";
/// Marker for a denial that came from the host backend rather than from policy.
const BACKEND_DENIED_MARKER: &str = "host capability denied";

/// Classify why an execution failed, for the `failure_class` on the final audit event.
///
/// Every non-fuel, non-deadline failure was previously recorded as `guest_trap`, which told an
/// operator the guest had a bug. That was wrong for most of them, and wrong in the direction that
/// matters: a module rejected because it declared more memory than policy allows, or asked for a
/// capability it was not granted, is the sandbox *working*. Filing those as guest bugs means the
/// audit log cannot answer "did policy stop anything today", which is the question this component
/// exists to answer.
///
/// The wasmtime cases are matched on message text because wasmtime raises them as opaque
/// `anyhow` errors with no typed variant to match on; the capability cases use the shared markers
/// above, which we raise ourselves. Anything genuinely unrecognised stays `guest_trap`.
fn classify_execution_failure(error: &WasmtimeError) -> &'static str {
    for cause in error.chain() {
        let message: String = cause.to_string();
        // Our own host-function denials. Checked first: they are exact and we own the wording.
        if message.contains(CAPABILITY_DENIED_MARKER)
            || message.contains(CAPABILITY_UNMAPPED_MARKER)
        {
            return "capability_denied";
        }
        if message.contains(BACKEND_DENIED_MARKER) {
            return "backend_denied";
        }
        // Resource limits the store's limiter refused -- policy enforcement, not a guest fault.
        if message.contains("exceeds memory limits") || message.contains("exceeds table limits") {
            return "resource_limit_denied";
        }
        // The guest asked for a host function whose signature does not match the one we expose.
        if message.contains("incompatible import type") {
            return "import_type_mismatch";
        }
        // A host function the policy never granted, so the linker has nothing to satisfy it with.
        if message.contains("unknown import") || message.contains("unknown func") {
            return "import_denied";
        }
    }
    "guest_trap"
}

/// Fail-closed sandbox runtime errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SandboxError {
    /// Signed policy structure is unsafe.
    #[error("invalid sandbox policy: {0}")]
    InvalidPolicy(String),
    /// T1 rejected the policy signature.
    #[error("sandbox policy signature invalid: {0}")]
    PolicySignatureInvalid(String),
    /// Policy expired.
    #[error("sandbox policy expired at {expires_at}; now={now}")]
    PolicyExpired {
        /// Expiry.
        expires_at: u64,
        /// Trusted current time.
        now: u64,
    },
    /// Request subject differs from the policy subject.
    #[error("sandbox request subject does not match policy")]
    SubjectMismatch,
    /// Request structure is unsafe.
    #[error("invalid sandbox request: {0}")]
    InvalidRequest(String),
    /// Module exceeds signed byte limit.
    #[error("module exceeds byte limit: actual={actual}, maximum={maximum}")]
    ModuleTooLarge {
        /// Actual module size.
        actual: u64,
        /// Signed maximum.
        maximum: u64,
    },
    /// Wasmtime engine/linker is unavailable.
    #[error("sandbox runtime unavailable: {0}")]
    RuntimeUnavailable(String),
    /// Durable audit failed.
    #[error("sandbox audit unavailable: {0}")]
    AuditUnavailable(String),
    /// Module compilation or instantiation was rejected.
    #[error("sandbox module rejected: {0}")]
    ModuleRejected(String),
    /// Import is absent from the signed capability policy.
    #[error("sandbox import denied: {module}::{name}")]
    ImportDenied {
        /// Import module.
        module: String,
        /// Import name.
        name: String,
    },
    /// Guest consumed all assigned fuel.
    #[error("sandbox fuel exhausted")]
    FuelExhausted,
    /// Guest trapped, host capability failed, or entrypoint contract was invalid.
    #[error("sandbox execution failed: {0}")]
    ExecutionFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use warrantor_trust_core::signing::SigningKeyWrapper;

    struct AcceptVerifier;

    impl PolicyVerifier for AcceptVerifier {
        fn verify(&self, _policy: &SandboxPolicy, _signature: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingAudit {
        events: Mutex<Vec<AuditEvent>>,
        fail: Mutex<bool>,
    }

    impl AuditSink for RecordingAudit {
        fn append(&self, event: &AuditEvent) -> Result<u64, String> {
            if *self.fail.lock().expect("fail lock") {
                return Err("ledger unavailable".into());
            }
            let mut events = self.events.lock().expect("events lock");
            events.push(event.clone());
            Ok(events.len() as u64)
        }
    }

    #[derive(Default)]
    struct RecordingBackend {
        calls: Mutex<Vec<(Capability, String)>>,
    }

    impl HostCapabilityBackend for RecordingBackend {
        fn filesystem_read(&self, resource: &str) -> Result<i32, String> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((Capability::FilesystemRead, resource.into()));
            Ok(17)
        }

        fn network_connect(&self, origin: &str) -> Result<i32, String> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((Capability::NetworkConnect, origin.into()));
            Ok(18)
        }

        fn process_spawn(&self, command: &str) -> Result<i32, String> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((Capability::ProcessSpawn, command.into()));
            Ok(19)
        }
    }

    fn policy() -> SandboxPolicy {
        let mut policy = SandboxPolicy::locked_down(
            "sandbox-policy-1",
            "spiffe://example.org/agent/test",
            2_000,
        );
        policy.max_fuel = 100_000;
        policy.max_memory_bytes = 2 * 65_536;
        policy.readable_files = vec!["/workspace/input.txt".into()];
        policy.network_origins = vec!["https://example.org".into()];
        policy
    }

    fn signed(policy: SandboxPolicy) -> SignedSandboxPolicy {
        SignedSandboxPolicy {
            policy,
            signature: vec![0; 64],
        }
    }

    fn request(wat_source: &str) -> ExecutionRequest {
        ExecutionRequest {
            subject: "spiffe://example.org/agent/test".into(),
            module: wat::parse_str(wat_source).expect("valid WAT"),
            entrypoint: "run".into(),
        }
    }

    fn runtime(audit: Arc<RecordingAudit>, backend: Arc<RecordingBackend>) -> SandboxRuntime {
        SandboxRuntime::new(Arc::new(AcceptVerifier), audit, backend, Arc::new(|| 1_000))
            .expect("runtime")
    }

    #[test]
    fn executes_pure_wasm_with_fuel_and_memory_limits() {
        let result = runtime(
            Arc::new(RecordingAudit::default()),
            Arc::new(RecordingBackend::default()),
        )
        .execute(
            &signed(policy()),
            &request("(module (func (export \"run\") (result i32) i32.const 42))"),
        )
        .expect("bounded execution");
        assert_eq!(result.value, 42);
        assert!(result.fuel_consumed > 0);
        assert_eq!(result.intent_sequence, 1);
        assert_eq!(result.final_sequence, 2);
    }

    #[test]
    fn fuel_exhaustion_traps_infinite_guest() {
        let result = runtime(
            Arc::new(RecordingAudit::default()),
            Arc::new(RecordingBackend::default()),
        )
        .execute(
            &signed(policy()),
            &request(
                "(module (func (export \"run\") (result i32) (loop $again br $again) i32.const 0))",
            ),
        );
        assert_eq!(result, Err(SandboxError::FuelExhausted));
    }

    #[test]
    fn guest_memory_over_policy_limit_cannot_instantiate() {
        let mut constrained = policy();
        constrained.max_memory_bytes = 65_536;
        let result = runtime(
            Arc::new(RecordingAudit::default()),
            Arc::new(RecordingBackend::default()),
        )
        .execute(
            &signed(constrained),
            &request("(module (memory 2) (func (export \"run\") (result i32) i32.const 0))"),
        );
        assert!(matches!(result, Err(SandboxError::ExecutionFailed(_))));
    }

    #[test]
    fn authorized_host_call_is_audited_before_exact_resource_dispatch() {
        let audit = Arc::new(RecordingAudit::default());
        let backend = Arc::new(RecordingBackend::default());
        let result = runtime(Arc::clone(&audit), Arc::clone(&backend))
            .execute(
                &signed(policy()),
                &request(
                    "(module (import \"warrantor.fs\" \"read\" (func $read (param i32) (result i32))) (func (export \"run\") (result i32) i32.const 0 call $read))",
                ),
            )
            .expect("capability call");
        assert_eq!(result.value, 17);
        assert_eq!(
            backend.calls.lock().expect("calls lock").as_slice(),
            &[(Capability::FilesystemRead, "/workspace/input.txt".into())]
        );
        let events = audit.events.lock().expect("events lock");
        assert_eq!(events[1].kind, AuditKind::CapabilityIntent);
        assert_eq!(events[1].outcome, "allowed");
        assert_eq!(events[2].kind, AuditKind::ExecutionFinal);
    }

    #[test]
    fn denied_import_and_out_of_range_resource_are_audited() {
        let audit = Arc::new(RecordingAudit::default());
        let backend = Arc::new(RecordingBackend::default());
        let process_import = request(
            "(module (import \"warrantor.process\" \"spawn\" (func $spawn (param i32) (result i32))) (func (export \"run\") (result i32) i32.const 0 call $spawn))",
        );
        let denied = runtime(Arc::clone(&audit), Arc::clone(&backend))
            .execute(&signed(policy()), &process_import);
        assert!(matches!(denied, Err(SandboxError::ImportDenied { .. })));
        assert_eq!(
            audit.events.lock().expect("events lock")[1].kind,
            AuditKind::ImportDenied
        );
        assert_eq!(
            audit.events.lock().expect("events lock")[2].kind,
            AuditKind::ExecutionFinal
        );
        assert!(backend.calls.lock().expect("calls lock").is_empty());

        audit.events.lock().expect("events lock").clear();
        let out_of_range = request(
            "(module (import \"warrantor.fs\" \"read\" (func $read (param i32) (result i32))) (func (export \"run\") (result i32) i32.const 99 call $read))",
        );
        let denied = runtime(Arc::clone(&audit), Arc::clone(&backend))
            .execute(&signed(policy()), &out_of_range);
        assert!(matches!(denied, Err(SandboxError::ExecutionFailed(_))));
        let events = audit.events.lock().expect("events lock");
        assert_eq!(events[1].kind, AuditKind::CapabilityIntent);
        assert_eq!(events[1].outcome, "denied");
        assert!(backend.calls.lock().expect("calls lock").is_empty());
    }

    #[test]
    fn audit_outage_prevents_compilation_and_host_dispatch() {
        let audit = Arc::new(RecordingAudit::default());
        *audit.fail.lock().expect("fail lock") = true;
        let backend = Arc::new(RecordingBackend::default());
        let result = runtime(audit, Arc::clone(&backend)).execute(
            &signed(policy()),
            &request("(module (func (export \"run\") (result i32) i32.const 0))"),
        );
        assert!(matches!(result, Err(SandboxError::AuditUnavailable(_))));
        assert!(backend.calls.lock().expect("calls lock").is_empty());
    }

    #[test]
    fn trust_core_signature_binds_every_policy_limit() {
        let signer = SigningKeyWrapper::generate();
        let policy = policy();
        let signature = signer.sign(&policy).expect("sign").to_bytes().to_vec();
        let verifier = TrustCorePolicyVerifier::new(signer.verifying_key());
        verifier
            .verify(&policy, &signature)
            .expect("valid signature");
        let mut tampered = policy;
        tampered.max_fuel += 1;
        assert!(verifier.verify(&tampered, &signature).is_err());
    }

    #[test]
    fn request_validation_rejects_text_modules_size_and_subject_mismatch() {
        let audit = Arc::new(RecordingAudit::default());
        let backend = Arc::new(RecordingBackend::default());
        let runtime = runtime(audit, backend);
        let mut text = request("(module (func (export \"run\") (result i32) i32.const 0))");
        text.module = b"(module)".to_vec();
        assert!(matches!(
            runtime.execute(&signed(policy()), &text),
            Err(SandboxError::InvalidRequest(_))
        ));
        let mut too_large_policy = policy();
        too_large_policy.max_module_bytes = 4;
        assert!(matches!(
            runtime.execute(
                &signed(too_large_policy),
                &request("(module (func (export \"run\") (result i32) i32.const 0))")
            ),
            Err(SandboxError::ModuleTooLarge { .. })
        ));
        let mut wrong_subject =
            request("(module (func (export \"run\") (result i32) i32.const 0))");
        wrong_subject.subject = "spiffe://example.org/agent/other".into();
        assert_eq!(
            runtime.execute(&signed(policy()), &wrong_subject),
            Err(SandboxError::SubjectMismatch)
        );
    }

    #[test]
    fn malformed_binary_is_finalized_after_compiler_rejection() {
        let audit = Arc::new(RecordingAudit::default());
        let backend = Arc::new(RecordingBackend::default());
        let malformed = ExecutionRequest {
            subject: "spiffe://example.org/agent/test".into(),
            module: b"\0asm\x01\x00\x00\x00\xff".to_vec(),
            entrypoint: "run".into(),
        };
        let result = runtime(Arc::clone(&audit), backend).execute(&signed(policy()), &malformed);
        assert!(matches!(result, Err(SandboxError::ModuleRejected(_))));
        let events = audit.events.lock().expect("events lock");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, AuditKind::ExecutionIntent);
        assert_eq!(events[1].kind, AuditKind::ExecutionFinal);
        assert_eq!(events[1].failure_class.as_deref(), Some("module_rejected"));
    }

    /// Fuel is not a time bound.
    ///
    /// A guest that loops consumes fuel slowly relative to wall-clock, so under the default
    /// 1,000,000-fuel policy `execute()` was measured blocking for 25 MINUTES on a release
    /// build before reporting "sandbox fuel exhausted". A caller who set a fuel budget
    /// believing it bounded execution had no such bound.
    #[test]
    fn a_spinning_guest_is_stopped_by_the_deadline_not_by_fuel() {
        let mut deadline_policy = policy();
        deadline_policy.max_wall_clock_ms = 200;
        // Fuel so high that reaching it would take far longer than the deadline, proving
        // it is the deadline and not fuel that stops the guest.
        deadline_policy.max_fuel = u64::MAX / 2;

        let started = std::time::Instant::now();
        let result = runtime(
            Arc::new(RecordingAudit::default()),
            Arc::new(RecordingBackend::default()),
        )
        .execute(
            &signed(deadline_policy),
            &request(
                "(module (func (export \"run\") (result i32) (loop $again br $again) i32.const 0))",
            ),
        );
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "execute() must return on the deadline; took {elapsed:?}"
        );
        assert!(
            result.is_err(),
            "a spinning guest must not succeed, got {result:?}"
        );
        assert_ne!(
            result,
            Err(SandboxError::FuelExhausted),
            "must be stopped by the DEADLINE, not by fuel"
        );
    }

    /// A sub-tick budget must round up to one tick, not a zero deadline that traps before
    /// the guest runs at all.
    #[test]
    fn a_tiny_deadline_still_lets_a_trivial_guest_finish() {
        let mut tiny = policy();
        tiny.max_wall_clock_ms = 1; // below one 10ms tick
        let result = runtime(
            Arc::new(RecordingAudit::default()),
            Arc::new(RecordingBackend::default()),
        )
        .execute(
            &signed(tiny),
            &request("(module (func (export \"run\") (result i32) i32.const 7))"),
        )
        .expect("a trivial guest must complete under a sub-tick budget");
        assert_eq!(result.value, 7);
    }

    /// Pull the failure_class off the ExecutionFinal audit event.
    fn final_failure_class(audit: &RecordingAudit) -> Option<String> {
        audit
            .events
            .lock()
            .expect("events lock")
            .iter()
            .find(|event| event.kind == AuditKind::ExecutionFinal)
            .and_then(|event| event.failure_class.clone())
    }

    fn run_and_classify(wat_source: &str) -> Option<String> {
        let audit = Arc::new(RecordingAudit::default());
        let mut policy = policy();
        // One page, so a module declaring two is refused by the limiter.
        policy.max_memory_bytes = 65_536;
        policy.max_table_elements = 8;
        let _ = runtime(Arc::clone(&audit), Arc::new(RecordingBackend::default()))
            .execute(&signed(policy), &request(wat_source));
        final_failure_class(&audit)
    }

    /// A module declaring more memory than policy permits is the SANDBOX WORKING. Recording it as
    /// `guest_trap` told the operator the guest had a bug and left the audit log unable to answer
    /// "did policy stop anything today".
    #[test]
    fn exceeding_the_memory_limit_is_a_policy_denial_not_a_guest_trap() {
        let class = run_and_classify(
            "(module (memory 2) (func (export \"run\") (result i32) i32.const 1))",
        );
        assert_eq!(class.as_deref(), Some("resource_limit_denied"));
    }

    #[test]
    fn exceeding_the_table_limit_is_a_policy_denial_not_a_guest_trap() {
        let class = run_and_classify(
            "(module (table 1000 funcref) (func (export \"run\") (result i32) i32.const 1))",
        );
        assert_eq!(class.as_deref(), Some("resource_limit_denied"));
    }

    /// A genuine guest fault must still read as one, or the classification is just noise.
    #[test]
    fn a_real_guest_fault_is_still_a_guest_trap() {
        let class = run_and_classify("(module (func (export \"run\") (result i32) unreachable))");
        assert_eq!(class.as_deref(), Some("guest_trap"));
    }

    #[test]
    fn a_divide_by_zero_is_a_guest_trap() {
        let class = run_and_classify(
            "(module (func (export \"run\") (result i32) i32.const 1 i32.const 0 i32.div_s))",
        );
        assert_eq!(class.as_deref(), Some("guest_trap"));
    }

    /// The classifier's markers must stay tied to the strings the host functions actually raise.
    #[test]
    fn capability_markers_classify_to_their_own_classes() {
        let denied = format_err!("{CAPABILITY_DENIED_MARKER}");
        assert_eq!(classify_execution_failure(&denied), "capability_denied");

        let unmapped = format_err!("{CAPABILITY_UNMAPPED_MARKER}");
        assert_eq!(classify_execution_failure(&unmapped), "capability_denied");

        let backend = format_err!("{BACKEND_DENIED_MARKER}: path not permitted");
        assert_eq!(classify_execution_failure(&backend), "backend_denied");
    }

    #[test]
    fn an_unrecognised_error_falls_back_to_guest_trap() {
        let other = format_err!("something nobody anticipated");
        assert_eq!(classify_execution_failure(&other), "guest_trap");
    }
}
