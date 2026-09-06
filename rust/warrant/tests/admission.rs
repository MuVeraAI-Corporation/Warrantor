//! Admission: what is refused, what is receipted, and what a receipt proves offline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use warrantor_warrant::admission::decompositions_of;
use warrantor_warrant::admission::{
    manifest_digest, sign_manifest, verify_receipt, AdmissionDecision, AdmissionError,
    AdmissionKind, AdmittedSet, ManifestClaims, SignedManifest, ToolEntry, MANIFEST_FORMAT,
    RECEIPT_FORMAT,
};
use warrantor_warrant::effects::{DecompositionRegistry, Syscall, UnclassifiedPolicy};
use warrantor_warrant::mcp::Endpoint;
use warrantor_warrant::mcp_endpoints::agent_endpoint_for;
use warrantor_warrant::proxy::ProxyMode;
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::trust::Directory;
use warrantor_warrant::upstream::{UpstreamSet, UpstreamSpec};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

/// The epoch base every fixture time is relative to: the real process clock, taken once per
/// test process. The CLI under test verifies against the wall clock, so a fixture pinned to a
/// fixed past epoch would have every manifest it signs expire before the binary reads it.
fn now_base() -> u64 {
    use std::sync::OnceLock;
    static BASE: OnceLock<u64> = OnceLock::new();
    *BASE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-admission-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn entry(effects: &[Syscall]) -> ToolEntry {
    ToolEntry {
        effects: effects.iter().copied().collect(),
        data_classes: ["public".to_string()].into_iter().collect(),
        schema_digest: None,
    }
}

/// The selftest server's manifest: `echo` with the effects given, `now` as a pure attestation.
fn selftest_manifest(echo_effects: &[Syscall]) -> ManifestClaims {
    let mut tools = BTreeMap::new();
    tools.insert("echo".to_string(), entry(echo_effects));
    tools.insert("now".to_string(), entry(&[Syscall::Attest]));
    ManifestClaims {
        format: MANIFEST_FORMAT.to_string(),
        server: "selftest".to_string(),
        kind: AdmissionKind::Tool,
        version: "1.0.0".to_string(),
        issuer: "vendor".to_string(),
        issued_at: now_base(),
        expires_at: now_base() + 86_400,
        subject_digest: None,
        tools,
    }
}

fn pinned(root: &Path, name: &str, vendor: &SigningKey) -> Directory {
    let mut directory = Directory::load(root).expect("empty");
    directory
        .pin(name, &vendor.verifying_key(), now_base(), "test pin")
        .expect("pin");
    directory.save(root).expect("save");
    directory
}

#[test]
fn an_unsigned_manifest_is_refused_and_the_refusal_is_receipted() {
    let root = tempdir("unsigned");
    let vendor = key(7);
    let machine = key(1);
    let directory = pinned(&root, "vendor", &vendor);
    let unsigned = SignedManifest {
        claims: selftest_manifest(&[Syscall::Attest]),
        signature: String::new(),
    };
    let set = AdmittedSet::open(&root);
    let err = set
        .admit(&unsigned, &directory, &machine, now_base() + 1)
        .expect_err("unsigned is refused");
    assert_eq!(err, AdmissionError::Unsigned);
    assert!(
        set.load("selftest").expect("read").is_none(),
        "nothing was admitted"
    );
    let receipts = set.receipts().expect("ledger");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].claims.decision, AdmissionDecision::Refused);
    assert_eq!(receipts[0].claims.format, RECEIPT_FORMAT);
    verify_receipt(&receipts[0], &machine.verifying_key()).expect("the refusal verifies");
}

#[test]
fn an_unpinned_issuer_is_refused_with_the_pin_command() {
    let root = tempdir("unpinned");
    let vendor = key(7);
    let signed = sign_manifest(selftest_manifest(&[Syscall::Attest]), &vendor);
    let directory = Directory::load(&root).expect("empty");
    let err = AdmittedSet::open(&root)
        .admit(&signed, &directory, &key(1), now_base() + 1)
        .expect_err("nobody pinned vendor");
    assert_eq!(err, AdmissionError::UnpinnedIssuer("vendor".to_string()));
    assert!(
        err.to_string().contains("warrantor issuer add vendor"),
        "{err}"
    );
}

#[test]
fn a_pinned_signed_manifest_is_admitted_receipted_and_revocable() {
    let root = tempdir("admit");
    let vendor = key(7);
    let machine = key(1);
    let directory = pinned(&root, "vendor", &vendor);
    let signed = sign_manifest(selftest_manifest(&[Syscall::Attest]), &vendor);
    let set = AdmittedSet::open(&root);

    let receipt = set
        .admit(&signed, &directory, &machine, now_base() + 1)
        .expect("admitted");
    assert_eq!(receipt.claims.decision, AdmissionDecision::Admitted);
    assert_eq!(receipt.claims.manifest_digest, manifest_digest(&signed));
    assert_eq!(receipt.claims.issuer_name, "vendor");
    assert_eq!(
        receipt.claims.issuer_key,
        hex::encode(vendor.verifying_key().to_bytes())
    );
    verify_receipt(&receipt, &machine.verifying_key()).expect("verifies");
    assert_eq!(
        verify_receipt(&receipt, &key(2).verifying_key()),
        Err(AdmissionError::Signature)
    );
    assert_eq!(set.load("selftest").expect("read"), Some(signed.clone()));

    let revoked = set
        .revoke(
            "selftest",
            "operator: vendor advisory",
            &machine,
            now_base() + 2,
        )
        .expect("revoked");
    assert_eq!(revoked.claims.decision, AdmissionDecision::Revoked);
    assert_eq!(
        set.is_revoked("selftest").expect("read"),
        Some((now_base() + 2, "operator: vendor advisory".to_string()))
    );
    assert!(
        set.load("selftest").expect("read").is_none(),
        "revoked is not loaded"
    );
    assert!(
        matches!(
            set.admit(&signed, &directory, &machine, now_base() + 3),
            Err(AdmissionError::Revoked { .. })
        ),
        "re-presenting the same manifest does not lift a revocation"
    );
    // Three decisions were made (admit, revoke, refused re-admit) and each left exactly one
    // receipt; the plan's draft asserted 4 against its own implementation, which the CLI test's
    // one-refused-admit -> one-receipt invariant rules out.
    assert_eq!(set.receipts().expect("ledger").len(), 3);
}

fn stored_open(id: &str, tools: &[&str], egress: &[&str]) -> StoredWarrant {
    let bounds = WarrantBounds {
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: egress.iter().map(|h| (*h).to_string()).collect(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: now_base() + 3600,
        budget_cents_observed: None,
        delegation_depth: 1,
    };
    let warrant = Warrant::grant(
        id,
        "admission",
        "spiffe://muveraai.com/agent/a",
        bounds,
        now_base(),
        &key(2).verifying_key(),
        &key(1),
    )
    .expect("grant");
    StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    }
}

/// The binary under test as an upstream. Built directly, never parsed: a build directory may
/// contain spaces and `UpstreamSpec::parse` splits on whitespace.
fn selftest_spec() -> UpstreamSpec {
    UpstreamSpec {
        name: "selftest".to_string(),
        program: env!("CARGO_BIN_EXE_warrantor").to_string(),
        args: vec!["selftest-upstream".to_string()],
    }
}

fn now() -> u64 {
    now_base() + 10
}

fn text_arg(text: &str) -> BTreeMap<String, Value> {
    [("text".to_string(), json!(text))].into_iter().collect()
}

/// Admit `signed` and build a strict endpoint whose registry carries the manifest's declarations.
fn admitted_endpoint(
    root: &Path,
    signed: &SignedManifest,
    stored: &StoredWarrant,
) -> (AdmittedSet, warrantor_warrant::mcp_endpoints::AgentEndpoint) {
    let vendor = key(7);
    let machine = key(1);
    let directory = pinned(root, "vendor", &vendor);
    let set = AdmittedSet::open(root);
    set.admit(signed, &directory, &machine, now_base() + 1)
        .expect("admitted");
    let upstreams =
        UpstreamSet::start(&[selftest_spec()], Duration::from_secs(30)).expect("attach");
    let mut registry = DecompositionRegistry::builtin();
    registry
        .merge(decompositions_of(signed).expect("decomposes"))
        .expect("no conflict with the builtin four");
    let manifests: BTreeMap<String, SignedManifest> = [("selftest".to_string(), signed.clone())]
        .into_iter()
        .collect();
    let endpoint = agent_endpoint_for(stored, root.join("staged.jsonl"), ProxyMode::Enforce, now)
        .expect("endpoint")
        .with_upstreams(upstreams)
        .with_decompositions(registry, UnclassifiedPolicy::Refuse)
        .with_admission(set.clone(), manifests, machine);
    (set, endpoint)
}

#[test]
fn a_call_naming_a_destination_to_a_tool_whose_manifest_has_no_net_is_refused_and_receipted() {
    let root = tempdir("runtime");
    let signed = sign_manifest(selftest_manifest(&[Syscall::Attest]), &key(7));
    // The warrant ALLOWS example.com, so the egress bound is not what refuses this.
    let stored = stored_open("w-runtime", &["selftest.echo"], &["example.com"]);
    let (set, mut endpoint) = admitted_endpoint(&root, &signed, &stored);

    let result = endpoint.call("selftest.echo", &text_arg("see https://example.com/x"));
    assert!(result.is_error, "{}", result.text);
    assert!(
        result.text.contains("admission bound") && result.text.contains("net"),
        "{}",
        result.text
    );
    assert_eq!(
        endpoint.forwarding_counts(),
        Some((0, 0)),
        "nothing was forwarded"
    );
    assert_eq!(endpoint.admission_refusals(), 1);

    let receipts = set.receipts().expect("ledger");
    let last = receipts.last().expect("a refusal receipt");
    assert_eq!(last.claims.decision, AdmissionDecision::Refused);
    assert!(
        last.claims.reason.contains("example.com"),
        "{}",
        last.claims.reason
    );
    verify_receipt(last, &key(1).verifying_key()).expect("the refusal verifies");
    assert!(
        set.load("selftest").expect("read").is_some(),
        "the manifest is NOT revoked by the agent's argument"
    );

    // A call within the manifest still works, so the check is a bound and not a kill.
    let ok = endpoint.call("selftest.echo", &text_arg("plain"));
    assert!(!ok.is_error, "{}", ok.text);
    assert_eq!(ok.text, "plain");
    assert_eq!(endpoint.forwarding_counts(), Some((1, 0)));
    assert!(
        endpoint.unclassified_tools().is_empty(),
        "the manifest declared every tool"
    );
}

#[test]
fn a_tool_whose_manifest_declares_net_may_name_a_destination_the_warrant_allows() {
    let root = tempdir("net");
    let signed = sign_manifest(selftest_manifest(&[Syscall::Net]), &key(7));
    let stored = stored_open("w-net", &["selftest.echo"], &["example.com"]);
    let (_, mut endpoint) = admitted_endpoint(&root, &signed, &stored);
    let ok = endpoint.call("selftest.echo", &text_arg("see https://example.com/x"));
    assert!(!ok.is_error, "{}", ok.text);
    assert_eq!(endpoint.admission_refusals(), 0);
    // The warrant's egress bound still decides destinations the manifest permits.
    let refused = endpoint.call("selftest.echo", &text_arg("see https://other.example/x"));
    assert!(
        refused.is_error && refused.text.contains("egress_hosts"),
        "{}",
        refused.text
    );
}

/// Run the real binary against `root`, with the binary's own directory on PATH so an
/// `--upstream 'x=warrantor selftest-upstream'` value never has to carry a path with spaces.
fn warrantor(root: &Path, args: &[&str]) -> std::process::Output {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_warrantor"));
    let mut paths = vec![bin.parent().expect("a directory").to_path_buf()];
    if let Some(existing) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    let mut all: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    all.push("--root".to_string());
    all.push(root.to_string_lossy().to_string());
    std::process::Command::new(&bin)
        .args(&all)
        .env("PATH", std::env::join_paths(paths).expect("joinable"))
        .output()
        .expect("run warrantor")
}

fn shown_hex(root: &Path) -> String {
    String::from_utf8_lossy(&warrantor(root, &["issuer", "show-hex"]).stdout)
        .lines()
        .find_map(|l| {
            l.strip_prefix("issuer public key  ")
                .map(str::trim)
                .map(str::to_string)
        })
        .expect("a key line")
}

fn machine_key(root: &Path) -> SigningKey {
    let bytes = std::fs::read(root.join("keys/issuer.key")).expect("the store's issuer key");
    SigningKey::from_bytes(&bytes.as_slice().try_into().expect("32 bytes"))
}

#[test]
fn the_cli_signs_admits_exports_verifies_offline_and_refuses_an_unadmitted_server() {
    let root = tempdir("cli");
    let vendor_root = tempdir("cli-vendor");
    // The vendor signs with its own store's issuer key; this machine pins that key by name.
    let claims_path = vendor_root.join("selftest.claims.json");
    std::fs::write(
        &claims_path,
        serde_json::to_vec_pretty(&selftest_manifest(&[Syscall::Attest])).expect("json"),
    )
    .expect("write claims");
    let manifest_path = vendor_root.join("selftest.manifest.json");
    let signed = warrantor(
        &vendor_root,
        &[
            "tools",
            "sign",
            claims_path.to_str().expect("utf-8"),
            "--out",
            manifest_path.to_str().expect("utf-8"),
        ],
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let vendor_hex = shown_hex(&vendor_root);

    // Unpinned: refused, and the refusal is in the ledger.
    let refused = warrantor(
        &root,
        &["tools", "admit", manifest_path.to_str().expect("utf-8")],
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("issuer add vendor"));
    assert_eq!(
        AdmittedSet::open(&root).receipts().expect("ledger").len(),
        1
    );

    assert!(warrantor(&root, &["issuer", "add", "vendor", &vendor_hex])
        .status
        .success());
    let admitted = warrantor(
        &root,
        &["tools", "admit", manifest_path.to_str().expect("utf-8")],
    );
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let listed = String::from_utf8_lossy(&warrantor(&root, &["tools", "list"]).stdout).to_string();
    assert!(
        listed.contains("admitted") && listed.contains("selftest"),
        "{listed}"
    );

    // Export, then verify on a store that has pinned nothing, against the admitting key.
    let export = root.join("selftest.admission.json");
    assert!(warrantor(
        &root,
        &[
            "tools",
            "export",
            "selftest",
            "--out",
            export.to_str().expect("utf-8")
        ]
    )
    .status
    .success());
    let machine_hex = shown_hex(&root);
    let clean = tempdir("cli-clean");
    let verdict = warrantor(
        &clean,
        &[
            "verify",
            export.to_str().expect("utf-8"),
            "--issuer",
            &machine_hex,
        ],
    );
    assert!(
        verdict.status.success(),
        "{}",
        String::from_utf8_lossy(&verdict.stderr)
    );
    let out = String::from_utf8_lossy(&verdict.stdout);
    assert!(
        out.contains("VERIFIED") && out.contains("not checked against a pin on this machine"),
        "{out}"
    );
    let no_anchor = warrantor(&clean, &["verify", export.to_str().expect("utf-8")]);
    assert!(
        !no_anchor.status.success(),
        "an export without an anchor verifies nothing"
    );

    // A session under --require-admission refuses a server with no admitted manifest.
    let stored = stored_open("w-cli", &["other.echo"], &[]);
    warrantor_warrant::store::WarrantStore::open(&root)
        .expect("store")
        .create(&stored)
        .expect("create");
    let refused = warrantor(
        &root,
        &[
            "mcp",
            "--agent",
            "w-cli",
            "--require-admission",
            "--upstream",
            "other=warrantor selftest-upstream",
        ],
    );
    assert!(!refused.status.success());
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(
        err.contains("no admitted manifest") && err.contains("tools admit"),
        "{err}"
    );
}

#[test]
fn a_server_publishing_beyond_its_manifest_is_revoked_at_attach_and_the_revocation_is_receipted() {
    let root = tempdir("attach");
    let vendor = key(7);
    // Names `echo` only; the selftest server also publishes `now`.
    let mut only_echo = selftest_manifest(&[Syscall::Attest]);
    only_echo.tools.remove("now");
    let signed = sign_manifest(only_echo, &vendor);
    let manifest_path = root.join("selftest.manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&signed).expect("json"),
    )
    .expect("write");
    let vendor_hex = hex::encode(vendor.verifying_key().to_bytes());
    assert!(warrantor(&root, &["issuer", "add", "vendor", &vendor_hex])
        .status
        .success());
    assert!(warrantor(
        &root,
        &["tools", "admit", manifest_path.to_str().expect("utf-8")]
    )
    .status
    .success());

    let stored = stored_open("w-attach", &["selftest.echo"], &[]);
    warrantor_warrant::store::WarrantStore::open(&root)
        .expect("store")
        .create(&stored)
        .expect("create");
    let session = warrantor(
        &root,
        &[
            "mcp",
            "--agent",
            "w-attach",
            "--upstream",
            "selftest=warrantor selftest-upstream",
        ],
    );
    assert!(!session.status.success(), "the session must not start");
    let err = String::from_utf8_lossy(&session.stderr);
    assert!(err.contains("revoked") && err.contains("\"now\""), "{err}");

    let set = AdmittedSet::open(&root);
    assert!(set.is_revoked("selftest").expect("read").is_some());
    let receipts = set.receipts().expect("ledger");
    let last = receipts.last().expect("the revocation");
    assert_eq!(last.claims.decision, AdmissionDecision::Revoked);
    assert!(last.claims.reason.contains("now"), "{}", last.claims.reason);
    verify_receipt(last, &machine_key(&root).verifying_key()).expect("the revocation verifies");

    // Revoked servers are refused at the next attach too, with or without --require-admission.
    let again = warrantor(
        &root,
        &[
            "mcp",
            "--agent",
            "w-attach",
            "--upstream",
            "selftest=warrantor selftest-upstream",
        ],
    );
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("was revoked at"));
}

#[test]
fn a_skill_manifest_is_admitted_by_digest_and_check_skill_tells_a_changed_file_from_the_admitted_one(
) {
    let root = tempdir("skill");
    let vendor = key(7);
    let skill = root.join("review.md");
    std::fs::write(
        &skill,
        b"# review
Read the diff before approving.
",
    )
    .expect("write skill");
    let digest = warrantor_warrant::report::sha256_hex(&std::fs::read(&skill).expect("read"));
    let mut claims = selftest_manifest(&[Syscall::Attest]);
    claims.server = "review-skill".to_string();
    claims.kind = AdmissionKind::Skill;
    claims.subject_digest = Some(digest);
    let signed = sign_manifest(claims, &vendor);
    let path = root.join("review.manifest.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&signed).expect("json")).expect("write");
    assert!(warrantor(
        &root,
        &[
            "issuer",
            "add",
            "vendor",
            &hex::encode(vendor.verifying_key().to_bytes())
        ]
    )
    .status
    .success());
    assert!(
        warrantor(&root, &["tools", "admit", path.to_str().expect("utf-8")])
            .status
            .success()
    );

    let same = warrantor(
        &root,
        &[
            "tools",
            "check-skill",
            "review-skill",
            skill.to_str().expect("utf-8"),
        ],
    );
    assert!(
        same.status.success(),
        "{}",
        String::from_utf8_lossy(&same.stderr)
    );
    assert!(String::from_utf8_lossy(&same.stdout).contains("OBSERVED"));

    std::fs::write(
        &skill,
        b"# review
Approve everything.
",
    )
    .expect("rewrite skill");
    let changed = warrantor(
        &root,
        &[
            "tools",
            "check-skill",
            "review-skill",
            skill.to_str().expect("utf-8"),
        ],
    );
    assert!(!changed.status.success());
    assert!(String::from_utf8_lossy(&changed.stderr).contains("MISMATCH"));
}

#[test]
fn a_new_manifest_lifts_a_revocation_and_the_withdrawn_one_stays_refused() {
    let root = tempdir("lift");
    let vendor = key(7);
    let machine = key(1);
    let directory = pinned(&root, "vendor", &vendor);
    let first = sign_manifest(selftest_manifest(&[Syscall::Attest]), &vendor);
    let set = AdmittedSet::open(&root);
    set.admit(&first, &directory, &machine, now_base() + 1)
        .expect("admitted");
    set.revoke(
        "selftest",
        "published beyond the manifest",
        &machine,
        now_base() + 2,
    )
    .expect("revoked");

    // Re-presenting the manifest that was withdrawn is refused.
    assert!(
        matches!(
            set.admit(&first, &directory, &machine, now_base() + 3),
            Err(AdmissionError::Revoked { .. })
        ),
        "the same manifest does not lift its own revocation"
    );

    // A NEW manifest from the same pinned issuer is a new decision, and it restores the server:
    // the revocation named the manifest it withdrew, not the server forever.
    let mut fuller = selftest_manifest(&[Syscall::Attest]);
    fuller.version = "1.0.1".to_string();
    let second = sign_manifest(fuller, &vendor);
    set.admit(&second, &directory, &machine, now_base() + 4)
        .expect("a new manifest lifts the revocation");
    assert_eq!(set.is_revoked("selftest").expect("read"), None);
    assert_eq!(set.load("selftest").expect("read"), Some(second));

    // The ledger tells the whole story: admit, revoke, refused re-presentation, lifting admit.
    assert_eq!(set.receipts().expect("ledger").len(), 4);
}
