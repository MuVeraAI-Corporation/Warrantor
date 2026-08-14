// Build script: compile the Warrantor protos into Rust types via tonic-build (prost).
// This keeps the contract plane authoritative: every `cargo build` regenerates the types
// from `proto/`, so the Rust code can never drift from the wire format.
//
// ── Why the proto root is resolved twice ─────────────────────────────────────
//
// In this workspace the protos live at `<repo>/proto/`, two levels above this crate, and
// regenerating from there is the whole point — one source of truth for four languages.
//
// But `cargo package` copies only files *inside* the crate directory into the tarball, so a
// published crate that reached two levels up would find nothing there. Verification fails with
// `Could not make proto path relative`, and the crate is simply unpublishable — which is exactly
// what happened on the first real publish attempt.
//
// So the protos are also vendored into `warrantor-api/proto/` and shipped with the package. The
// build script prefers the vendored copy when it exists, which is the case both in the packaged
// crate and in a normal workspace checkout, and falls back to the repository copy otherwise.
//
// Keeping the vendored copy in sync is enforced in CI rather than left to memory: see
// `tools/ci/check_vendored_protos.py`, which fails if it drifts from `<repo>/proto/`.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Vendored copy first: it is the only one that exists inside a published crate.
    let vendored = manifest_dir.join("proto");
    let proto_root = if vendored.join("warrantor").is_dir() {
        vendored
    } else {
        manifest_dir
            .ancestors()
            .nth(2)
            .expect("could not locate repo root from CARGO_MANIFEST_DIR")
            .join("proto")
    };

    if !proto_root.join("warrantor").is_dir() {
        // Fail with the reason rather than letting protoc emit a path error that says nothing
        // about what is actually wrong.
        return Err(format!(
            "no proto sources found at {}. In a checkout they live at <repo>/proto/; in a \
             published crate they must be vendored into warrantor-api/proto/ (see the note at \
             the top of build.rs).",
            proto_root.display()
        )
        .into());
    }

    println!("cargo:rerun-if-changed={}", proto_root.display());

    let proto_files = [
        "warrantor/identity/v1/agent.proto",
        "warrantor/trust/v1/signing.proto",
        "warrantor/attestation/v1/report.proto",
        "warrantor/protocols/v1/aar.proto",
    ];

    // `tonic_prost_build`, not `tonic_build`. As of tonic 0.14 the prost integration lives in its
    // own crate; `tonic_build` still exists but is the codec-agnostic half and has no
    // `compile_protos`. The call below is otherwise unchanged.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &proto_files
                .iter()
                .map(|p| proto_root.join(p).to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            &[proto_root.to_string_lossy().into_owned()],
        )?;

    Ok(())
}
