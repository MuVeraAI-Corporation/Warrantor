// Build script: compile the AumOS protos into Rust types via tonic-build (prost).
// This keeps the contract plane authoritative: every `cargo build` regenerates the types
// from `proto/`, so the Rust code can never drift from the wire format.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // proto/ lives at <repo>/proto/, i.e. two levels up from rust/warrantor-api/.
    let proto_root = manifest_dir
        .ancestors()
        .nth(2)
        .expect("could not locate repo root from CARGO_MANIFEST_DIR")
        .join("proto");

    println!("cargo:rerun-if-changed={}", proto_root.display());

    // Tell prost/tonic about all our proto packages.
    let proto_files = [
        "aumos/identity/v1/agent.proto",
        "aumos/trust/v1/signing.proto",
        "aumos/attestation/v1/report.proto",
        "aumos/protocols/v1/aar.proto",
    ];

    tonic_build::configure()
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
