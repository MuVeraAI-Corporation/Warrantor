//! `credential-vault` CLI.

use aumos_credential_vault::{
    issue, scan_for_exposed_credentials, AwsSecretsManagerBackend, CredentialBackend,
    HashiCorpVaultBackend, KubernetesSecretsBackend, MockBackend, DEFAULT_TTL,
};
use clap::{Parser, Subcommand};
use std::io::{self, Read};

#[derive(Parser, Debug)]
#[command(
    name = "credential-vault",
    version,
    about = "Broker and revoke agent-scoped credentials; scan for exposed credentials"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Issue a scoped credential.
    Issue {
        #[arg(long)]
        spiffe_id: String,
        #[arg(long)]
        task: String,
        #[arg(long)]
        bound_ip: String,
        #[arg(long)]
        secret_key: String,
        /// Backend: mock (default), vault, aws, k8s.
        #[arg(long, default_value = "mock")]
        backend: String,
    },
    /// Revoke all credentials (kill-switch hook).
    RevokeAll,
    /// Scan stdin (or --path) for exposed credentials. Exit 1 if any are found.
    Scan {
        /// Path to scan, or `-` for stdin.
        #[arg(long, default_value = "-")]
        path: String,
    },
    /// Service status.
    Status,
}

fn read_input(path: &str) -> io::Result<String> {
    if path == "-" {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        Ok(std::fs::read_to_string(path)?)
    }
}

fn select_backend(name: &str) -> Box<dyn CredentialBackend> {
    match name {
        "mock" => Box::new(MockBackend::new([
            ("github_token".to_string(), "ghp_REDACTED".to_string()),
            ("aws_key".to_string(), "AKIA_REDACTED".to_string()),
        ])),
        "vault" => Box::new(HashiCorpVaultBackend::new("https://vault.example.com:8200")),
        "aws" => Box::new(AwsSecretsManagerBackend::new("us-east-1")),
        "k8s" => Box::new(KubernetesSecretsBackend::new("default")),
        other => {
            eprintln!("credential-vault: unknown backend '{other}' (try mock|vault|aws|k8s)");
            std::process::exit(2);
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Status => {
            println!("credential-vault: ready (mock backend; Vault/AWS/K8s are stubs in task 03)");
        }
        Commands::Issue {
            spiffe_id,
            task,
            bound_ip,
            secret_key,
            backend,
        } => {
            let backend = select_backend(&backend);
            match issue(backend.as_ref(), &spiffe_id, &task, &bound_ip, &secret_key, DEFAULT_TTL) {
                Ok(cred) => {
                    // REDACT the secret in CLI output (never log secrets at INFO level).
                    let redacted = ScopedCredJson {
                        spiffe_id: cred.spiffe_id,
                        task: cred.task,
                        bound_ip: cred.bound_ip,
                        issued_at: cred.issued_at,
                        expires_at: cred.expires_at,
                        secret_redacted: true,
                    };
                    println!("{}", serde_json::to_string_pretty(&redacted).expect("serialize"));
                }
                Err(e) => {
                    eprintln!("credential-vault: issue failed — {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::RevokeAll => match aumos_credential_vault::revoke_all() {
            Ok(count) => println!(
                "credential-vault: revoked {count} credential(s)"
            ),
            Err(e) => {
                eprintln!("credential-vault: revoke failed — {e}");
                std::process::exit(1);
            }
        },
        Commands::Scan { path } => {
            let text = match read_input(&path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("credential-vault: read {path} failed: {e}");
                    std::process::exit(2);
                }
            };
            match scan_for_exposed_credentials(&text) {
                Ok(found) if found.is_empty() => {
                    println!("credential-vault: no exposed credentials detected");
                    std::process::exit(0);
                }
                Ok(found) => {
                    eprintln!("credential-vault: {} exposed credential(s) detected:", found.len());
                    for f in &found {
                        eprintln!("  - {} : {}", f.credential_type, f.matched);
                    }
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("credential-vault: scan failed — {e}");
                    std::process::exit(2);
                }
            }
        }
    }
}

#[derive(serde::Serialize)]
struct ScopedCredJson {
    spiffe_id: String,
    task: String,
    bound_ip: String,
    issued_at: u64,
    expires_at: u64,
    secret_redacted: bool,
}
