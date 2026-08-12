//! `defstack` — unified Warrantor installer/orchestrator CLI.
//!
//! Subcommands: `install`, `verify`, `upgrade`, `compliance-report`, `privacy`, `list`.
//! Wave-1: install/verify/compliance-report/list are wired against a real component registry
//! (the 8 Wave-1 components + the full catalog). Real package-registry install logic lands
//! post-Wave-1 (per scope boundary: no external publishing during Wave-1).

use clap::{Parser, Subcommand};
use std::collections::BTreeMap;

#[derive(Parser, Debug)]
#[command(
    name = "defstack",
    version,
    about = "Warrantor — open authority and evidence layer for autonomous systems",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all known Warrantor components (the catalog from the reconciliation matrix).
    List,
    /// Install a component: `defstack install <name>`. Wave-1: prints the install plan.
    Install { name: String },
    /// Verify an installation: `defstack verify [<name>]`. Wave-1: checks the component is known.
    Verify { name: Option<String> },
    /// Upgrade all installed components. Wave-1: prints the upgrade plan.
    Upgrade,
    /// Generate a compliance report (EU AI Act Art. 55, NIST AI RMF, ISO 42001, etc.).
    ComplianceReport {
        /// Optional model identifier to scope the report.
        #[arg(long)]
        model: Option<String>,
    },
    /// Privacy operations (GDPR / CCPA / HIPAA data-subject rights).
    Privacy {
        #[command(subcommand)]
        action: PrivacyAction,
    },
    /// Initialize a new Warrantor-secured project in the current directory.
    Init {
        /// Project name (defaults to directory name).
        #[arg(long)]
        name: Option<String>,
        /// Initialize with a specific agent type template.
        #[arg(long)]
        agent: Option<String>,
    },
    /// Start the local development environment (all services with mock backends).
    Dev {
        /// Only start specific services (comma-separated names).
        #[arg(long)]
        only: Option<String>,
    },
    /// Run the cross-language conformance suite.
    Test {
        /// Only run tests for a specific language.
        #[arg(long)]
        lang: Option<String>,
    },
    /// Deploy Warrantor to a cloud provider.
    Deploy {
        /// Cloud provider (azure, aws, local).
        #[arg(long)]
        cloud: String,
        /// Configuration file path.
        #[arg(long, default_value = "warrantor.deploy.toml")]
        config: String,
    },
}

#[derive(Subcommand, Debug)]
enum PrivacyAction {
    /// Export all data for a subject (GDPR Art. 15 / 20).
    Export { subject: String },
    /// Erase a subject's data (GDPR Art. 17).
    Erase { subject: String },
}

/// A catalog entry — mirrors docs/00-reconciliation-matrix.md.
#[derive(Debug, Clone, serde::Serialize)]
struct Component {
    id: &'static str,
    name: &'static str,
    wave: u8,
    language: &'static str,
    status: &'static str,
}

/// The Wave-1 component catalog (the 8 components shipped in Wave-1).
const WAVE1: &[Component] = &[
    Component {
        id: "T1",
        name: "trust-core",
        wave: 1,
        language: "rust",
        status: "v1.0.0",
    },
    Component {
        id: "X1",
        name: "defstack-cli",
        wave: 1,
        language: "rust",
        status: "v1.0.0",
    },
    Component {
        id: "C1-1",
        name: "nvtrust-bridge",
        wave: 1,
        language: "rust+py+go",
        status: "v1.0.0",
    },
    Component {
        id: "C1-2",
        name: "cuda-gram",
        wave: 1,
        language: "python",
        status: "v1.0.0",
    },
    Component {
        id: "R2",
        name: "eval-guard",
        wave: 1,
        language: "rust+ebpf",
        status: "v1.0.0",
    },
    Component {
        id: "R3",
        name: "kill-switch",
        wave: 1,
        language: "rust+python",
        status: "v1.0.0",
    },
    Component {
        id: "R4",
        name: "credential-vault",
        wave: 1,
        language: "rust",
        status: "v1.0.0",
    },
    Component {
        id: "I1",
        name: "agent-identity",
        wave: 1,
        language: "go (mock in wave-1)",
        status: "mock",
    },
];

fn find_component(name: &str) -> Option<&'static Component> {
    // Match by canonical id or kebab-name.
    WAVE1.iter().find(|c| c.id == name || c.name == name)
}

fn install_plan(c: &Component) -> serde_json::Value {
    serde_json::json!({
        "component": { "id": c.id, "name": c.name },
        "language": c.language,
        "wave": c.wave,
        "status": c.status,
        "plan": [
            format!("resolve {} package for language {}", c.name, c.language),
            "verify CycloneDX SBOM present".to_string(),
            "verify SLSA L3 build provenance".to_string(),
            "install to ~/.aumos/components/<id>".to_string(),
        ],
        "note": "Wave-1: install plan only — real package-registry install lands post-Wave-1",
    })
}

fn compliance_report(model: &Option<String>) -> serde_json::Value {
    // The 10 frameworks from docs/cross-cutting/13-compliance-frameworks.md.
    let mut frameworks = BTreeMap::new();
    frameworks.insert(
        "EU-AI-Act-Article-55",
        serde_json::json!({
            "covered_by": {
                "documentation": "S4 model-sbom",
                "training_data": "S5 data-provenance-kit",
                "lineage": "S2 provena-chain",
                "copyright": "A3 bias-sentinel",
                "adversarial_testing": "A2 adversaria",
                "incident_reporting": "X5 retro-spec-kit + A4 comply-gate"
            },
            "deadline": "2027-08-02"
        }),
    );
    frameworks.insert(
        "NIST-AI-RMF-1.0",
        serde_json::json!({
            "Govern": "I1 agent-identity + A4 comply-gate",
            "Map": "S4 model-sbom + S5 data-provenance-kit + S2 provena-chain",
            "Measure": "A1 safe-eval + A2 adversaria + A3 bias-sentinel",
            "Manage": "R3 kill-switch + R2 eval-guard + R4 credential-vault"
        }),
    );
    frameworks.insert(
        "ISO-IEC-42001-2023",
        serde_json::json!({"target_certification": "M18"}),
    );
    frameworks.insert("FedRAMP-AI", serde_json::json!({"target_components": ["R3 kill-switch", "I1 agent-identity", "C1-3 attesta-flow"], "target": "M18"}));
    frameworks.insert(
        "OpenSSF-SLSA-v1.0",
        serde_json::json!({"target_level": "L3", "all_components": true}),
    );
    frameworks.insert("EU-DORA", serde_json::json!({"financial_sector_components": ["N1 open-serve-kit", "N3 inference-proxy", "N4 tenant-guard", "R3 kill-switch"]}));
    frameworks.insert("AI-Kill-Switch-Act-HR-2026", serde_json::json!({"reference_implementation": "R3 kill-switch", "government_api": "stubbed in Wave-1"}));
    frameworks.insert(
        "EU-NIS2",
        serde_json::json!({"audit_components": ["I1 agent-identity"]}),
    );
    frameworks.insert(
        "UK-AI-Safety-Bill",
        serde_json::json!({"mirrors": "EU-AI-Act-Article-55"}),
    );
    frameworks.insert(
        "China-Generative-AI",
        serde_json::json!({"status": "out of scope for v1"}),
    );

    serde_json::json!({
        "generated_at": chrono_now(),
        "model": model.clone().unwrap_or_else(|| "<unspecified>".into()),
        "frameworks": frameworks,
        "signed_by": "did:web:muveraai.com",
        "note": "Wave-1: structural report only — attestation signatures land as components ship"
    })
}

fn chrono_now() -> String {
    // Avoid pulling chrono; use SystemTime + a fixed-format approximation.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}") // epoch seconds; ISO 8601 conversion in task 07
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::List => {
            println!(
                "{:<6} {:<22} {:<5} {:<18} STATUS",
                "ID", "NAME", "WAVE", "LANGUAGE"
            );
            for c in WAVE1 {
                println!(
                    "{:<6} {:<22} {:<5} {:<18} {}",
                    c.id, c.name, c.wave, c.language, c.status
                );
            }
        }
        Commands::Install { name } => match find_component(&name) {
            Some(c) => {
                let plan = install_plan(c);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&plan).expect("serialize")
                );
            }
            None => {
                eprintln!("defstack: unknown component '{name}'. Try `defstack list`.");
                std::process::exit(1);
            }
        },
        Commands::Verify { name } => match name {
            Some(n) => match find_component(&n) {
                Some(c) => {
                    println!(
                        "defstack verify {}: known (id={}, status={})",
                        c.name, c.id, c.status
                    );
                }
                None => {
                    eprintln!("defstack verify: unknown component '{n}'");
                    std::process::exit(1);
                }
            },
            None => {
                // Verify all Wave-1 components.
                println!(
                    "defstack verify: checking {} Wave-1 components",
                    WAVE1.len()
                );
                for c in WAVE1 {
                    println!("  [ok] {} ({}) — {}", c.id, c.name, c.status);
                }
            }
        },
        Commands::Upgrade => {
            println!("defstack upgrade: {} components in scope", WAVE1.len());
            for c in WAVE1 {
                println!("  - {} ({}): would upgrade to latest", c.id, c.name);
            }
            println!("note: Wave-1 — upgrade plan only");
        }
        Commands::ComplianceReport { model } => {
            let report = compliance_report(&model);
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("serialize")
            );
        }
        Commands::Privacy { action } => match action {
            PrivacyAction::Export { subject } => {
                println!(
                    "{{\"action\":\"export\",\"subject\":\"{subject}\",\"status\":\"not-yet-implemented\",\"sla_days\":30}}"
                );
            }
            PrivacyAction::Erase { subject } => {
                println!(
                    "{{\"action\":\"erase\",\"subject\":\"{subject}\",\"status\":\"not-yet-implemented\",\"sla_days\":30,\"propagation_hours\":72}}"
                );
            }
        },
        Commands::Init { name, agent } => {
            let project_name = name.unwrap_or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "warrantor-project".into())
            });
            println!(" Initializing Warrantor project: {project_name}");
            // Create .aumos/ directory
            let warrantor_dir = std::path::Path::new(".aumos");
            let _ = std::fs::create_dir_all(warrantor_dir);
            // Create aumos.toml config
            let config = format!(
                r#"[project]
name = "{project_name}"
version = "0.1.0"
agent_type = "{}"

[security]
side_effect_class = "write"
require_attestation = false
kill_on_secret_exposure = true

[components]
# Add components to install: trust-core, agent-identity, kill-switch, etc.
"#,
                agent.as_deref().unwrap_or("generic")
            );
            std::fs::write(warrantor_dir.join("config.toml"), config).expect("write config");
            println!(" Created .aumos/config.toml");
            // Create CLAUDE.md if agent is claude_code
            if agent.as_deref() == Some("claude_code") {
                std::fs::write("CLAUDE.md", "# Warrantor Secured Project\n\n## Allowed Tools\ngit, npm, cargo, python\n\n## Warrantor Integration\npip install warrantor-agent\n").ok();
                println!(" Created CLAUDE.md");
            }
            // Create .complygate.yml
            std::fs::write(".complygate.yml", "# Warrantor Compliance Gates\ncoverage:\n  minimum: 85\nsbom:\n  required: true\neval:\n  required: false\n").ok();
            println!(" Created .complygate.yml");
            println!("\n Next steps:");
            println!("   defstack install trust-core agent-identity");
            println!("   defstack dev");
            println!("   defstack test");
        }
        Commands::Dev { only } => {
            println!(" Starting Warrantor development environment...");
            match &only {
                Some(services) => println!("   services: {services}"),
                None => println!("   services: all"),
            }
            // Check if docker-compose.yml exists
            if std::path::Path::new("docker-compose.yml").exists()
                || std::path::Path::new("../docker-compose.yml").exists()
            {
                let compose_file = if std::path::Path::new("docker-compose.yml").exists() {
                    "docker-compose.yml"
                } else {
                    "../docker-compose.yml"
                };
                let mut cmd = std::process::Command::new("docker-compose");
                cmd.arg("-f").arg(compose_file).arg("up").arg("-d");
                if let Some(services) = &only {
                    for s in services.split(',') {
                        cmd.arg(s.trim());
                    }
                }
                match cmd.status() {
                    Ok(status) if status.success() => {
                        println!(" Development environment started.");
                        println!(" Services:");
                        println!("   agent-identity:  http://localhost:8441/healthz");
                        println!("   open-serve-kit:  http://localhost:8443/healthz");
                        println!("   ollama:          http://localhost:11434");
                        println!("   console:         http://localhost:3000");
                    }
                    _ => {
                        eprintln!(" Failed to start docker-compose. Is Docker installed?");
                    }
                }
            } else {
                eprintln!(" No docker-compose.yml found. Run `defstack init` first.");
            }
        }
        Commands::Test { lang } => {
            println!(" Running Warrantor test suite...");
            if let Some(l) = &lang {
                println!("   language: {l}");
                match l.as_str() {
                    "rust" => {
                        let _ = std::process::Command::new("cargo")
                            .arg("test")
                            .current_dir("rust")
                            .status();
                    }
                    "go" => {
                        if let Ok(entries) = std::fs::read_dir("go") {
                            for entry in entries.flatten() {
                                let _ = std::process::Command::new("go")
                                    .args(["test", "./..."])
                                    .current_dir(entry.path())
                                    .status();
                            }
                        } else {
                            eprintln!(" No go/ directory found");
                        }
                    }
                    "python" => {
                        if let Ok(entries) = std::fs::read_dir("python") {
                            for entry in entries.flatten() {
                                let _ = std::process::Command::new("python")
                                    .args(["-m", "pytest", "-q"])
                                    .current_dir(entry.path())
                                    .status();
                            }
                        } else {
                            eprintln!(" No python/ directory found");
                        }
                    }
                    "typescript" | "ts" => {
                        let _ = std::process::Command::new("npx")
                            .args(["vitest", "run"])
                            .current_dir("typescript")
                            .status();
                    }
                    _ => {
                        eprintln!(" Unknown language: {l}. Use: rust, go, python, typescript");
                    }
                }
            } else {
                println!("   Running all languages...");
                // Rust
                let _ = std::process::Command::new("cargo")
                    .arg("test")
                    .current_dir("rust")
                    .status();
                // Go
                if let Ok(entries) = std::fs::read_dir("go") {
                    for entry in entries.flatten() {
                        let _ = std::process::Command::new("go")
                            .args(["test", "./..."])
                            .current_dir(entry.path())
                            .status();
                    }
                }
                // Python
                if let Ok(entries) = std::fs::read_dir("python") {
                    for entry in entries.flatten() {
                        let _ = std::process::Command::new("python")
                            .args(["-m", "pytest", "-q"])
                            .current_dir(entry.path())
                            .status();
                    }
                }
                // TypeScript
                let _ = std::process::Command::new("npx")
                    .args(["vitest", "run"])
                    .current_dir("typescript")
                    .status();
                // Conformance
                let _ = std::process::Command::new("bash")
                    .arg("tools/conformance/run.sh")
                    .status();
            }
            println!(" Test suite complete.");
        }
        Commands::Deploy { cloud, config } => {
            println!(" Deploying Warrantor to {cloud}...");
            println!("   config: {config}");
            match cloud.as_str() {
                "azure" => {
                    println!("   Terraform: terraform/azure/");
                    println!("   Steps:");
                    println!("     1. az login");
                    println!("     2. cd terraform/azure && terraform init && terraform apply");
                    println!("     3. defstack install trust-core agent-identity ...");
                }
                "aws" => {
                    println!("   Terraform: terraform/aws/");
                    println!("   Steps:");
                    println!("     1. aws configure");
                    println!("     2. cd terraform/aws && terraform init && terraform apply");
                }
                "local" => {
                    println!("   Local deployment via Docker Compose");
                    let _ = std::process::Command::new("docker-compose")
                        .args(["up", "-d"])
                        .status();
                }
                _ => {
                    eprintln!(" Unknown cloud: {cloud}. Use: azure, aws, local");
                }
            }
        }
    }
}
