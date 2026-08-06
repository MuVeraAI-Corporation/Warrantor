//! `kill-switch` CLI.

use aumos_kill_switch::{execute_kill, KillTrigger};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "kill-switch",
    version,
    about = "Execute an AumOS kill-switch action (<5s end-to-end)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Kill an agent after a sandbox escape (confidence > 0.8).
    SandboxEscape {
        #[arg(long)]
        agent: String,
        /// Detector confidence, 0.0..=1.0.
        #[arg(long)]
        confidence: f64,
    },
    /// Kill after a behavioral anomaly (confidence > 0.9).
    BehavioralAnomaly {
        #[arg(long)]
        agent: String,
        /// MITRE ATT&CK / AIX pattern name.
        #[arg(long)]
        pattern: String,
        #[arg(long)]
        confidence: f64,
    },
    /// Execute a government regulatory order (AI Kill Switch Act). Notifies the Gov API.
    RegulatoryOrder {
        #[arg(long)]
        order_id: String,
    },
    /// Manual operator kill (requires clearance >= 3).
    Manual {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        operator: String,
        /// Operator clearance (1..=5).
        #[arg(long)]
        clearance: u8,
    },
    /// Service status.
    Status,
}

fn report(outcome: Result<aumos_kill_switch::KillOutcome, aumos_kill_switch::KillError>) -> ! {
    match outcome {
        Ok(o) => {
            println!("kill-switch: executed in {:?}", o.elapsed);
            for a in &o.actions_taken {
                println!("  - {a}");
            }
            if let Some(ack) = &o.government_ack {
                println!(
                    "  government api: ack_id={} confirmed={}",
                    ack.ack_id, ack.confirmed
                );
            }
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("kill-switch: FAILED — {e}");
            std::process::exit(1);
        }
    }
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
        Commands::Status => {
            println!("kill-switch: ready (mock policy; OPA Rego lands in task 03)");
            println!("kill-switch: government api url={}", aumos_kill_switch::GOVERNMENT_API_URL);
            let _ = cli; // suppress unused warning path
        }
        Commands::SandboxEscape {
            agent: _,
            confidence,
        } => report(execute_kill(KillTrigger::SandboxEscape { confidence })),
        Commands::BehavioralAnomaly {
            agent: _,
            pattern,
            confidence,
        } => report(execute_kill(KillTrigger::BehavioralAnomaly { pattern, confidence })),
        Commands::RegulatoryOrder { order_id } => {
            report(execute_kill(KillTrigger::RegulatoryOrder { order_id }))
        }
        Commands::Manual {
            agent: _,
            operator,
            clearance,
        } => report(execute_kill(KillTrigger::Manual {
            operator,
            clearance,
        })),
    }
}
