//! `kill-switch` CLI.
//!
//! # ⚠ Trust assumptions you are accepting by running this binary
//!
//! * **`--operator` and `--clearance` are NOT authenticated.** They are argv strings. Anyone who
//!   can execute this binary can assert any operator identity and any clearance level. There is
//!   no signature, no SPIFFE SVID check and no directory lookup behind them. The only thing
//!   gating a manual kill is the ambient authorization on this process — the shell, the container
//!   and the RBAC that let you run it at all. AX-05 therefore requires
//!   `--i-am-not-authenticating` on every manual kill, so the gap cannot be accepted by accident.
//!   (The intended replacement is a signed operator token; see
//!   `aumos_kill_switch::OperatorAuthentication`.)
//! * **`--engine mock` contains nothing.** It exists for rehearsals. It prints a banner, and the
//!   emitted outcome carries `engine="mock"` / `simulated=true`. The default is `local`, which
//!   really terminates the target process.

use aumos_kill_switch::{
    execute_kill, ExecutionEngine, KillTarget, KillTrigger, LocalProcessEngine,
    MockExecutionEngine, OperatorAuthentication,
};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "kill-switch",
    version,
    about = "Execute an AumOS kill-switch action (<5s end-to-end)",
    long_about = "Execute an AumOS kill-switch action (<5s end-to-end).\n\n\
                  TRUST ASSUMPTION: --operator and --clearance are UNAUTHENTICATED argv strings. \
                  A manual kill therefore requires --i-am-not-authenticating."
)]
struct Cli {
    /// Which execution backend to run. `local` really suspends/terminates the target process;
    /// `mock` simulates and contains NOTHING.
    #[arg(long, value_enum, default_value_t = EngineChoice::Local, global = true)]
    engine: EngineChoice,

    /// OS process id of the agent. Required by the `local` engine.
    #[arg(long, global = true)]
    pid: Option<u32>,

    /// Kubernetes pod name (informational for the `local` engine).
    #[arg(long, global = true)]
    pod: Option<String>,

    /// Network namespace to isolate (informational for the `local` engine).
    #[arg(long, global = true)]
    netns: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum EngineChoice {
    /// Real containment of a local OS process.
    Local,
    /// Simulated containment — nothing is killed.
    Mock,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Kill an agent after a sandbox escape (confidence > 0.8).
    SandboxEscape {
        #[arg(long)]
        agent: String,
        /// Detector confidence, 0.0..=1.0. Rejected if NaN, infinite, or out of range.
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
    ///
    /// `--operator` and `--clearance` are UNAUTHENTICATED. You must pass
    /// `--i-am-not-authenticating` to acknowledge that.
    Manual {
        #[arg(long)]
        agent: String,
        /// UNAUTHENTICATED operator identity — see the command help.
        #[arg(long)]
        operator: String,
        /// UNAUTHENTICATED, self-asserted clearance (1..=5; >=3 required).
        #[arg(long)]
        clearance: u8,
        /// Acknowledge that --operator and --clearance are unauthenticated argv strings and that
        /// you are relying on the ambient authorization of this process. Required.
        #[arg(long = "i-am-not-authenticating", default_value_t = false)]
        i_am_not_authenticating: bool,
    },
    /// Service status.
    Status,
}

fn report(outcome: Result<aumos_kill_switch::KillOutcome, aumos_kill_switch::KillError>) -> ! {
    match outcome {
        Ok(o) => {
            if o.simulated {
                eprintln!(
                    "kill-switch: *** SIMULATED CONTAINMENT — NOTHING WAS KILLED *** \
                     (engine={})",
                    o.engine
                );
            }
            println!(
                "kill-switch: executed in {:?} (engine={}, simulated={})",
                o.elapsed, o.engine, o.simulated
            );
            for r in &o.action_reports {
                println!("  - {} [{:?}] {}", r.action, r.status, r.detail);
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

    let local_engine;
    let mock_engine;
    let engine: &dyn ExecutionEngine = match cli.engine {
        EngineChoice::Local => {
            local_engine = LocalProcessEngine::new();
            &local_engine
        }
        EngineChoice::Mock => {
            eprintln!(
                "kill-switch: *** --engine mock selected: this run will CONTAIN NOTHING. *** \
                 The outcome will be tagged engine=mock simulated=true."
            );
            mock_engine = MockExecutionEngine::new();
            &mock_engine
        }
    };

    let agent_id = match &cli.command {
        Commands::SandboxEscape { agent, .. }
        | Commands::BehavioralAnomaly { agent, .. }
        | Commands::Manual { agent, .. } => agent.clone(),
        Commands::RegulatoryOrder { order_id } => format!("regulatory-order:{order_id}"),
        Commands::Status => String::new(),
    };
    let target = KillTarget {
        agent_id,
        pid: cli.pid,
        pod: cli.pod.clone(),
        netns: cli.netns.clone(),
    };

    match cli.command {
        Commands::Status => {
            println!("kill-switch: ready (mock policy; OPA Rego lands in task 03)");
            println!(
                "kill-switch: execution engine={} simulated={}",
                engine.name(),
                engine.is_simulated()
            );
            println!(
                "kill-switch: government api url={}",
                aumos_kill_switch::GOVERNMENT_API_URL
            );
            println!(
                "kill-switch: TRUST ASSUMPTION — --operator/--clearance are UNAUTHENTICATED \
                 argv strings; a manual kill requires --i-am-not-authenticating"
            );
        }
        Commands::SandboxEscape {
            agent: _,
            confidence,
        } => report(execute_kill(
            engine,
            &target,
            KillTrigger::SandboxEscape { confidence },
        )),
        Commands::BehavioralAnomaly {
            agent: _,
            pattern,
            confidence,
        } => report(execute_kill(
            engine,
            &target,
            KillTrigger::BehavioralAnomaly {
                pattern,
                confidence,
            },
        )),
        Commands::RegulatoryOrder { order_id } => report(execute_kill(
            engine,
            &target,
            KillTrigger::RegulatoryOrder { order_id },
        )),
        Commands::Manual {
            agent: _,
            operator,
            clearance,
            i_am_not_authenticating,
        } => {
            if !i_am_not_authenticating {
                eprintln!(
                    "kill-switch: REFUSED — --operator and --clearance are unauthenticated argv \
                     strings. Re-run with --i-am-not-authenticating to acknowledge that this \
                     manual kill is gated only by the ambient authorization on this process."
                );
                std::process::exit(2);
            }
            report(execute_kill(
                engine,
                &target,
                KillTrigger::Manual {
                    operator,
                    clearance,
                    operator_authentication: OperatorAuthentication::UnauthenticatedAcknowledged,
                },
            ))
        }
    }
}
