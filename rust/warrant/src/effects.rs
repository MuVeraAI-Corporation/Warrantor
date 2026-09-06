//! L4-01 — the effect decomposition registry.
//!
//! Every tool the proxy forwards is a composition of the nine effect syscalls, or it is
//! unclassified. The kernel authorizes, checks and receipts syscalls, never tool names: a tool
//! called `deploy_to_prod` is EXEC plus NET plus MUTATE, and those are the policy units.
//!
//! # What this refuses to be
//!
//! A classifier. The precedent this file replaces guessed `Read` for anything it did not know and
//! forwarded it, so an upstream `write_file` was performed rather than staged. Inferring a
//! decomposition from a tool's `inputSchema` would be the same guess with a better costume.
//! Decompositions are *declared* — by the operator on the command line, by a
//! [`EFFECT_REGISTRY_FORMAT`] document, and from Task 2.2 onward by a signed manifest — and under
//! [`UnclassifiedPolicy::Refuse`] a tool nobody declared is refused rather than defaulted.
//!
//! # Projection to `SideEffectClass`, and why it is temporary
//!
//! [`crate::proxy::Proxy::decide`] still reads a [`SideEffectClass`] for the observe-mode hard
//! block and for `staged_classes`. Until staging moves onto syscalls (Task 2.3) a decomposition
//! projects to one class through [`Syscall::projection`]. The table is lossy and documented, and
//! it never projects *downward*: a multi-syscall decomposition takes its highest-ranked class.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::SideEffectClass;

/// The registry document format. A registry in any other format is refused, never read.
pub const EFFECT_REGISTRY_FORMAT: &str = "warrantor.effect-registry/1";

/// The nine effect syscalls: the fixed, enumerable set of consequential-action types the kernel
/// understands. Every adapter is a decomposition into these, never a tenth entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Syscall {
    /// Network egress: destination, method, data class, volume, purpose.
    Net,
    /// Credential minting or presentation: audience, resource, method, expiry.
    Cred,
    /// Execution by content digest on a declared execution surface.
    Exec,
    /// Durable write: target path or resource, write set, data class.
    Mutate,
    /// A message to a recipient: sender identity, recipient, content class, rate.
    Msg,
    /// Consumption of a metered resource: money, tokens, compute, wall-clock.
    Spend,
    /// Authority handed to a child: child = intersection(parent, requested).
    Delegate,
    /// A physical or irreversible effect; non-delegable human authority in the chain (I-08).
    Actuate,
    /// A claim about the agent's own state or work; an input to a receipt, never the receipt.
    Attest,
}

impl Syscall {
    /// Every syscall, in table order.
    pub const ALL: [Self; 9] = [
        Self::Net,
        Self::Cred,
        Self::Exec,
        Self::Mutate,
        Self::Msg,
        Self::Spend,
        Self::Delegate,
        Self::Actuate,
        Self::Attest,
    ];

    /// Parse a wire word. Exact and lowercase: `"NET"` does not parse, and neither does `"delete"`
    /// — the wider vocabulary lands on the table, it does not grow it.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.as_str() == word)
    }

    /// The wire word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Net => "net",
            Self::Cred => "cred",
            Self::Exec => "exec",
            Self::Mutate => "mutate",
            Self::Msg => "msg",
            Self::Spend => "spend",
            Self::Delegate => "delegate",
            Self::Actuate => "actuate",
            Self::Attest => "attest",
        }
    }

    /// The [`SideEffectClass`] this syscall projects to while the proxy still decides by class.
    ///
    /// `Actuate` projects to `Destructive`, not `Physical`: the table defines ACTUATE as "physical
    /// or irreversible", and `Destructive` is the class [`crate::proxy`] refuses in observe mode
    /// while `Physical` is not. Projecting to the class the proxy does not block would weaken a
    /// refusal that exists today. `Physical` is reachable from no decomposition until an actuation
    /// adapter exists.
    #[must_use]
    pub const fn projection(self) -> SideEffectClass {
        match self {
            Self::Net | Self::Attest => SideEffectClass::Read,
            Self::Cred | Self::Exec | Self::Mutate | Self::Msg | Self::Delegate => {
                SideEffectClass::Write
            }
            Self::Spend => SideEffectClass::Financial,
            Self::Actuate => SideEffectClass::Destructive,
        }
    }
}

/// Strict ordering of classes for [`Decomposition::class`]: a decomposition never projects below
/// its most consequential syscall.
const fn rank(class: SideEffectClass) -> u8 {
    match class {
        SideEffectClass::Read => 0,
        SideEffectClass::Write => 1,
        SideEffectClass::Financial => 2,
        SideEffectClass::Destructive => 3,
        SideEffectClass::Physical => 4,
    }
}

fn verb_list() -> String {
    Syscall::ALL
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// One tool's decomposition into syscalls. Fields are private so a decomposition with no
/// syscalls — which would project to `Read` by accident — cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decomposition {
    tool: String,
    syscalls: BTreeSet<Syscall>,
}

impl Decomposition {
    /// Build a decomposition. Refuses an empty tool name and an empty set.
    ///
    /// # Errors
    /// A sentence naming what was wrong, suitable for the command line.
    pub fn new(tool: &str, syscalls: BTreeSet<Syscall>) -> Result<Self, String> {
        let tool = tool.trim();
        if tool.is_empty() {
            return Err("a decomposition names no tool".to_string());
        }
        if syscalls.is_empty() {
            return Err(format!(
                "{tool} decomposes to nothing; a tool with no effect is a tool nobody needs to \
                 declare, and one with an effect must say which"
            ));
        }
        Ok(Self {
            tool: tool.to_string(),
            syscalls,
        })
    }

    /// Parse `<tool>=<verb>+<verb>...`. The LAST `=` splits, so a tool name may not contain one
    /// and a verb list never does.
    ///
    /// # Errors
    /// The first thing wrong with the value, naming the nine verbs when the fault is a verb. A
    /// typo is refused rather than defaulted: a misspelled `mutate` forwarded as a read is the
    /// exact failure this registry exists to end.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let Some((tool, verbs)) = raw.rsplit_once('=') else {
            return Err(format!(
                "--upstream-effects takes tool=verb+verb, e.g. --upstream-effects \
                 'deploy.to_prod=exec+net+mutate'; got {raw:?}"
            ));
        };
        let tool = tool.trim();
        if tool.is_empty() {
            return Err(format!("--upstream-effects {raw:?} names no tool"));
        }
        if verbs.trim().is_empty() {
            return Err(format!(
                "{tool} decomposes to nothing; a tool with no effect is a tool nobody needs to \
                 declare, and one with an effect must say which"
            ));
        }
        let mut syscalls = BTreeSet::new();
        for word in verbs.split('+') {
            let word = word.trim();
            let Some(syscall) = Syscall::parse(word) else {
                return Err(format!(
                    "{word:?} is not an effect syscall. The nine are: {}. Refusing rather than \
                     defaulting -- a typo here would forward an effect the warrant never decided.",
                    verb_list()
                ));
            };
            if !syscalls.insert(syscall) {
                return Err(format!(
                    "{tool} lists {word} twice; a decomposition is a set"
                ));
            }
        }
        Self::new(tool, syscalls)
    }

    /// The published tool name, `<server>.<tool>`.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// The syscalls, in table order.
    #[must_use]
    pub fn syscalls(&self) -> &BTreeSet<Syscall> {
        &self.syscalls
    }

    /// The class the proxy decides by, until staging moves onto syscalls: the highest-ranked
    /// projection of any syscall present. Never lower than any member.
    #[must_use]
    pub fn class(&self) -> SideEffectClass {
        let mut best = SideEffectClass::Read;
        for syscall in &self.syscalls {
            let class = syscall.projection();
            if rank(class) > rank(best) {
                best = class;
            }
        }
        best
    }

    /// `verb+verb` in set order, so equal decompositions render equal.
    #[must_use]
    pub fn render(&self) -> String {
        self.syscalls
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("+")
    }
}
