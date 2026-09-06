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
