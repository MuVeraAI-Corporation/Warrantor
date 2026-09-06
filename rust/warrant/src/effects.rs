//! L4-01 — the effect decomposition registry.
//!
//! Every tool the proxy forwards is a composition of the nine effect syscalls, or it is
//! unclassified. A tool called `deploy_to_prod` is EXEC plus NET plus MUTATE, and the blueprint's
//! goal is that those become the policy units.
//!
//! **What that is today: a declaration vocabulary, and nothing more.** The kernel does not yet
//! authorize, check or receipt a syscall. Authorization is still a tool-NAME allowlist
//! (`proxy.rs` `bounds.tools.contains(&call.tool)`), so the `deploy_to_prod` above is admitted or
//! refused by its name while its declared syscalls play no part. Observe mode and the staging
//! decision both read a projected `SideEffectClass`, not a syscall. And no evidence surface
//! records one: `receipts.rs`, `bundle.rs`, `report.rs`, `settle.rs`, `staging.rs` and `proxy.rs`
//! contain zero occurrences of `Syscall`, so `warrantor report` still prints a staged effect as
//! the tool name `github.create_pr`.
//!
//! What a decomposition decides here is narrower and worth stating exactly: whether a forwarded
//! tool is classified by declaration or refused as undeclared, and which `SideEffectClass` the
//! proxy sees through `Syscall::projection`. Task 2.3 moves staging onto syscalls; until it lands,
//! a present-tense sentence about the kernel authorizing syscalls would be a guarantee no line of
//! code makes true.
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

use std::collections::{BTreeMap, BTreeSet};

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

/// What the registry says about one tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified<'a> {
    /// Somebody declared it.
    Declared(&'a Decomposition),
    /// Nobody declared it and the policy is [`UnclassifiedPolicy::GuessRead`]: the caller uses
    /// `Read` and must name the tool at the end of the session, because a count is not a work
    /// list.
    Guessed,
}

/// What to do with a tool nobody declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnclassifiedPolicy {
    /// Strict mode: refuse the call. What `--upstream-strict` selects.
    Refuse,
    /// The shipped default until Task 2.2 lands signed manifests: class it `Read`, forward it,
    /// and name it when the session ends.
    GuessRead,
}

/// A tool refused under [`UnclassifiedPolicy::Refuse`]. `Display` is the sentence the agent
/// reads, and it tells the operator what to type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unclassified {
    /// The published tool name.
    pub tool: String,
}

impl std::fmt::Display for Unclassified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} has no declared effect decomposition, and this session is strict. This build can \
             only tell what a call DOES for the tools it stages; for everything else the \
             decomposition is what an operator declared, and an undeclared tool would otherwise \
             be forwarded as if it only read. Declare it: --upstream-effects '{}=mutate' (verbs: \
             {}, joined with '+'), or load a {EFFECT_REGISTRY_FORMAT} file with \
             --upstream-effects-file <path>.",
            self.tool,
            self.tool,
            verb_list()
        )
    }
}

impl std::error::Error for Unclassified {}

/// The on-disk shape of [`EFFECT_REGISTRY_FORMAT`]. Deliberately a map of verb lists rather than
/// of [`Decomposition`]s, so the only way in is through [`Decomposition::new`]'s checks.
#[derive(Debug, Serialize, Deserialize)]
struct RegistryDocument {
    format: String,
    tools: BTreeMap<String, BTreeSet<Syscall>>,
}

/// Published tool name to decomposition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecompositionRegistry {
    tools: BTreeMap<String, Decomposition>,
}

impl DecompositionRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The four tools this build can stage and perform, as
    /// [`crate::staging::EffectRegistry::github`] lists them. Exactly these and no more: a
    /// builtin decomposition for a tool the settle path cannot perform would promise staging that
    /// never happens.
    #[must_use]
    pub fn builtin() -> Self {
        fn of(tool: &str, syscalls: &[Syscall]) -> Decomposition {
            Decomposition {
                tool: tool.to_string(),
                syscalls: syscalls.iter().copied().collect(),
            }
        }
        let mut registry = Self::new();
        for decomposition in [
            of("github.create_pr", &[Syscall::Net, Syscall::Mutate]),
            of("github.comment", &[Syscall::Net, Syscall::Msg]),
            of("github.request_review", &[Syscall::Net, Syscall::Msg]),
            of("github.add_label", &[Syscall::Net, Syscall::Mutate]),
            // The governed HTTP call: it names a destination, which is network egress, and it
            // carries a payload, which is the user's data in motion.
            of(
                crate::adapters::http::TOOL,
                &[Syscall::Net],
            ),
        ] {
            registry
                .tools
                .insert(decomposition.tool.clone(), decomposition);
        }
        registry
    }

    /// Add one declaration. A second declaration for the same tool is refused even when
    /// identical: on one command line, saying a thing twice is a sign one of the two was meant to
    /// be something else.
    ///
    /// # Errors
    /// The duplicate, with both decompositions named.
    pub fn insert(&mut self, decomposition: Decomposition) -> Result<(), String> {
        if let Some(existing) = self.tools.get(&decomposition.tool) {
            return Err(format!(
                "{} is declared twice ({} and {}). Two decompositions for one tool means \
                 whichever was read last decides what happens to it, which is not a decision \
                 anybody made.",
                decomposition.tool,
                existing.render(),
                decomposition.render()
            ));
        }
        self.tools.insert(decomposition.tool.clone(), decomposition);
        Ok(())
    }

    /// Fold `other` in. An identical redeclaration is accepted (two documents may both state the
    /// obvious); a different one is refused, and the existing decomposition is named so the
    /// operator can see which side is wrong.
    ///
    /// # Errors
    /// The first conflict.
    pub fn merge(&mut self, other: Self) -> Result<(), String> {
        for (tool, decomposition) in other.tools {
            match self.tools.get(&tool) {
                Some(existing) if *existing == decomposition => {}
                Some(existing) => {
                    return Err(format!(
                        "{tool} is already declared as {} and cannot be redeclared as {}. If the \
                         existing one is builtin, it is what the settle path actually performs; \
                         if it came from a file, fix the file.",
                        existing.render(),
                        decomposition.render()
                    ))
                }
                None => {
                    self.tools.insert(tool, decomposition);
                }
            }
        }
        Ok(())
    }

    /// Look a tool up.
    #[must_use]
    pub fn get(&self, tool: &str) -> Option<&Decomposition> {
        self.tools.get(tool)
    }

    /// How many tools are declared.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Read a [`EFFECT_REGISTRY_FORMAT`] document. Any other format is refused by name; a
    /// document with no `format` field is not a registry at all.
    ///
    /// # Errors
    /// The parse failure, the foreign format, or the first bad decomposition inside.
    pub fn from_json(body: &str) -> Result<Self, String> {
        let document: RegistryDocument = serde_json::from_str(body)
            .map_err(|e| format!("not a {EFFECT_REGISTRY_FORMAT} document: {e}"))?;
        if document.format != EFFECT_REGISTRY_FORMAT {
            return Err(format!(
                "format {:?} is not {EFFECT_REGISTRY_FORMAT}. A registry in another format is \
                 not read, it is refused; a new format gets a new name, never a silent change.",
                document.format
            ));
        }
        let mut registry = Self::new();
        for (tool, syscalls) in document.tools {
            registry.insert(Decomposition::new(&tool, syscalls)?)?;
        }
        Ok(registry)
    }

    /// Render as a [`EFFECT_REGISTRY_FORMAT`] document, tools in name order.
    ///
    /// # Errors
    /// Only a serialization failure, which for this shape does not occur.
    pub fn to_json(&self) -> Result<String, String> {
        let document = RegistryDocument {
            format: EFFECT_REGISTRY_FORMAT.to_string(),
            tools: self
                .tools
                .iter()
                .map(|(tool, d)| (tool.clone(), d.syscalls.clone()))
                .collect(),
        };
        serde_json::to_string_pretty(&document).map_err(|e| format!("encode registry: {e}"))
    }

    /// Classify one published tool under `policy`.
    ///
    /// # Errors
    /// [`Unclassified`] when nobody declared the tool and the policy is
    /// [`UnclassifiedPolicy::Refuse`].
    pub fn classify(
        &self,
        tool: &str,
        policy: UnclassifiedPolicy,
    ) -> Result<Classified<'_>, Unclassified> {
        match (self.tools.get(tool), policy) {
            (Some(decomposition), _) => Ok(Classified::Declared(decomposition)),
            (None, UnclassifiedPolicy::GuessRead) => Ok(Classified::Guessed),
            (None, UnclassifiedPolicy::Refuse) => Err(Unclassified {
                tool: tool.to_string(),
            }),
        }
    }
}
