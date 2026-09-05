//! # warrantor-delegation-chain (A-2 / catalogue Domain A)
//!
//! W6 delegation-chain intersection: warrants that can **delegate**. A holder of warrant `W` may issue a
//! sub-warrant `W′` where `scope(W′) ⊆ scope(W)`, `time(W′) ⊆ time(W)`, `budget(W′) ⊆ budget(W)` —
//! intersection, not union, computed at the notary. The chain is recorded on every delegated receipt, and
//! any link's revocation voids everything below it.
//!
//! ## Why this component exists
//!
//! Today a grant is one static scope; there is no delegable authority. The catalogue's agent-economy loop
//! (L5) and multi-org verification (B-4) both need the same primitive: authority that flows down a chain
//! and *narrows* as it goes, so a team-lead's "write GitHub, $500/mo" can delegate to an agent's "write
//! one repo, $50/mo" and onward to a sub-agent's "one branch, $5, 2 hours" — with the sub-agent's every
//! receipt carrying the three-deep chain, and the team-lead's revocation voiding the sub-agent's staged
//! actions at the next bind. The kill-switch already revokes credential-vault bindings; this generalizes
//! that to warrant lineage.
//!
//! ## What it does
//!
//! [`intersection`](rust/delegation-chain/src/lib.rs) computes the effective child scope from a parent and a request, refusing any
//! widening ([`Escalation`](rust/delegation-chain/src/lib.rs)). [`WarrantStore`] holds warrants with parent links; [`delegate`](WarrantStore::delegate) issues a narrowed
//! child, [`chain_of`](WarrantStore::chain_of) walks a warrant's ancestors to the root, [`revoke`](WarrantStore::revoke) voids a link, and
//! [`is_valid`](WarrantStore::is_valid) reports whether a warrant stands — false if it *or any ancestor* was revoked, which is the
//! "revocation voids everything below" rule.
//!
//! ## What it does NOT do
//!
//! It does not evaluate a live action — the notary consults `is_valid` and the effective scope at bind
//! time. It does not sign warrants — digests are content fingerprints. It does not perform the revocation
//! fan-out to runtime surfaces — that is `rust/revocation-verbs` (M8); this is the *lineage* semantics
//! that tells the revocation what to void.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// The governed shape of a warrant: what it authorizes, until when, and up to what spend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarrantScope {
    /// Capabilities conferred.
    pub capabilities: Vec<String>,
    /// Resource classes the grant applies to.
    pub resource_classes: Vec<String>,
    /// Absolute expiry, in milliseconds since an arbitrary epoch.
    pub expires_at_ms: u64,
    /// Spend ceiling in micro-dollars.
    pub budget_micros: u64,
}

/// A way a delegation request tried to widen beyond its parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Escalation {
    /// A requested capability the parent does not have.
    Capability(String),
    /// A requested resource class the parent does not have.
    Resource(String),
    /// A requested expiry later than the parent's.
    Time,
    /// A requested budget above the parent's.
    Budget,
}

/// A warrant in the lineage: its scope, its issuer, and its parent (if delegated).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warrant {
    /// Unique warrant id.
    pub id: String,
    /// The effective (already-narrowed) scope.
    pub scope: WarrantScope,
    /// The warrant this was issued from, if any.
    pub parent: Option<String>,
    /// `sha256:` digest over the canonical JSON of `(id, scope, parent)`.
    pub digest: String,
}

impl Warrant {
    fn compute_digest(id: &str, scope: &WarrantScope, parent: &Option<String>) -> String {
        let payload = serde_json::json!({ "id": id, "scope": scope, "parent": parent });
        let canonical = serde_json::to_string(&payload).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

/// Whether a parent resource class covers a child request: exact match, or a `prefix/*` wildcard that
/// the child falls under.
fn resource_covers(parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    if let Some(prefix) = parent.strip_suffix('*') {
        return child.starts_with(prefix);
    }
    false
}

/// Compute the intersection of a parent scope and a requested child scope.
///
/// The child may only narrow: every requested capability and resource must exist in the parent (a parent
/// `prefix/*` resource covers any child under that prefix), and the requested time and budget must not
/// exceed the parent's. Any widening is an [`Escalation`].
pub fn intersection(
    parent: &WarrantScope,
    requested: &WarrantScope,
) -> Result<WarrantScope, Escalation> {
    for cap in &requested.capabilities {
        if !parent.capabilities.contains(cap) {
            return Err(Escalation::Capability(cap.clone()));
        }
    }
    for res in &requested.resource_classes {
        if !parent
            .resource_classes
            .iter()
            .any(|p| resource_covers(p, res))
        {
            return Err(Escalation::Resource(res.clone()));
        }
    }
    if requested.expires_at_ms > parent.expires_at_ms {
        return Err(Escalation::Time);
    }
    if requested.budget_micros > parent.budget_micros {
        return Err(Escalation::Budget);
    }
    Ok(requested.clone())
}

/// A store of warrants with parent links and revocation state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarrantStore {
    warrants: HashMap<String, Warrant>,
    revoked: HashSet<String>,
}

impl WarrantStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> WarrantStore {
        WarrantStore::default()
    }

    /// Issue a root warrant (no parent).
    pub fn issue_root(&mut self, id: &str, scope: WarrantScope) -> Warrant {
        let digest = Warrant::compute_digest(id, &scope, &None);
        let w = Warrant {
            id: id.into(),
            scope,
            parent: None,
            digest,
        };
        self.warrants.insert(id.into(), w.clone());
        w
    }

    /// Delegate a child warrant from `parent_id`, narrowing to `requested`. Fails if the parent is
    /// unknown or revoked, or the request escalates beyond the parent's effective scope.
    pub fn delegate(
        &mut self,
        parent_id: &str,
        child_id: &str,
        requested: &WarrantScope,
    ) -> Result<Warrant, DelegateError> {
        let parent = self
            .warrants
            .get(parent_id)
            .ok_or_else(|| DelegateError::UnknownParent(parent_id.into()))?;
        if self.is_revoked_lineage(parent_id) {
            return Err(DelegateError::ParentRevoked(parent_id.into()));
        }
        let scope = intersection(&parent.scope, requested).map_err(DelegateError::Escalated)?;
        let digest = Warrant::compute_digest(child_id, &scope, &Some(parent_id.into()));
        let w = Warrant {
            id: child_id.into(),
            scope,
            parent: Some(parent_id.into()),
            digest,
        };
        self.warrants.insert(child_id.into(), w.clone());
        Ok(w)
    }

    /// The chain of warrants from `id` up to the root, root first.
    #[must_use]
    pub fn chain_of(&self, id: &str) -> Vec<Warrant> {
        let mut chain = Vec::new();
        let mut current = self.warrants.get(id);
        while let Some(w) = current {
            chain.push(w.clone());
            current = w.parent.as_ref().and_then(|p| self.warrants.get(p));
        }
        chain.reverse();
        chain
    }

    /// Revoke a warrant; everything delegated below it becomes invalid.
    pub fn revoke(&mut self, id: &str) {
        self.revoked.insert(id.to_string());
    }

    /// Whether a warrant is directly revoked.
    #[must_use]
    pub fn is_revoked_lineage(&self, id: &str) -> bool {
        self.revoked.contains(id)
    }

    /// Whether a warrant stands: it exists, is not revoked, and no ancestor is revoked — the
    /// "revocation voids everything below" rule.
    #[must_use]
    pub fn is_valid(&self, id: &str) -> bool {
        self.chain_of(id)
            .iter()
            .all(|w| !self.revoked.contains(&w.id))
    }

    /// The effective scope of a warrant, if it stands.
    #[must_use]
    pub fn effective_scope(&self, id: &str) -> Option<&WarrantScope> {
        if self.is_valid(id) {
            self.warrants.get(id).map(|w| &w.scope)
        } else {
            None
        }
    }
}

/// Why a delegation failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegateError {
    /// The named parent warrant does not exist.
    UnknownParent(String),
    /// The parent (or an ancestor) is revoked, so it cannot delegate.
    ParentRevoked(String),
    /// The request widened beyond the parent's scope.
    Escalated(Escalation),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(caps: &[&str], res: &[&str], expires: u64, budget: u64) -> WarrantScope {
        WarrantScope {
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
            resource_classes: res.iter().map(|s| s.to_string()).collect(),
            expires_at_ms: expires,
            budget_micros: budget,
        }
    }

    fn team_lead() -> WarrantScope {
        scope(&["github:write"], &["repo:acme/*"], 1_000_000, 500_000_000)
    }

    #[test]
    fn intersection_allows_narrowing() {
        let child = intersection(
            &team_lead(),
            &scope(&["github:write"], &["repo:acme/api"], 500_000, 50_000_000),
        );
        assert!(child.is_ok());
        assert_eq!(child.unwrap().budget_micros, 50_000_000);
    }

    #[test]
    fn intersection_refuses_capability_escalation() {
        let e = intersection(&team_lead(), &scope(&["github:admin"], &[], 100, 100));
        assert_eq!(e, Err(Escalation::Capability("github:admin".into())));
    }

    #[test]
    fn intersection_refuses_resource_escalation() {
        let e = intersection(&team_lead(), &scope(&[], &["repo:other/*"], 100, 100));
        assert_eq!(e, Err(Escalation::Resource("repo:other/*".into())));
    }

    #[test]
    fn intersection_refuses_time_escalation() {
        let e = intersection(&team_lead(), &scope(&[], &[], 2_000_000, 100));
        assert_eq!(e, Err(Escalation::Time));
    }

    #[test]
    fn intersection_refuses_budget_escalation() {
        let e = intersection(&team_lead(), &scope(&[], &[], 100, 999_999_999));
        assert_eq!(e, Err(Escalation::Budget));
    }

    #[test]
    fn three_deep_chain_narrows_each_level() {
        let mut s = WarrantStore::new();
        s.issue_root("tl", team_lead());
        s.delegate(
            "tl",
            "agent",
            &scope(&["github:write"], &["repo:acme/api"], 500_000, 50_000_000),
        )
        .unwrap();
        s.delegate(
            "agent",
            "sub",
            &scope(&["github:write"], &["repo:acme/api"], 100_000, 5_000_000),
        )
        .unwrap();
        let chain = s.chain_of("sub");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].id, "tl");
        assert_eq!(chain[2].scope.budget_micros, 5_000_000);
    }

    #[test]
    fn revoking_root_voids_all_below() {
        let mut s = WarrantStore::new();
        s.issue_root("tl", team_lead());
        s.delegate(
            "tl",
            "agent",
            &scope(&["github:write"], &["repo:acme/api"], 500_000, 50_000_000),
        )
        .unwrap();
        s.delegate(
            "agent",
            "sub",
            &scope(&["github:write"], &["repo:acme/api"], 100_000, 5_000_000),
        )
        .unwrap();
        assert!(s.is_valid("sub"));
        s.revoke("tl");
        assert!(!s.is_valid("sub"));
        assert!(!s.is_valid("agent"));
        assert!(s.effective_scope("sub").is_none());
    }

    #[test]
    fn revoking_middle_voids_below_not_above() {
        let mut s = WarrantStore::new();
        s.issue_root("tl", team_lead());
        s.delegate(
            "tl",
            "agent",
            &scope(&["github:write"], &["repo:acme/api"], 500_000, 50_000_000),
        )
        .unwrap();
        s.delegate(
            "agent",
            "sub",
            &scope(&["github:write"], &["repo:acme/api"], 100_000, 5_000_000),
        )
        .unwrap();
        s.revoke("agent");
        assert!(s.is_valid("tl"));
        assert!(!s.is_valid("sub"));
    }

    #[test]
    fn delegate_from_unknown_parent_fails() {
        let mut s = WarrantStore::new();
        let e = s.delegate("ghost", "x", &scope(&[], &[], 1, 1));
        assert_eq!(e, Err(DelegateError::UnknownParent("ghost".into())));
    }

    #[test]
    fn delegate_from_revoked_parent_fails() {
        let mut s = WarrantStore::new();
        s.issue_root("tl", team_lead());
        s.revoke("tl");
        let e = s.delegate("tl", "agent", &scope(&["github:write"], &[], 100, 100));
        assert_eq!(e, Err(DelegateError::ParentRevoked("tl".into())));
    }

    #[test]
    fn delegate_escalation_is_refused() {
        let mut s = WarrantStore::new();
        s.issue_root("tl", team_lead());
        let e = s.delegate("tl", "agent", &scope(&["github:admin"], &[], 100, 100));
        assert!(matches!(
            e,
            Err(DelegateError::Escalated(Escalation::Capability(_)))
        ));
    }

    #[test]
    fn warrant_digest_is_deterministic() {
        let mut a = WarrantStore::new();
        let mut b = WarrantStore::new();
        let wa = a.issue_root("tl", team_lead());
        let wb = b.issue_root("tl", team_lead());
        assert_eq!(wa.digest, wb.digest);
        assert!(wa.digest.starts_with("sha256:"));
    }

    #[test]
    fn chain_records_full_ancestor_lineage() {
        let mut s = WarrantStore::new();
        s.issue_root("tl", team_lead());
        s.delegate(
            "tl",
            "agent",
            &scope(&["github:write"], &["repo:acme/api"], 500_000, 50_000_000),
        )
        .unwrap();
        let ids: Vec<String> = s.chain_of("agent").iter().map(|w| w.id.clone()).collect();
        assert_eq!(ids, vec!["tl".to_string(), "agent".to_string()]);
    }

    #[test]
    fn root_warrant_has_no_parent() {
        let mut s = WarrantStore::new();
        let w = s.issue_root("tl", team_lead());
        assert!(w.parent.is_none());
        assert!(s.is_valid("tl"));
    }

    #[test]
    fn effective_scope_present_when_valid() {
        let mut s = WarrantStore::new();
        s.issue_root("tl", team_lead());
        assert_eq!(s.effective_scope("tl").unwrap().budget_micros, 500_000_000);
    }

    #[test]
    fn sibling_branches_independent() {
        let mut s = WarrantStore::new();
        s.issue_root("tl", team_lead());
        s.delegate(
            "tl",
            "a1",
            &scope(&["github:write"], &["repo:acme/x"], 500_000, 100),
        )
        .unwrap();
        s.delegate(
            "tl",
            "a2",
            &scope(&["github:write"], &["repo:acme/y"], 500_000, 100),
        )
        .unwrap();
        s.revoke("a1");
        assert!(!s.is_valid("a1"));
        assert!(s.is_valid("a2"));
    }
}
