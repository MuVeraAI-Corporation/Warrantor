//! L6-01 / blueprint proof gate B-02: for all chains and all requested authorities, granted is a
//! subset of every ancestor; and every reachable expansion is refused.
//!
//! Hand-rolled xorshift generator rather than proptest: the crate has no dev-dependencies and a
//! fixed seed makes every failure reproducible from the case index in the assertion message.

use warrantor_evidence::{
    compute_intersection_proof, narrow_chain, recompute_intersection, verify_authority, Authority,
    DelegationLink, EvidenceError,
};

const UNIVERSE: [&str; 6] = ["read", "write", "deploy", "pay", "delete", "actuate"];
const CASES: u64 = 2_000;
const SEED: u64 = 0x9E37_79B9_7F4A_7C15;

struct Xorshift(u64);

impl Xorshift {
    // Not `next`: a method of that name and shape trips `clippy::should_implement_trait`, and the
    // gate denies warnings.
    fn step(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.step() % bound
    }
    fn coin(&mut self) -> bool {
        (self.step() & 1) == 1
    }
}

fn subset_of(rng: &mut Xorshift, pool: &[String]) -> Vec<String> {
    pool.iter().filter(|_| rng.coin()).cloned().collect()
}

struct Generated {
    chain: Vec<DelegationLink>,
    /// `Some(index)` if the generator deliberately widened at that link.
    widened_at: Option<usize>,
}

fn generate(rng: &mut Xorshift, case: u64) -> Generated {
    let universe: Vec<String> = UNIVERSE.iter().map(|s| s.to_string()).collect();
    let depth = 1 + rng.below(6) as usize;
    let mut parent_capabilities = subset_of(rng, &universe);
    let mut parent_not_after = 1_000_000 + rng.below(1_000_000);
    let mut widened_at = None;
    let mut chain = Vec::with_capacity(depth);

    for index in 0..depth {
        let mut capabilities = if index == 0 {
            parent_capabilities.clone()
        } else {
            subset_of(rng, &parent_capabilities)
        };
        let mut not_after = if index == 0 {
            parent_not_after
        } else {
            parent_not_after - rng.below(parent_not_after)
        };

        if index > 0 && widened_at.is_none() && rng.below(8) == 0 {
            let foreign: Vec<String> = universe
                .iter()
                .filter(|c| !parent_capabilities.contains(c))
                .cloned()
                .collect();
            match foreign.first() {
                Some(extra) => capabilities.push(extra.clone()),
                None => not_after = parent_not_after + 1,
            }
            widened_at = Some(index);
        }

        chain.push(DelegationLink {
            issuer: format!("spiffe://issuer-{case}-{index}"),
            subject: format!("spiffe://subject-{case}-{index}"),
            capabilities: capabilities.clone(),
            not_before: 0,
            not_after,
            token_digest: format!("sha256:{case:x}-{index}"),
        });
        parent_capabilities = capabilities;
        parent_not_after = not_after;
    }
    Generated { chain, widened_at }
}

#[test]
fn granted_is_a_subset_of_every_ancestor_and_every_expansion_is_refused() {
    let mut rng = Xorshift(SEED);
    let mut narrowing = 0u64;
    let mut widening = 0u64;

    for case in 0..CASES {
        let Generated { chain, widened_at } = generate(&mut rng, case);

        match widened_at {
            None => {
                narrowing += 1;
                let granted = narrow_chain(&chain)
                    .unwrap_or_else(|e| panic!("case {case}: a narrowing chain was refused: {e}"));

                for (index, link) in chain.iter().enumerate() {
                    assert!(
                        granted.iter().all(|g| link.capabilities.contains(g)),
                        "case {case}: granted {granted:?} is not a subset of ancestor {index} {:?}",
                        link.capabilities
                    );
                }
                assert_eq!(granted, recompute_intersection(&chain), "case {case}");
                let mut sorted = granted.clone();
                sorted.sort();
                sorted.dedup();
                assert_eq!(granted, sorted, "case {case}: not sorted and deduplicated");

                let authority = Authority {
                    effective_capabilities: granted.clone(),
                    intersection_proof: compute_intersection_proof(&chain),
                    chain: chain.clone(),
                };
                verify_authority(&authority).unwrap_or_else(|e| {
                    panic!("case {case}: an honest authority was refused: {e}")
                });

                // Adversarial: claim one capability some ancestor never held.
                for (index, link) in chain.iter().enumerate() {
                    let Some(extra) = UNIVERSE
                        .iter()
                        .find(|c| !link.capabilities.iter().any(|held| held == *c))
                    else {
                        continue;
                    };
                    let mut forged = authority.clone();
                    forged.effective_capabilities.push((*extra).to_string());
                    forged.effective_capabilities.sort();
                    assert!(
                        matches!(verify_authority(&forged), Err(EvidenceError::Authority(_))),
                        "case {case}: claiming {extra} beyond ancestor {index} was not refused"
                    );
                }
            }
            Some(index) => {
                widening += 1;
                match narrow_chain(&chain) {
                    Err(EvidenceError::Authority(message)) => assert!(
                        message.contains(&format!("link {index} ")),
                        "case {case}: refusal must name link {index}: {message}"
                    ),
                    other => panic!("case {case}: a widening chain was not refused: {other:?}"),
                }
                assert!(
                    recompute_intersection(&chain).is_empty(),
                    "case {case}: a widening chain must confer nothing"
                );
                let authority = Authority {
                    effective_capabilities: Vec::new(),
                    intersection_proof: compute_intersection_proof(&chain),
                    chain,
                };
                assert!(
                    matches!(
                        verify_authority(&authority),
                        Err(EvidenceError::Authority(_))
                    ),
                    "case {case}: an empty claim over a widening chain must still be refused"
                );
            }
        }
    }

    assert!(
        narrowing > 1_000,
        "generator produced too few narrowing chains: {narrowing}"
    );
    assert!(
        widening > 100,
        "generator produced too few widening chains: {widening}"
    );
}
