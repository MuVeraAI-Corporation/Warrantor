// Package lightwellbridge implements S9 lightwell-bridge — AI-artifact patch
// distribution extending IBM/Red Hat Lightwell.
//
// Lightwell-bridge bundles four kinds of AI artifacts (model weights, guardrails,
// config changes, runtime updates) into a PatchBundle, attaches a Rollout policy
// (canary / staged / immediate), and tracks which deployment versions are
// affected by which patch via an affected-version graph.
//
// The package is structured so every external interaction (artifact store,
// deployment target, signer) is an interface — the production wiring lives in
// cmd/; the unit tests run fully in-memory with deterministic fakes.
//
// See docs/rfcs/S9-lightwell-bridge.md.
package lightwellbridge
