# Phase A — blocked on model availability, not on quota

**Status 2026-09-01: cannot proceed as scoped. Nothing has been deployed and
nothing is billing.**

---

## What Phase A was

Serve `Qwen3Guard-Gen-4B` and the 0.6B on Foundry managed compute instead of local
Ollama, so that every published guard figure comes from a **stated, reproducible
serving configuration** rather than from a developer machine that produced 2.86s
process spawns, fork exhaustion and cache corruption in a single day.

The quota is genuinely there: **A100_80GB 8 · H100_80GB 8 · MI300_192GB 8 ·
H200_141GB 8**, all zero-used.

## Why it cannot proceed

**Qwen3Guard is not in the Foundry model catalog.**

| Query | Result |
|---|---|
| `guard` | **0 of 212 models** |
| `qwen` | 29 models — all `Chat completion` / `Embeddings`, source **Hugging Face** |

Foundry does host Hugging Face models on managed compute — `qwen--qwen3.5-4b`,
`qwen--qwen3-0.6b`, `qwen--qwen3.6-27b-fp8` and 26 others. **None of them is a
guard model.** The guard variants (`Qwen3Guard-Gen-4B`, `Qwen3Guard-Gen-0.6B`) are
absent from the catalog entirely.

Deploying `qwen3.5-4b` would give a chat model on an H100, not the classifier every
published figure was measured on. That is not Phase A; it is a different
experiment wearing its name.

---

## The three ways forward

### A. Request the model into the catalog
The catalog offers a request path for missing models. Zero cost, unknown latency,
and it may simply be declined. Worth firing regardless because it costs nothing.

### B. Custom container on managed compute *(the real answer, most work)*
Managed compute can serve a container you build. Package the guard —
vLLM or TGI serving the HF weights — push to a registry, deploy to an A100 or
H100. This gives exactly what Phase A wanted: a pinned, reproducible serving
configuration with a stated `num_ctx`, quantisation and sampling profile, on
hardware that does not fight the desktop compositor.

**Cost shape:** billed per hour while the endpoint exists. Create, measure,
delete. I would want your explicit approval on the SKU and an agreed teardown
before creating anything.

### C. Re-scope Phase A around what is already deployed
The five existing Foundry deployments are at **0% utilisation** with **200M
enqueued batch tokens** unused. Phase B — re-measuring every published figure —
does not actually need the guard on Foundry. It needs:

- the **guard** running somewhere reproducible (local Ollama is acceptable *if*
  the configuration is pinned and stated, which `guard bench` already reports)
- the **judging** at scale, which is exactly what GlobalBatch is for

**This is the cheapest path to the actual goal.** Phase A existed to remove a
measurement hazard; Phase B is what produces the result. Running B first on batch,
while A is unblocked by route A or B, inverts nothing important.

---

## Recommendation

**Do C now, fire A today, and hold B until you approve a SKU and a teardown.**

The reason is the same one that has governed every decision on this branch: the
thing that produces a defensible number is the measurement, and the measurement
does not require the guard to move hosts. It requires the configuration to be
*stated* — which `guard bench` already does — and the sample size to be large,
which the 200M unused batch tokens make free-ish today.

Moving the guard to managed compute is a real improvement and it should still
happen. It is not a prerequisite.

---

## Nothing was created

No endpoint, no deployment, no container, no spend. The Foundry quota is exactly
as found: 32 accelerators across four types, zero used.
