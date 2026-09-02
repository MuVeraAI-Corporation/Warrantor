---
license: other
license_name: research-only-derivative
license_link: LICENSE
base_model: Qwen/Qwen3Guard-Gen-0.6B
library_name: peft
tags:
  - lora
  - guard-model
  - ai-safety
  - negative-result
language:
  - en
---

# guard-lora-t1a-all-modules — a guard adapter that lost an output class

**LoRA adapter on `Qwen/Qwen3Guard-Gen-0.6B`, target modules: all seven.**

The control. Retrains the original configuration and reproduces its collapse to within one item.

Author: **Vikram Jha**, MuVeraAI · ORCID [0009-0004-3959-6099](https://orcid.org/0009-0004-3959-6099) · <vikram@muveraai.com>

## Read this before using it

**This adapter emits only two severity values.** The base model emits three — `Safe`, `Unsafe`, `Controversial`. This one never emits `Controversial`.

| | recall | FPR | `safe` | `unsafe` | `controversial` |
|---|---|---|---|---|---|
| Qwen3Guard-Gen-0.6B (base) | 0.7150 | 0.0854 | 1290 | 863 | **122** |
| **this adapter** | 0.7842 | 0.0589 | 1230 | 1038 | **0** |

*ExpGuardTest, n = 2,275, `num_ctx` 8192, seed 0, greedy. Paired exact-binomial McNemar against the base: 31 items the base caught and this missed, 116 the reverse, p < 0.0001.*

**Consequence for anyone deploying it:** a policy control of the form `Controversial = SAFE` becomes a **silent no-op**. It will read as configured and govern nothing. If your stack has such a lever, this adapter disables it without saying so.

**Recall is not the whole story.** Higher recall here coexists with a lost output class, and for the attention-only arm with a false-positive rate that nearly doubles the base. A model scoring better on the headline metric is not the same instrument.

## Why it was published

It is a **negative result**, and the useful kind. Three arms were trained, varying *only* which projections the adapter touches. All three destroyed the class. Attention-only and MLP-only are disjoint families and each is independently sufficient, so the loss is **not attributable to a module family**. The cause is the training target: the corpus renders the `Safety:` field as a boolean, so ~11,272 gradient updates teach a two-valued field.

- [`guard-lora-t1a-all-modules`](https://huggingface.co/MuVeraAI/guard-lora-t1a-all-modules) — control, all seven
- [`guard-lora-t1b-attention`](https://huggingface.co/MuVeraAI/guard-lora-t1b-attention) — attention only
- [`guard-lora-t1c-mlp`](https://huggingface.co/MuVeraAI/guard-lora-t1c-mlp) — MLP only

Per-item verdicts for every run: [`MuVeraAI/guard-verdicts`](https://huggingface.co/datasets/MuVeraAI/guard-verdicts).

## Training

| | |
|---|---|
| base | `Qwen/Qwen3Guard-Gen-0.6B` (Apache-2.0) |
| method | LoRA, rank 16, alpha 32, one epoch, bf16 |
| target modules | `q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj` |
| corpus | 11,272 rows derived from **ExpGuardMix** (`6rightjade/expguardmix`) |
| hardware | single A100-80GB |

## Licence — research only, and narrower than the base model

The base model is Apache-2.0. **This adapter is not.**

It was trained on data derived from **ExpGuardMix**, whose access gate requires affirming **research-only use** — a restriction narrower than that dataset's own CC-BY-4.0 licence. These weights are a derivative of that data, so the restriction is passed forward rather than dropped:

> **Research and evaluation use only. Not for commercial use.** If you intend to use these weights commercially, obtain your own clearance for ExpGuardMix-derived artifacts first.

The training corpus itself is **not** redistributed here or anywhere else in this release.

## Citation

```bibtex
@misc{jha2026guardlorat1aallmodules,
  author = {Vikram Jha},
  title  = {guard-lora-t1a-all-modules: a guard adapter that lost an output class},
  year   = {2026},
  note   = {ORCID 0009-0004-3959-6099},
  howpublished = {\url{https://huggingface.co/MuVeraAI/guard-lora-t1a-all-modules}}
}
```
