---
title: Where Did Controversial Go?
emoji: 🛡️
colorFrom: indigo
colorTo: red
sdk: static
app_file: index.html
pinned: false
license: cc-by-4.0
---

# Where Did `Controversial` Go?

Three LoRA fine-tunes of `Qwen3Guard-Gen-0.6B`, varying **only** which projections the adapter
touches. All three destroyed the model's third severity class, and a recall-only review cannot see it.

Traced on 2,275 measured items from
[`invincible-jha/guard-verdicts`](https://huggingface.co/datasets/invincible-jha/guard-verdicts).

Static by design: the measurements are fixed, so a pre-computed page has no cold start and cannot
drift from the dataset it was built from.

Vikram Jha · MuVeraAI · ORCID 0009-0004-3959-6099
