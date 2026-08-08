# AumOS Modal GPU deployments

Real Modal scripts that deploy the AumOS safe-eval pipeline and the adversaria
attack suite against a vLLM-served model on an **A10G GPU** (24 GB). These are
not mocks: the local `python/safe_eval` and `python/adversaria` packages are
installed into the container image and run against a real vLLM engine.

## Prerequisites

1. A Modal account with the `$280` GPU credit applied.
2. The Modal CLI authenticated once:

   ```bash
   pip install modal
   modal token set
   ```

   (`modal token set` opens a browser to generate a token tied to your account.)

## Files

| File                    | What it deploys                                             |
| ----------------------- | ----------------------------------------------------------- |
| `safe_eval_modal.py`    | A10G + vLLM (`facebook/opt-1.3b`) running the safe-eval benchmark pipeline |
| `adversaria_modal.py`   | A10G + vLLM running the 5 adversaria attack generators, reporting success rates per attack type |

Both scripts follow the same shape:

- a CUDA base image with `vllm` + the local AumOS package installed,
- a class-based GPU model server (`@app.cls(gpu="A10G")`) that loads the model
  once per container via `@modal.enter()` so cold starts amortise the weight
  download,
- a remote `@app.function(gpu="A10G")` runner that drives the model in-process
  (no HTTP hop — the benchmark saturates the GPU directly), and
- an `@app.local_entrypoint` so you can `modal run` it from the CLI.

## Deploy / run

### safe-eval

```bash
# Run once locally (spins the container, runs the pipeline, prints JSON to stdout)
modal run deploy/modal/safe_eval_modal.py

# Override the model
modal run deploy/modal/safe_eval_modal.py --model facebook/opt-1.3b

# Deploy as a pinned, callable function (then invoke via the Modal API / web endpoint)
modal deploy deploy/modal/safe_eval_modal.py
```

Output is a JSON document with one entry per benchmark prompt, the aggregated
`PipelineResult`, and a Verifiable Evaluation Bundle (P8 VEB) for cross-language
reproducibility.

### adversaria

```bash
# Run all five attack types against the served model
modal run deploy/modal/adversaria_modal.py

# More prompts per attack type (longer run, tighter confidence on success rates)
modal run deploy/modal/adversaria_modal.py --prompts-per-attack 3
```

Output is a JSON document with:

- `overall_success_rate` — fraction of attacks that succeeded (lower = safer model),
- `success_rate_by_attack_type` — per-type breakdown
  (`prompt_injection`, `jailbreak`, `encoding_attack`,
  `multi_turn_manipulation`, `training_data_extraction`),
- `critical_or_high_count` — successful attacks at HIGH/CRITICAL severity,
- `results` — the full per-prompt result list.

## Configuration

Both scripts read defaults from environment variables (set at deploy time):

| Env var                          | Default               | Meaning                              |
| -------------------------------- | --------------------- | ------------------------------------ |
| `AUMOS_MODAL_MODEL`              | `facebook/opt-1.3b`   | HF model id (must fit the GPU VRAM)  |
| `AUMOS_MODAL_GPU`                | `A10G`                | Any Modal GPU spec (`"L4:1"`, ...)   |
| `AUMOS_MODAL_MAX_TOKENS`         | `64`                  | Max generated tokens per prompt      |
| `AUMOS_MODAL_PROMPTS_PER_ATTACK` | `1`                   | adversaria: prompts per attack type  |

Example — swap in a larger model on a bigger GPU:

```bash
AUMOS_MODAL_MODEL=meta-llama/Llama-3.2-3B AUMOS_MODAL_GPU="A100-40GB:1" \
  modal run deploy/modal/safe_eval_modal.py
```

## Cost notes

- A10G containers bill per second of GPU time. The default `opt-1.3b` cold-start
  + a 4-prompt safe-eval run is well under a dollar.
- `container_idle_timeout=300` keeps the container warm for 5 minutes between
  calls so repeated invocations skip the model load. Drop this to `0` for pure
  serverless (pay only for what you run) at the cost of a cold start every call.
- The `@app.cls` server and the `@app.function` runner are deliberately separate
  so you can `modal deploy` the server once and drive it from many cheap CPU
  clients, or `modal run` the runner for one-shot eval jobs.

## CI integration

Both runners return plain JSON, so they slot into a CI gate:

```bash
result=$(modal run deploy/modal/safe_eval_modal.py --json 2>/dev/null) \
  || exit 1
echo "$result" | jq '.pipeline.ok' | grep -q true || exit 1
```
