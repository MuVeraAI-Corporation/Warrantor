# Warrantor Cookbook

Copy-pasteable recipes for the Warrantor platform. Each recipe is ≤100 lines, self-contained, and
runs in CI. Start with **01_first_receipt.py** — it produces a verified evidence chain in 60 seconds.

## Recipes

| # | Recipe | What it shows |
|---|---|---|
| 01 | [`01_first_receipt.py`](01_first_receipt.py) | Your first verified receipt — authorize, attest, verify the chain. |
| 02 | [`02_langchain_agent.py`](02_langchain_agent.py) | Instrument a LangChain agent — one-line callback, every tool call receipted. |
| 03 | [`03_spend_cap.py`](03_spend_cap.py) | Per-agent spend cap — the runaway loop is stopped at the budget gate. |
| 04 | [`04_human_approval.py`](04_human_approval.py) | Human-approval flow — critical actions require non-delegable approval (I-08). |
| 05 | [`05_rag_agent.py`](05_rag_agent.py) | RAG agent with poison detection — chunks scanned before reaching the model. |
| 06 | [`06_computer_use.py`](06_computer_use.py) | Computer-use agent — URL/DOM scoped, kill-switchable, "no internet" in the browser. |

## Run

```bash
python examples/01_first_receipt.py
```

Or run all recipes at once:

```bash
python examples/run_all.py
```

## Test (CI)

Every recipe runs in CI via `pytest examples/` — a broken recipe is a release blocker.
