"""Recipe 3 — Add a per-agent spend cap.

Every action the agent takes is checked against an autonomy budget. When the budget is exhausted,
the action is denied with a receipted reason — the "$10k overnight runaway loop" is stopped at the
budget gate, not discovered on the invoice.

Uses the W9 spend engine: per-agent USD caps + per-task token budgets + cost-aware routing.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _pkg in ("warrantor_spend",):
    _src = os.path.join(_ROOT, "..", "aumos", "python", _pkg, "src")
    # In the monorepo, the Rust crate is the source of truth; for this example we demonstrate
    # the budget logic inline (it's integer arithmetic, not crypto).
    pass

# Inline the W9 budget logic for a self-contained example (the Rust crate is the authoritative impl).
MICROS_PER_DOLLAR = 1_000_000


class AgentBudget:
    """Per-agent USD budget in micros (millionths of a dollar)."""

    def __init__(self, cap_micros: int) -> None:
        self.cap = cap_micros
        self.spent = 0

    def remaining(self) -> int:
        return self.cap - self.spent

    def charge(self, cost: int) -> bool:
        if self.spent + cost > self.cap:
            return False
        self.spent += cost
        return True


def main() -> None:
    # Set a $0.01 cap (10,000 micros) — enough for a few cheap calls.
    budget = AgentBudget(cap_micros=10_000)
    print(f"Agent budget: ${budget.cap / MICROS_PER_DOLLAR:.4f}")

    # Each action costs some micros (e.g. $0.0025 per 1k input tokens on gpt-4o).
    action_cost = 2500  # $0.0025

    for i in range(10):
        if budget.charge(action_cost):
            print(f"  Action {i + 1}: charged ${action_cost / MICROS_PER_DOLLAR:.5f} — remaining: ${budget.remaining() / MICROS_PER_DOLLAR:.5f}")
        else:
            print(f"  Action {i + 1}: DENY — spend cap exceeded (cap: ${budget.cap / MICROS_PER_DOLLAR:.4f}, spent: ${budget.spent / MICROS_PER_DOLLAR:.4f})")
            print("✓ The runaway loop was stopped at the budget gate.")
            break


if __name__ == "__main__":
    main()
