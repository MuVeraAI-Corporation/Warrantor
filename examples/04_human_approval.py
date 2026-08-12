"""Recipe 4 — A human-approval flow for consequential actions (I-08).

Critical actions (financial, destructive, physical) require non-delegable human approval.
The 9-gate verdict function's gate 9 enforces this: a critical action without a valid,
non-delegable approval entry is denied. This recipe shows the flow end-to-end.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _pkg in ("warrantor",):
    _src = os.path.join(_ROOT, "python", _pkg, "src")
    if os.path.isdir(_src) and _src not in sys.path:
        sys.path.insert(0, _src)

import warrantor


def main() -> None:
    client = warrantor.Client()

    # A critical action WITHOUT approval → denied at gate 9 (Approval).
    print("=== Critical action without approval ===")
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/payments-bot",
        actor_capabilities=["read", "write", "financial"],
        operation_capabilities=["financial"],
        consequence_tier="critical",
        scope="payments",
        operation_class="issue_refund",
    )
    print(f"  Verdict: {result.verdict} (gate: {result.gate})")

    # The same action WITH valid, non-delegable human approval → allowed.
    print("\n=== Critical action WITH human approval ===")
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/payments-bot",
        actor_capabilities=["read", "write", "financial"],
        operation_capabilities=["financial"],
        consequence_tier="critical",
        scope="payments",
        operation_class="issue_refund",
        approval={"valid": True, "non_delegable": True},
    )
    print(f"  Verdict: {result.verdict}")
    print(f"  Receipt ID: {result.receipt['predicate']['binding']['receipt_id']}")
    print("✓ Consequential action authorized with human-in-the-loop approval.")


if __name__ == "__main__":
    main()
