"""Recipe 1 — Your first verified receipt in 60 seconds.

The Warrantor quickstart: create a client, authorize an action, get a signed pre_commit receipt,
attest the outcome, and verify the chain independently.

    pip install warrantor
    python 01_first_receipt.py
"""

from __future__ import annotations

import warrantor


def main() -> None:
    # 1. Create a Warrantor client (generates an Ed25519 keypair for you).
    client = warrantor.Client()

    # 2. Authorize an action — the 9-gate verdict runs, and a pre_commit receipt is signed.
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/hello-bot",
        actor_capabilities=["read"],
        operation_capabilities=["read"],
        consequence_tier="routine",
        scope="demo",
        operation_class="greet",
    )
    print(f"Verdict: {result.verdict}")
    print(f"Receipt ID: {result.receipt['predicate']['binding']['receipt_id']}")

    # 3. Attest the outcome — the post_commit receipt chains to the pre_commit.
    post = client.attest(result.receipt, outcome_status="success", outcome_digest="sha256:hello-world")
    print(f"Post-commit phase: {post['predicate']['binding']['phase']}")

    # 4. Verify the chain independently — any third party can do this.
    warrantor.verify_chain(result.receipt, post)
    print("✓ Evidence chain verified independently — no privileged access needed.")


if __name__ == "__main__":
    main()
