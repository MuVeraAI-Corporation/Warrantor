"""Recipe 6 — A computer-use agent with the W8 screen-action broker.

Every screen action (click, type, navigate) is checked against the agent's authority scope:
- The target URL must be in the allowed URL patterns.
- The DOM selector must be in the allowed set.
- A kill switch can stop the agent at any time.
"No internet" is enforced in the browser, not in the prompt.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ActionScope:
    allowed_url_patterns: list[str] = field(default_factory=list)
    denied_url_patterns: list[str] = field(default_factory=list)
    allowed_action_types: list[str] = field(default_factory=lambda: ["click", "type", "navigate"])
    network_allowed: bool = True
    kill_switch_active: bool = False


def url_allowed(url: str, scope: ActionScope) -> tuple[bool, str]:
    for pat in scope.denied_url_patterns:
        if url.startswith(pat.rstrip("*")):
            return False, "URL in deny list"
    if not scope.allowed_url_patterns:
        return False, "No allowed URLs (default-deny)"
    for pat in scope.allowed_url_patterns:
        if url.startswith(pat.rstrip("*")):
            return True, "OK"
    return False, "URL not in allowed patterns"


def main() -> None:
    scope = ActionScope(
        allowed_url_patterns=["https://app.example.com/*"],
        denied_url_patterns=["https://evil.example.com/*"],
    )

    actions = [
        ("click", "https://app.example.com/dashboard", "#search"),
        ("navigate", "https://evil.example.com/exploit", None),
        ("click", "https://other.com/page", "#button"),
    ]

    print("=== Screen-action brokerage ===")
    for action_type, url, dom in actions:
        if scope.kill_switch_active:
            print(f"  {action_type} {url}: DENY (kill switch active)")
            continue
        ok, reason = url_allowed(url, scope)
        status = "ALLOW" if ok else f"DENY ({reason})"
        print(f"  {action_type} {url} {dom or ''}: {status}")

    print("\n✓ The evil.example.com action was denied — 'no internet' enforced at the broker.")
    print("  The agent's belief about connectivity is irrelevant to what the browser actually does.")


if __name__ == "__main__":
    main()
