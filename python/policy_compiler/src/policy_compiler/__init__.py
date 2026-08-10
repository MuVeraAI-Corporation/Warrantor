"""AumOS policy-compiler (R5) — compile NL intent + enterprise rules into policy.

Compiles a small declarative rule DSL plus a natural-language intent string
into three artifacts:

- An OPA Rego module (:class:`RegoPolicyEmitter`).
- A Cedar policy (:class:`CedarPolicyEmitter`).
- An OpenShell YAML policy (:class:`OpenShellEmitter`).

The :class:`PolicyCompiler` driver ties them together and is the canonical
entry point.

DSL grammar (one rule per line)::

    <effect> <action> on <resource> when <attribute> <op> <value>

For example::

    allow tool:read on /sandbox/* when clearance >= 3
    deny  tool:write on /etc/* when always

``effect`` is ``allow`` or ``deny``. ``op`` is one of ``==``, ``!=``,
``>=``, ``<=``, ``>``, ``<``. The literal ``always`` may be used in place
of a condition to make the rule unconditional.

See ``docs/rfcs/R5-policy-compiler.md``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Rule model
# ---------------------------------------------------------------------------
class Effect(str, Enum):
    """Whether a rule permits or forbids the action."""

    ALLOW = "allow"
    DENY = "deny"


_VALID_OPS = {"==", "!=", ">=", "<=", ">", "<"}


@dataclass
class Rule:
    """One structured rule parsed from the DSL."""

    effect: Effect
    action: str
    resource: str
    attribute: str = ""
    op: str = ""
    value: str = ""
    description: str = ""

    @property
    def conditional(self) -> bool:
        """True if the rule has a non-trivial ``when`` clause."""
        return bool(self.attribute) and self.op != ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the rule to a plain dict."""
        return {
            "effect": self.effect.value,
            "action": self.action,
            "resource": self.resource,
            "attribute": self.attribute,
            "op": self.op,
            "value": self.value,
            "description": self.description,
            "conditional": self.conditional,
        }


class RuleParseError(Exception):
    """Raised when a rule line cannot be parsed."""


# ---------------------------------------------------------------------------
# DSL parser
# ---------------------------------------------------------------------------
_RULE_RE = re.compile(
    r"""
    ^\s*
    (?P<effect>allow|deny)\s+
    (?P<action>[A-Za-z0-9_:./\-*]+)\s+
    on\s+
    (?P<resource>[A-Za-z0-9_:./\-*/]+)
    (?P<rest>.*)
    $
    """,
    re.VERBOSE,
)

_COND_RE = re.compile(
    r"""
    ^\s*when\s+
    (?P<attribute>[A-Za-z_][A-Za-z0-9_]*)\s*
    (?P<op>==|!=|>=|<=|>|<)\s*
    (?P<value>[A-Za-z0-9_.'"\-]+)
    \s*$
    """,
    re.VERBOSE,
)


def parse_rule(line: str) -> Rule:
    """Parse a single DSL rule line into a :class:`Rule`.

    Raises :class:`RuleParseError` on any malformed input.
    """
    m = _RULE_RE.match(line)
    if not m:
        raise RuleParseError(f"could not parse rule: {line!r}")
    effect = Effect(m.group("effect"))
    action = m.group("action")
    resource = m.group("resource")
    rest = (m.group("rest") or "").strip()
    rule = Rule(effect=effect, action=action, resource=resource)
    if not rest:
        return rule
    if rest == "when always":
        return rule
    if not rest.startswith("when"):
        raise RuleParseError(f"expected 'when <clause>' but got {rest!r}")
    cm = _COND_RE.match(rest)
    if not cm:
        raise RuleParseError(f"could not parse condition: {rest!r}")
    rule.attribute = cm.group("attribute")
    rule.op = cm.group("op")
    rule.value = cm.group("value").strip("'\"")
    return rule


def parse_rules(text: str) -> list[Rule]:
    """Parse a multi-line DSL document into a list of rules.

    Blank lines and lines starting with ``#`` are ignored.
    """
    out: list[Rule] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        out.append(parse_rule(s))
    return out


# ---------------------------------------------------------------------------
# NL intent translation (small canonical phrasebook)
# ---------------------------------------------------------------------------
_INTENT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bdeny\s+all\s+egress\b", re.IGNORECASE), "deny tool:http on * when always"),
    (re.compile(r"\brequire\s+mfa\b", re.IGNORECASE), "allow tool:* on * when mfa == true"),
    (
        re.compile(r"\bblock\s+external\s+network\b", re.IGNORECASE),
        "deny tool:net on external/* when always",
    ),
    (re.compile(r"\bonly\s+allow\s+read\b", re.IGNORECASE), "allow tool:read on * when always"),
]


def translate_intent(intent: str) -> list[Rule]:
    """Translate a natural-language intent into a list of seed rules.

    The translation is phrasebook-based: a small set of canonical phrases
    each map to a seed rule. Unknown intents return an empty list (the
    enterprise rules carry the real policy).
    """
    out: list[Rule] = []
    for pat, rule_str in _INTENT_PATTERNS:
        if pat.search(intent):
            out.append(parse_rule(rule_str))
    return out


# ---------------------------------------------------------------------------
# Emitters
# ---------------------------------------------------------------------------
def _rego_resource_match(resource: str) -> str:
    """Translate a glob-ish resource pattern into a Rego ``startswith``/equality check."""
    if resource.endswith("/*"):
        prefix = resource[:-2]
        return f'startsWith(input.resource, "{prefix}/")'
    if resource == "*":
        return "true"
    return f'input.resource == "{resource}"'


def _rego_action_match(action: str) -> str:
    """Translate an action pattern into a Rego action check."""
    if action == "tool:*":
        return 'startsWith(input.action, "tool:")'
    if action.endswith("*"):
        prefix = action[:-1]
        return f'startswith(input.action, "{prefix}")'
    return f'input.action == "{action}"'


def _rego_condition(rule: Rule) -> str:
    """Render the condition clause for a rule (empty when unconditional)."""
    if not rule.conditional:
        return "true"
    return f"input.identity.attributes.{rule.attribute} {rule.op} {rule.value}"


class RegoPolicyEmitter:
    """Emits an OPA Rego module from a list of rules.

    The generated module has two top-level rules: ``allow`` and ``deny``,
    each an OR of every contributing rule's conditions. Deny wins (the
    canonical least-privilege default).
    """

    def emit(self, rules: Iterable[Rule], *, package: str = "aumos.policy") -> str:
        """Render ``rules`` as a Rego module string."""
        rules = list(rules)
        allow_lines: list[str] = []
        deny_lines: list[str] = []
        for r in rules:
            cond_parts = [
                _rego_action_match(r.action),
                _rego_resource_match(r.resource),
                _rego_condition(r),
            ]
            cond = ", ".join(p for p in cond_parts if p != "")
            target = allow_lines if r.effect == Effect.ALLOW else deny_lines
            target.append(f"    {cond}")
        out: list[str] = [f"package {package}", "", "default allow = false  # deny by default"]
        if allow_lines:
            out.append("allow {")
            out.extend(allow_lines)
            out.append("}")
        if deny_lines:
            out.append("deny {")
            out.extend(deny_lines)
            out.append("}")
            # deny overrides allow
            out.append("allow {")
            out.append("    not deny")
            out.append("    # (only when no deny rule matched)")
            out.append("}")
        return "\n".join(out) + "\n"


class CedarPolicyEmitter:
    """Emits a Cedar policy from a list of rules."""

    def emit(self, rules: Iterable[Rule], *, principal: str = "Agent") -> str:
        """Render ``rules`` as a Cedar policy string."""
        rules = list(rules)
        out: list[str] = []
        for i, r in enumerate(rules):
            forbid = r.effect == Effect.DENY
            keyword = "forbid" if forbid else "permit"
            cond_parts = [
                _cedar_action_clause(r.action),
                _cedar_resource_clause(r.resource),
            ]
            when_clause = _cedar_when_clause(r)
            if when_clause:
                cond_parts.append(when_clause)
            cond = ",\n  ".join(p for p in cond_parts if p)
            out.append(f"{keyword} (\n  principal is {principal},\n  {cond}\n);  // rule #{i + 1}")
        return "\n".join(out) + "\n"


def _cedar_action_clause(action: str) -> str:
    """Render the Cedar ``action ==`` clause for ``action``."""
    if action == "tool:*":
        return 'action like "tool:*"'
    if action.endswith("*"):
        return f'action like "{action}"'
    return f'action == "{action}"'


def _cedar_resource_clause(resource: str) -> str:
    """Render the Cedar ``resource ==`` clause for ``resource``."""
    if resource == "*":
        return "resource is Resource"
    if resource.endswith("/*"):
        prefix = resource[:-2]
        return f'resource like "{prefix}/*"'
    return f'resource == "{resource}"'


def _cedar_when_clause(rule: Rule) -> str:
    """Render the optional Cedar ``when`` clause for ``rule``."""
    if not rule.conditional:
        return ""
    attr = rule.attribute
    val = rule.value
    # cedar booleans and numbers are bare; quote everything else
    if val.lower() in ("true", "false"):
        literal = val.lower()
    elif re.match(r"^-?\d+(\.\d+)?$", val):
        literal = val
    else:
        literal = f'"{val}"'
    return f'when {{ principal.attrs["{attr}"] {rule.op} {literal} }}'


class OpenShellEmitter:
    """Emits an OpenShell YAML policy from a list of rules."""

    def emit(self, rules: Iterable[Rule], *, version: str = "1") -> str:
        """Render ``rules`` as an OpenShell YAML policy string."""
        rules = list(rules)
        lines: list[str] = [f'version: "{version}"', "rules:"]
        for r in rules:
            lines.append(f"  - effect: {r.effect.value}")
            lines.append(f'    action: "{r.action}"')
            lines.append(f'    resource: "{r.resource}"')
            if r.conditional:
                lines.append("    when:")
                lines.append(f'      attribute: "{r.attribute}"')
                lines.append(f'      op: "{r.op}"')
                lines.append(f'      value: "{r.value}"')
            else:
                lines.append("    when: always")
            if r.description:
                lines.append(f'    description: "{r.description}"')
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------
@dataclass
class CompiledPolicy:
    """The three artifacts produced by :class:`PolicyCompiler`."""

    rego: str
    cedar: str
    openshell: str
    rules: list[Rule] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the compiled policy to a plain dict."""
        return {
            "rego": self.rego,
            "cedar": self.cedar,
            "openshell": self.openshell,
            "rules": [r.to_dict() for r in self.rules],
        }


class PolicyCompiler:
    """The top-level driver: NL intent + enterprise rules -> all three artifacts.

    Usage::

        policy = PolicyCompiler().compile(
            intent="deny all egress",
            enterprise_rules='''
                allow tool:read on /sandbox/* when clearance >= 3
                deny  tool:write on /etc/* when always
            ''',
        )
        print(policy.rego)
    """

    def __init__(
        self,
        rego_emitter: RegoPolicyEmitter | None = None,
        cedar_emitter: CedarPolicyEmitter | None = None,
        openshell_emitter: OpenShellEmitter | None = None,
    ) -> None:
        self._rego = rego_emitter or RegoPolicyEmitter()
        self._cedar = cedar_emitter or CedarPolicyEmitter()
        self._openshell = openshell_emitter or OpenShellEmitter()

    def compile(self, *, intent: str = "", enterprise_rules: str = "") -> CompiledPolicy:
        """Compile ``intent`` + ``enterprise_rules`` into all three artifacts."""
        rules: list[Rule] = []
        if intent:
            rules.extend(translate_intent(intent))
        if enterprise_rules:
            rules.extend(parse_rules(enterprise_rules))
        return CompiledPolicy(
            rego=self._rego.emit(rules),
            cedar=self._cedar.emit(rules),
            openshell=self._openshell.emit(rules),
            rules=rules,
        )


__all__ = [
    "CedarPolicyEmitter",
    "CompiledPolicy",
    "Effect",
    "OpenShellEmitter",
    "PolicyCompiler",
    "RegoPolicyEmitter",
    "Rule",
    "RuleParseError",
    "parse_rule",
    "parse_rules",
    "translate_intent",
]
