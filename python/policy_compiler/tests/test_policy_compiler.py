"""Tests for policy-compiler: parser, emitters, intent translation, driver."""

from __future__ import annotations

import pytest

from policy_compiler import (
    CedarPolicyEmitter,
    Effect,
    OpenShellEmitter,
    PolicyCompiler,
    RegoPolicyEmitter,
    RuleParseError,
    parse_rule,
    parse_rules,
    translate_intent,
)


# ---------- parser ----------
def test_parse_simple_allow_rule() -> None:
    r = parse_rule("allow tool:read on /sandbox/x")
    assert r.effect == Effect.ALLOW
    assert r.action == "tool:read"
    assert r.resource == "/sandbox/x"
    assert not r.conditional


def test_parse_deny_with_condition() -> None:
    r = parse_rule("deny tool:write on /etc/* when clearance >= 3")
    assert r.effect == Effect.DENY
    assert r.resource == "/etc/*"
    assert r.conditional
    assert r.attribute == "clearance"
    assert r.op == ">="
    assert r.value == "3"


def test_parse_rule_when_always_is_unconditional() -> None:
    r = parse_rule("deny tool:net on external/* when always")
    assert not r.conditional


def test_parse_rule_rejects_malformed() -> None:
    with pytest.raises(RuleParseError):
        parse_rule("this is not a rule")


def test_parse_rule_rejects_bad_operator() -> None:
    with pytest.raises(RuleParseError):
        parse_rule("allow tool:read on r when clearance ~= 3")


def test_parse_rules_skips_blank_and_comments() -> None:
    text = """\
# comment line

allow tool:read on x
deny tool:write on y when always
"""
    rules = parse_rules(text)
    assert len(rules) == 2
    assert rules[1].effect == Effect.DENY


# ---------- intent translation ----------
def test_translate_intent_known_phrase() -> None:
    rules = translate_intent("we want to deny all egress from this account")
    assert len(rules) == 1
    assert rules[0].effect == Effect.DENY


def test_translate_intent_unknown_returns_empty() -> None:
    assert translate_intent("make me a sandwich") == []


# ---------- Rego emitter ----------
def test_rego_emitter_produces_default_deny() -> None:
    out = RegoPolicyEmitter().emit([])
    assert "default allow = false" in out
    assert "package aumos.policy" in out


def test_rego_emitter_emits_allow_block() -> None:
    rules = [parse_rule("allow tool:read on /sandbox/* when clearance >= 3")]
    out = RegoPolicyEmitter().emit(rules)
    assert "allow {" in out
    assert 'startsWith(input.resource, "/sandbox/")' in out
    assert "input.identity.attributes.clearance >= 3" in out


def test_rego_emitter_emits_deny_override() -> None:
    rules = [parse_rule("deny tool:write on /etc/* when always")]
    out = RegoPolicyEmitter().emit(rules)
    assert "deny {" in out
    assert "not deny" in out


# ---------- Cedar emitter ----------
def test_cedar_emitter_uses_permit_for_allow() -> None:
    rules = [parse_rule("allow tool:read on /sandbox/* when clearance >= 3")]
    out = CedarPolicyEmitter().emit(rules)
    assert "permit (" in out
    assert "principal is Agent" in out
    assert 'resource like "/sandbox/*"' in out
    assert 'principal.attrs["clearance"] >= 3' in out


def test_cedar_emitter_uses_forbid_for_deny_and_unconditional() -> None:
    rules = [parse_rule("deny tool:net on external/* when always")]
    out = CedarPolicyEmitter().emit(rules)
    assert "forbid (" in out
    assert "when" not in out


# ---------- OpenShell emitter ----------
def test_openshell_emitter_serializes_rules() -> None:
    rules = [
        parse_rule("allow tool:read on /sandbox/* when clearance >= 3"),
        parse_rule("deny tool:net on external/* when always"),
    ]
    out = OpenShellEmitter().emit(rules)
    assert 'version: "1"' in out
    assert "rules:" in out
    assert "effect: allow" in out
    assert "effect: deny" in out
    assert "when: always" in out
    assert 'attribute: "clearance"' in out


# ---------- PolicyCompiler driver ----------
def test_compiler_combines_intent_and_enterprise_rules() -> None:
    policy = PolicyCompiler().compile(
        intent="deny all egress",
        enterprise_rules="allow tool:read on /sandbox/* when clearance >= 3",
    )
    assert len(policy.rules) == 2
    assert "package aumos.policy" in policy.rego
    assert "permit (" in policy.cedar
    assert 'version: "1"' in policy.openshell


def test_compiler_handles_intent_only() -> None:
    policy = PolicyCompiler().compile(intent="require mfa")
    assert len(policy.rules) == 1
    assert policy.rules[0].action == "tool:*"


def test_compiled_policy_to_dict_round_trips() -> None:
    policy = PolicyCompiler().compile(enterprise_rules="allow tool:read on r when always")
    d = policy.to_dict()
    assert d["rego"]
    assert d["cedar"]
    assert d["openshell"]
    assert len(d["rules"]) == 1
