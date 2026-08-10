"""Tests for warrantor_rbac: roles, permissions, grant/revoke, edge cases."""

from __future__ import annotations

import pytest

from warrantor_rbac import (
    ROLE_PERMISSIONS,
    Permission,
    PermissionDenied,
    RBACEngine,
    Role,
)


# ---------------------------------------------------------------------------
# Role / permission matrix
# ---------------------------------------------------------------------------
def test_security_officer_permissions_match_spec() -> None:
    assert ROLE_PERMISSIONS[Role.SECURITY_OFFICER] == frozenset(
        {
            Permission.READ_EVIDENCE,
            Permission.APPROVE_ACTIONS,
            Permission.TRIGGER_KILL_SWITCH,
        }
    )


def test_compliance_officer_permissions_match_spec() -> None:
    assert ROLE_PERMISSIONS[Role.COMPLIANCE_OFFICER] == frozenset(
        {Permission.READ_EVIDENCE, Permission.VIEW_COMPLIANCE}
    )


def test_developer_and_viewer_permissions_match_spec() -> None:
    assert ROLE_PERMISSIONS[Role.DEVELOPER] == frozenset({Permission.READ_EVIDENCE})
    assert ROLE_PERMISSIONS[Role.VIEWER] == frozenset({Permission.VIEW_COMPLIANCE})


# ---------------------------------------------------------------------------
# Grant / check / revoke
# ---------------------------------------------------------------------------
def test_grant_and_check_permission() -> None:
    engine = RBACEngine()
    engine.grant_role("alice", Role.SECURITY_OFFICER)
    assert engine.check_permission("alice", Permission.READ_EVIDENCE)
    assert engine.check_permission("alice", Permission.TRIGGER_KILL_SWITCH)
    # Not granted to security_officer
    assert not engine.check_permission("alice", Permission.MANAGE_POLICIES)


def test_admin_has_all_permissions() -> None:
    engine = RBACEngine()
    engine.grant_role("root", Role.ADMIN)
    for perm in Permission:
        assert engine.check_permission("root", perm), f"admin missing {perm}"


def test_unknown_subject_has_no_permissions() -> None:
    engine = RBACEngine()
    assert not engine.check_permission("nobody", Permission.READ_EVIDENCE)
    assert engine.get_roles("nobody") == []


def test_revoke_removes_permission() -> None:
    engine = RBACEngine()
    engine.grant_role("bob", Role.DEVELOPER)
    assert engine.check_permission("bob", Permission.READ_EVIDENCE)
    assert engine.revoke_role("bob", Role.DEVELOPER) is True
    assert not engine.check_permission("bob", Permission.READ_EVIDENCE)


def test_revoke_unknown_role_returns_false() -> None:
    engine = RBACEngine()
    engine.grant_role("carol", Role.VIEWER)
    # Revoke a role she never had
    assert engine.revoke_role("carol", Role.DEVELOPER) is False
    # Revoke from a subject that doesn't exist
    assert engine.revoke_role("ghost", Role.VIEWER) is False


def test_multiple_roles_union_permissions() -> None:
    engine = RBACEngine()
    engine.grant_role("dave", Role.DEVELOPER)  # READ_EVIDENCE
    engine.grant_role("dave", Role.VIEWER)  # VIEW_COMPLIANCE
    assert engine.check_permission("dave", Permission.READ_EVIDENCE)
    assert engine.check_permission("dave", Permission.VIEW_COMPLIANCE)
    # Still cannot approve actions
    assert not engine.check_permission("dave", Permission.APPROVE_ACTIONS)


def test_grant_role_is_idempotent() -> None:
    engine = RBACEngine()
    engine.grant_role("eve", Role.ADMIN)
    engine.grant_role("eve", Role.ADMIN)
    assert engine.get_roles("eve") == [Role.ADMIN]


def test_revoke_all_roles_clears_subject() -> None:
    engine = RBACEngine()
    engine.grant_role("frank", Role.DEVELOPER)
    engine.revoke_role("frank", Role.DEVELOPER)
    # After the last role is revoked the subject should be gone
    assert "frank" not in engine.list_subjects()
    assert engine.get_roles("frank") == []


# ---------------------------------------------------------------------------
# get_roles / get_permissions / require_permission
# ---------------------------------------------------------------------------
def test_get_roles_sorted_deterministically() -> None:
    engine = RBACEngine()
    engine.grant_role("gina", Role.VIEWER)
    engine.grant_role("gina", Role.ADMIN)
    roles = engine.get_roles("gina")
    # Sorted by enum declaration order, not insertion order
    assert roles == [Role.ADMIN, Role.VIEWER]


def test_get_permissions_for_admin_is_full_set() -> None:
    engine = RBACEngine()
    engine.grant_role("heidi", Role.ADMIN)
    assert engine.get_permissions("heidi") == set(Permission)


def test_require_permission_raises_on_denial() -> None:
    engine = RBACEngine()
    engine.grant_role("ivan", Role.VIEWER)
    with pytest.raises(PermissionDenied) as excinfo:
        engine.require_permission("ivan", Permission.TRIGGER_KILL_SWITCH)
    assert excinfo.value.subject == "ivan"
    assert excinfo.value.permission is Permission.TRIGGER_KILL_SWITCH


def test_require_permission_passes_when_allowed() -> None:
    engine = RBACEngine()
    engine.grant_role("judy", Role.SECURITY_OFFICER)
    # Should not raise
    engine.require_permission("judy", Permission.APPROVE_ACTIONS)


# ---------------------------------------------------------------------------
# Defensive validation
# ---------------------------------------------------------------------------
def test_grant_role_rejects_non_enum() -> None:
    engine = RBACEngine()
    with pytest.raises(TypeError):
        engine.grant_role("k", "admin")  # type: ignore[arg-type]


def test_check_permission_rejects_non_enum() -> None:
    engine = RBACEngine()
    with pytest.raises(TypeError):
        engine.check_permission("k", "read_evidence")  # type: ignore[arg-type]


def test_grant_role_rejects_empty_subject() -> None:
    engine = RBACEngine()
    with pytest.raises(ValueError):
        engine.grant_role("", Role.ADMIN)


def test_list_subjects_sorted() -> None:
    engine = RBACEngine()
    engine.grant_role("zoe", Role.VIEWER)
    engine.grant_role("amy", Role.VIEWER)
    assert engine.list_subjects() == ["amy", "zoe"]
