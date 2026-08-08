"""AumOS RBAC Engine — role-based access control for the AAE permission gate.

This is the runtime permission engine behind the AumOS Action Enforcer (AAE).
Every privileged action (approve, install component, trigger kill-switch,
manage tenants, view compliance reports, read signed evidence) must pass
``RBACEngine.check_permission`` before it executes.

Role model (invariant I-04 — least privilege):
  - ADMIN               : every permission
  - SECURITY_OFFICER    : READ_EVIDENCE, APPROVE_ACTIONS, TRIGGER_KILL_SWITCH
  - COMPLIANCE_OFFICER  : READ_EVIDENCE, VIEW_COMPLIANCE
  - DEVELOPER           : READ_EVIDENCE
  - VIEWER              : VIEW_COMPLIANCE

Usage:
    engine = RBACEngine()
    engine.grant_role("alice", Role.ADMIN)
    assert engine.check_permission("alice", Permission.TRIGGER_KILL_SWITCH)
"""

from __future__ import annotations

from collections import defaultdict
from enum import Enum


class Role(str, Enum):
    """AumOS first-class roles. Use ``str`` mixin so values serialise cleanly."""

    ADMIN = "admin"
    SECURITY_OFFICER = "security_officer"
    COMPLIANCE_OFFICER = "compliance_officer"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class Permission(str, Enum):
    """Fine-grained actions that the AAE can gate."""

    READ_EVIDENCE = "read_evidence"
    APPROVE_ACTIONS = "approve_actions"
    MANAGE_POLICIES = "manage_policies"
    TRIGGER_KILL_SWITCH = "trigger_kill_switch"
    VIEW_COMPLIANCE = "view_compliance"
    INSTALL_COMPONENTS = "install_components"
    MANAGE_TENANTS = "manage_tenants"


# Role -> set of permissions granted by that role.
# ADMIN is special-cased in the engine so that adding a new permission to the
# Permission enum automatically grants it to ADMIN without editing this map.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.SECURITY_OFFICER: frozenset(
        {
            Permission.READ_EVIDENCE,
            Permission.APPROVE_ACTIONS,
            Permission.TRIGGER_KILL_SWITCH,
        }
    ),
    Role.COMPLIANCE_OFFICER: frozenset(
        {
            Permission.READ_EVIDENCE,
            Permission.VIEW_COMPLIANCE,
        }
    ),
    Role.DEVELOPER: frozenset({Permission.READ_EVIDENCE}),
    Role.VIEWER: frozenset({Permission.VIEW_COMPLIANCE}),
}

# The set of all permissions defined at import time. ADMIN is granted this set
# dynamically so the engine never needs to be edited when a new permission is
# added — only the ROLE_PERMISSIONS map above.
_ALL_PERMISSIONS: frozenset[Permission] = frozenset(Permission)


class RBACEngine:
    """In-memory RBAC engine.

    The engine is intentionally framework-free: it stores a ``subject -> set[Role]``
    mapping and resolves roles to permissions through ``ROLE_PERMISSIONS``. A
    production deployment can wrap it with a persistent store (Postgres, OPA
    data plane, etc.) by implementing the same surface.
    """

    def __init__(self) -> None:
        # subject id -> set of roles currently granted
        self._subject_roles: dict[str, set[Role]] = defaultdict(set)

    # ------------------------------------------------------------------
    # Granting / revoking
    # ------------------------------------------------------------------
    def grant_role(self, subject: str, role: Role) -> None:
        """Grant ``role`` to ``subject``. Idempotent.

        ``role`` must be a ``Role`` instance to avoid silent typos. Passing a
        raw string is a programmer error and will raise ``TypeError``.
        """
        if not isinstance(role, Role):
            raise TypeError(f"role must be a Role enum, got {type(role).__name__}")
        if not isinstance(subject, str) or not subject:
            raise ValueError("subject must be a non-empty string")
        self._subject_roles[subject].add(role)

    def revoke_role(self, subject: str, role: Role) -> bool:
        """Revoke ``role`` from ``subject``.

        Returns ``True`` if the subject previously held the role, ``False``
        otherwise. Revoking a role the subject never had is a no-op.
        """
        if not isinstance(role, Role):
            raise TypeError(f"role must be a Role enum, got {type(role).__name__}")
        roles = self._subject_roles.get(subject)
        if roles is None or role not in roles:
            return False
        roles.discard(role)
        # Tidy up empty sets so get_roles() == [] for subjects with no roles.
        if not roles:
            self._subject_roles.pop(subject, None)
        return True

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def get_roles(self, subject: str) -> list[Role]:
        """Return the list of roles held by ``subject`` (possibly empty).

        The list is sorted by the Role enum declaration order so output is
        deterministic — important for log lines and tests.
        """
        roles = self._subject_roles.get(subject, set())
        return sorted(roles, key=lambda r: list(Role).index(r))

    def get_permissions(self, subject: str) -> set[Permission]:
        """Return the full set of permissions effective for ``subject``."""
        perms: set[Permission] = set()
        for role in self._subject_roles.get(subject, set()):
            perms |= self._permissions_for_role(role)
        return perms

    def list_subjects(self) -> list[str]:
        """Return all subjects that currently hold at least one role."""
        return sorted(self._subject_roles.keys())

    # ------------------------------------------------------------------
    # Permission checks
    # ------------------------------------------------------------------
    def check_permission(self, subject: str, permission: Permission) -> bool:
        """Return ``True`` iff ``subject`` has been granted ``permission``.

        Resolution is union-based: if any of the subject's roles grants the
        permission, the check passes. A subject with no roles has no
        permissions.
        """
        if not isinstance(permission, Permission):
            raise TypeError(
                f"permission must be a Permission enum, got {type(permission).__name__}"
            )
        for role in self._subject_roles.get(subject, set()):
            if permission in self._permissions_for_role(role):
                return True
        return False

    def require_permission(self, subject: str, permission: Permission) -> None:
        """Raise ``PermissionDenied`` if ``subject`` lacks ``permission``.

        Convenience for call sites that prefer exception-based control flow
        (e.g. inside request handlers).
        """
        if not self.check_permission(subject, permission):
            raise PermissionDenied(subject, permission)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _permissions_for_role(role: Role) -> frozenset[Permission]:
        """Resolve a single role to its permission set, ADMIN-special-cased."""
        if role is Role.ADMIN:
            return _ALL_PERMISSIONS
        return ROLE_PERMISSIONS.get(role, frozenset())


class PermissionDenied(Exception):
    """Raised by ``require_permission`` when a check fails."""

    def __init__(self, subject: str, permission: Permission) -> None:
        self.subject = subject
        self.permission = permission
        super().__init__(
            f"Permission denied: subject {subject!r} lacks {permission.value!r}"
        )


__all__ = [
    "ROLE_PERMISSIONS",
    "Permission",
    "PermissionDenied",
    "RBACEngine",
    "Role",
]
