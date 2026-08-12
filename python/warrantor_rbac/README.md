# warrantor-rbac

Role-based access control engine for **Warrantor**. This is the runtime permission
engine behind the **Warrantor Action Enforcer (AAE)**. Every privileged action
(approve, install component, trigger kill-switch, manage tenants, view
compliance reports, read signed evidence) must pass
`RBACEngine.check_permission` before it executes.

## Roles

| Role                | Permissions                                                                  |
| ------------------- | ---------------------------------------------------------------------------- |
| `ADMIN`             | **all** permissions (special-cased; new permissions auto-grant to ADMIN)     |
| `SECURITY_OFFICER`  | `READ_EVIDENCE`, `APPROVE_ACTIONS`, `TRIGGER_KILL_SWITCH`                    |
| `COMPLIANCE_OFFICER`| `READ_EVIDENCE`, `VIEW_COMPLIANCE`                                           |
| `DEVELOPER`         | `READ_EVIDENCE`                                                              |
| `VIEWER`            | `VIEW_COMPLIANCE`                                                            |

## Permissions

`READ_EVIDENCE`, `APPROVE_ACTIONS`, `MANAGE_POLICIES`, `TRIGGER_KILL_SWITCH`,
`VIEW_COMPLIANCE`, `INSTALL_COMPONENTS`, `MANAGE_TENANTS`.

## Usage

```python
from warrantor_rbac import RBACEngine, Role, Permission, PermissionDenied

engine = RBACEngine()
engine.grant_role("alice", Role.ADMIN)
assert engine.check_permission("alice", Permission.TRIGGER_KILL_SWITCH)

engine.grant_role("bob", Role.DEVELOPER)
engine.require_permission("bob", Permission.READ_EVIDENCE)   # OK
try:
    engine.require_permission("bob", Permission.APPROVE_ACTIONS)
except PermissionDenied:
    print("bob cannot approve actions")
```

## Design notes

- **Least privilege by default** (Warrantor invariant I-04). A subject with no
  roles has no permissions.
- **Union resolution**: a subject holding several roles gets the union of
  those roles' permissions.
- **ADMIN is dynamic**: it is resolved against `set(Permission)` so a new
  permission added to the enum is automatically available to ADMIN without
  editing the role map.
- The engine is intentionally framework-free. Wire it to a persistent store
  (Postgres, OPA) by re-implementing the same surface.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```
