# aumos-policy-compiler (R5)

Compiles NL intent + enterprise rules into OpenShell policy + OPA Rego +
Cedar rules.

- **Rule DSL parser** — parses a small declarative DSL into structured
  :class:`Rule` objects.
- **RegoPolicyEmitter** — emits an OPA Rego module from a rule set.
- **CedarPolicyEmitter** — emits a Cedar policy from a rule set.
- **OpenShellEmitter** — emits an OpenShell YAML policy.
- **PolicyCompiler** — top-level driver: NL intent + rules -> all three.

See `docs/rfcs/R5-policy-compiler.md`.
