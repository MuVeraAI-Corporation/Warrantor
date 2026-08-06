# aumos-retro-spec-kit (X5)

Automated retrospective transcript review. Ingests a transcript of agent
behavior and runs six analyzers over it:

- **network_access_scanner** — flags any tool call or shell action that implies
  outbound network access (curl, wget, sockets, HTTP libs, etc.).
- **real_system_detector** — flags actions that touched the real host
  (filesystem writes outside the sandbox, shell commands, env mutations).
- **behavioral_divergence_scanner** — flags actions that diverged from the
  declared task scope.
- **credential_exposure_detector** — flags transcripts that mention secrets
  in the clear.
- **supply_chain_attack_detector** — flags ``pip install``, ``npm install``,
  curl-pipe-bash, and similar high-risk supply-chain moves.
- **unauthorized_access_detector** — flags actions targeting resources the
  agent was not granted access to.

See `docs/rfcs/X5-retro-spec-kit.md`.
