# warrantor-crypto-audit-ai (X4)

AI-assisted cryptanalysis. Three modes:

- **IMPLEMENTATION_AUDIT** — scans source code for weak crypto patterns:
  hardcoded keys, ECB mode, MD5/SHA1, short RSA keys, insecure RNG.
- **ALGORITHM_STRESS_TEST** — runs known-answer and edge-case vectors
  against the project's crypto primitives (AES, RSA, ECC, KDFs).
- **DEPENDENCY_SCAN** — flags known-vulnerable crypto library versions.

See `docs/rfcs/X4-crypto-audit-ai.md`.
