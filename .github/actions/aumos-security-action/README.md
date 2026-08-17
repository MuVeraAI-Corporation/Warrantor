# Warrantor Security Action

Drop-in GitHub Action for secret scanning, SBOM generation, and compliance gating.

## Usage

```yaml
steps:
  - uses: actions/checkout@v7
  - uses: MuVeraAI/aumos/.github/actions/aumos-security-action@v1
    with:
      scan-secrets: true
      generate-sbom: true
      run-compliance: false
      fail-on-secret: true
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-secrets` | `true` | Scan for AWS/GitHub/OpenAI/GitLab/Slack credentials |
| `generate-sbom` | `true` | Generate CycloneDX SBOM (auto-detects Rust/Python/Go/TS) |
| `run-compliance` | `false` | Run `defstack compliance-report` if `.complygate.yml` exists |
| `fail-on-secret` | `true` | Fail the build if secrets are detected |
| `language` | `""` | Override auto-detection for SBOM generation |

## Outputs

| Output | Description |
|--------|-------------|
| `secrets-found` | Number of secrets detected |
| `sbom-path` | Path to the generated SBOM file |

## Secret Patterns Detected

- AWS Access Key IDs (`AKIA...`)
- GitHub PATs (`ghp_...`)
- OpenAI API Keys (`sk-...`)
- GitLab PATs (`glpat-...`)
- Slack Tokens (`xox...`)
