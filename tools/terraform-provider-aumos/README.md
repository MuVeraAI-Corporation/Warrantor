# AumOS Terraform Provider

Manage AumOS resources as Infrastructure-as-Code.

## Usage

```hcl
terraform {
  required_providers {
    aumos = {
      source  = "registry.terraform.io/MuVeraAI/aumos"
      version = "1.0.0"
    }
  }
}

provider "aumos" {
  endpoint     = "http://localhost:8441"
  trust_domain = "warrantor.dev"
}

# Install a component
resource "aumos_component" "trust_core" {
  name    = "trust-core"
  version = "1.0.0"
}

# Issue an agent identity
resource "aumos_identity" "coding_agent" {
  subject = "spiffe://warrantor.dev/agent/coding-1"
}

# Generate a compliance report
data "aumos_compliance_report" "current" {
  model = "llama-3-8b"
}

output "compliance_report" {
  value = data.aumos_compliance_report.current.report
}
```

## Resources

- `aumos_component` — Install and verify an AumOS component
- `aumos_identity` — Issue an AumOS agent identity (SVID)

## Data Sources

- `aumos_compliance_report` — Generate a compliance report
