# Warrantor Terraform Provider

Manage Warrantor resources as Infrastructure-as-Code.

## Usage

```hcl
terraform {
  required_providers {
    aumos = {
      source  = "registry.terraform.io/MuVeraAI/warrantor"
      version = "1.0.0"
    }
  }
}

provider "aumos" {
  endpoint     = "http://localhost:8441"
  trust_domain = "muveraai.com"
}

# Install a component
resource "warrantor_component" "trust_core" {
  name    = "trust-core"
  version = "1.0.0"
}

# Issue an agent identity
resource "warrantor_identity" "coding_agent" {
  subject = "spiffe://muveraai.com/agent/coding-1"
}

# Generate a compliance report
data "warrantor_compliance_report" "current" {
  model = "llama-3-8b"
}

output "compliance_report" {
  value = data.warrantor_compliance_report.current.report
}
```

## Resources

- `warrantor_component` — Install and verify an Warrantor component
- `warrantor_identity` — Issue an Warrantor agent identity (SVID)

## Data Sources

- `warrantor_compliance_report` — Generate a compliance report
