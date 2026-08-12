# Disaster Recovery & Business Continuity

> How Warrantor services recover from failures, and how we ensure our own operational continuity.

## RTO and RPO Targets

| Component | RTO (Recovery Time) | RPO (Recovery Point) | Rationale |
|-----------|---------------------|----------------------|-----------|
| KillSwitchKit | 30 seconds | 0 (sync replication) | Critical — must be available to stop incidents |
| AgentVault | 1 minute | 0 | Identity must be available |
| CredentialVault | 1 minute | 0 | Credentials must be revocable |
| SentinelTrace | 5 minutes | 1 minute | Monitoring can tolerate brief gap |
| OpenServeKit | 30 seconds | 0 | Serving must be highly available |
| AttestaFlow | 5 minutes | 1 minute | Pipeline orchestration |
| FedCore | 5 minutes | 1 minute | Federated rounds can pause |
| ModelNotary | 1 minute | 0 | Signing must be available |

## High Availability Architecture

All production services run:
- **3+ replicas** across 3 availability zones
- **PodDisruptionBudget** (min available: 2)
- **HorizontalPodAutoscaler** (min 3, max 10)
- **TopologySpreadConstraints** (across zones)
- **Health checks** (readiness + liveness)

## Backup Strategy

| Data Type | Backup Frequency | Retention | Storage |
|-----------|-----------------|-----------|--------|
| Audit logs | Continuous (stream) | 7 years | S3 + Glacier |
| Attestation ledger | Continuous (replication) | Indefinite | Multi-region |
| Model registry | Daily snapshot | 90 days | S3 cross-region |
| Configuration | On change | 30 days | Git (versioned) |
| Secrets | Never backed up (rotated) | N/A | KMS / HSM |

## Disaster Scenarios

### Scenario 1: Single AZ Failure
- **Detection:** Kubernetes node health checks (within 30 seconds)
- **Response:** Traffic rerouted to healthy AZs (automatic)
- **Recovery:** Automatic rescheduling to new nodes

### Scenario 2: Region Failure
- **Detection:** Uptime monitoring (within 1 minute)
- **Response:** Failover to secondary region (DNS update)
- **Recovery:** 5-15 minutes for full cutover
- **Data:** Latest backup restored; RPO depends on data type

### Scenario 3: Data Corruption
- **Detection:** Integrity checks (daily)
- **Response:** Stop writes, identify corruption scope
- **Recovery:** Restore from last known-good backup
- **Post-mortem:** Root cause analysis within 48 hours

### Scenario 4: Security Incident
- **Detection:** SentinelTrace + security monitoring
- **Response:** Activate KillSwitchKit, isolate affected systems
- **Recovery:** Forensic analysis, patch, restore from clean state
- **Communication:** Notify affected customers within 24 hours

### Scenario 5: Supply Chain Attack
- **Detection:** SBOM vulnerability scanning + dependency monitoring
- **Response:** Identify compromised dependency, pin to safe version
- **Recovery:** Rebuild all affected components from clean state
- **Communication:** Public advisory within 24 hours

## Business Continuity

### Founding Team Continuity
- **Bus factor:** Minimum 2 people per critical component
- **Documentation:** Every component has runbooks
- **Cross-training:** Engineers rotate through on-call

### Infrastructure Continuity
- **Multi-cloud:** AWS + GCP (avoid single-cloud dependency)
- **Git mirrors:** GitHub + GitLab (backup)
- **Package registry:** PyPI + crates.io + pkg.go.dev (no single registry)

### Financial Continuity
- **Runway:** Maintain minimum 9 months runway
- **Bridge financing:** Pre-negotiated bridge round
- **Revenue diversification:** Cloud + enterprise + support (no single customer > 30% of revenue)

## DR Testing

- **Monthly:** Tabletop exercise (scenario walkthrough)
- **Quarterly:** Failover test (actual region failover)
- **Annually:** Full disaster simulation (multi-system failure)

## On-Call

- **Primary on-call:** 1 engineer, 1-week rotation
- **Secondary on-call:** 1 engineer, backup for primary
- **Escalation:** Engineering lead → CTO → CEO
- **Alerting:** PagerDuty, response within 15 minutes (critical)

## Communication Plan

| Audience | Channel | SLA |
|----------|---------|-----|
| Customers (critical) | Email + SMS | 1 hour |
| Customers (non-critical) | Status page | 4 hours |
| Public | Status page + Twitter | 4 hours |
| Regulators | Direct contact | Per regulatory requirement |
| Press | Press release | 24 hours |
