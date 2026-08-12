# Open Source Governance Charter

> How the Warrantor open-source project is governed, licensed, and maintained.

## Governance Model (Phased)

### Phase 1 (M0-M12): BDFL
- **BDFL:** CEO/CTO (founding team)
- **Decision-making:** BDFL decides, with input from maintainers
- **Rationale:** Speed during OSS land grab (Horizon 1)

### Phase 2 (M12-M24): Steering Committee
- **5-7 members:** founding team + key external contributors + 1 OSAF representative
- **Decision-making:** consensus where possible, vote otherwise (2/3 majority)
- **Rationale:** Incorporate community input as adoption grows (Horizon 2)

### Phase 3 (M24+): Foundation Donation
- **Option A:** Donate core libraries to Linux Foundation
- **Option B:** Donate to PyTorch Foundation
- **Option C:** Establish Warrantor Foundation
- **Rationale:** Maximize neutrality and adoption (Horizon 3)

## Roles

| Role | Permissions | How to Get |
|------|-------------|------------|
| **Contributor** | Open PRs, comment on issues | Sign DCO, submit PR |
| **Reviewer** | Review and approve PRs | Consistent quality contributions over 3+ months |
| **Maintainer** | Merge PRs, cut releases | Steering Committee appointment |
| **Steering Committee** | Set direction, approve RFCs | Election (Phase 2+) |

## Licensing

| Component Type | License | Rationale |
|----------------|---------|-----------|
| Core libraries (CudaGram, SafeTensors++, etc.) | Apache 2.0 | Maximum adoption, OSAF-friendly |
| Enterprise features (TenantGuard, FedRAMP package) | BSL 1.1 | Source-available, prevents cloud competition |
| CLI tools (Warrantor CLI, ModelNotary) | Apache 2.0 | Developers expect CLI tools to be open |
| Specifications (OpenHarnessSpec) | CC-BY-4.0 | Standards must be freely reusable |
| Documentation | CC-BY-SA-4.0 | Allows community improvement |
| Reference implementations | Apache 2.0 | Reference code should be maximally adoptable |

### BSL Change Date

BSL-licensed code converts to Apache 2.0 after 4 years (the "change date"). This is the HashiCorp/MongoDB playbook — protects early commercial value but ensures long-term openness.

## DCO and CLA

- **DCO (Developer Certificate of Origin):** Required for all contributions. Sign commits with `git commit -s`.
- **CLA (Contributor License Agreement):** Required for corporate contributors only. Automated via CLA bot.
- **Individual contributors:** DCO only, no CLA.

## IP Review

All contributions undergo IP review:
- Automated: CI checks for license compatibility (via `licensecheck`)
- Manual: Reviewer checks for potential IP issues
- Third-party code: Must be properly attributed and license-compatible

## Trademark

"Warrantor" is a trademark of the founding company. Usage guidelines:
- OSS projects: free to use "Warrantor" in code and docs
- Commercial products: must obtain trademark license
- Derivative works: must use different name (e.g., "Acme Warrantor Fork")

## Release Process

1. Maintainer opens release PR with CHANGELOG
2. CI runs full test suite + security scans
3. Reviewer approves
4. Maintainer cuts tag (signed)
5. CI publishes to package registry
6. GitHub Release created with release notes
7. Announcement (Discord, Twitter, blog)

## Conflict Resolution

1. Technical disputes: RFC discussion → Steering Committee vote
2. Behavioral disputes: Code of Conduct enforcement
3. License disputes: Legal counsel + Steering Committee

## Code of Conduct

We adopt the **Contributor Covenant 2.1**. Enforcement by CoC team (3 volunteers, rotating annually).
