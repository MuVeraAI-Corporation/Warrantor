# Azure GPU quota — everything is ready, the last step needs your login

**Prepared 2026-09-01. I could not file this; the reason is below and it is not fixable from here.**

---

## What I did, and where it stopped

| step | result |
|---|---|
| Registered `Microsoft.MachineLearningServices` | ✅ **Registered** (you authorized this) |
| Read real GPU quota, now that the provider is registered | ✅ 127 quota rows returned, where before there were 0 |
| Requested A100 quota via the **Quota API** | ❌ **Failed** — `"Request failed."`, no detail |
| Filed a **support ticket** via the Support API | ❌ **`InvalidSupportPlan`** |

⚠️ **The support-ticket API returned HTTP 202 Accepted and then failed asynchronously.** A 202 is a
receipt, not a created ticket; the operation-status endpoint is where the real answer was:

> *"Your support plan type is Developer. To create and update support tickets, and add communication
> operations, you need access to our high tier-support plans."*

**Reads work; writes do not.** Upgrading the support plan costs money, so it was not done.

## The thing that surprised me, and corrects an earlier note

An earlier record said Azure AI Foundry showed **8× A100-80GB, 8× H100-80GB, 8× MI300-192GB all
free** in westus3. **The API does not agree.** With the provider registered, in *both* eastus and
westus3:

| family | limit |
|---|---|
| `standardNCADSA100v4Family` (A100 80GB) | **0** |
| `standardNCADSH100v5Family` (H100 80GB) | **0** |
| `standardNDv5H100Family` | **0** |
| every other A100 / H100 / ND family | **0** |
| `standardNCFamily` (legacy K80-class) | 6 |
| `standardNVFamily` (legacy M60-class) | 6 |

**There is no modern GPU capacity on this subscription today.** The $5,000 credit cannot buy GPU
until this quota is raised, whatever the portal blade displayed in July.

## What you need to do — about two minutes

**Portal quota requests are free on every support plan, including Developer.** That is the path.

1. Azure portal → **Help + support** → **Create a support request**
2. **Issue type:** *Service and subscription limits (quotas)*
3. **Subscription:** `Azure subscription 1` — the only subscription on the account.
   ⚠️ **The subscription ID is redacted from this file**, which lives in a public repository. It is
   not a credential, but it identifies the tenant. Get it with `az account show --query id -o tsv`,
   or just read it off the portal blade.
4. **Quota type:** *Machine Learning Service: Virtual Machine Quota*
   ⚠️ **Not** *Compute-VM (cores-vCPUs)* — that is the raw-VM path and does not grant AML managed
   compute, which is what the experiments would use.
5. **Region:** East US
6. Request these three:

| quota | new limit | what it buys |
|---|---|---|
| `standardNCADSA100v4Family` | **48** dedicated cores | 2 × NC24ads_A100_v4 (2 × A100 80GB) |
| `standardNCADSH100v5Family` | **40** dedicated cores | 1 × NC40ads_H100_v5 (1 × H100 80GB) |
| **Total Low Priority Cores** | **96** | **spot capacity on every GPU family at once** |

⚠️ **The third row was added after this file was first written, and it is the one to keep if you
trim anything.** Each VM family appears twice in the quota list, split by a `type` field rather than
by name: the dedicated row for the A100 reads `0`, but its low-priority row reads `-1`, which is
Azure's convention for *not enforced*. **Every GPU family reads `-1` there.** Low-priority is gated
solely by the one subscription-level aggregate, `TotalLowPriorityCores`, which is `0` — so raising
that single number unlocks spot across A100, H100, H200 and MI300 together. Spot runs far below
pay-as-you-go, and these are interruptible batch jobs with no uptime obligation, which is exactly
the workload it suits.

## Justification text — paste this

> Requesting GPU quota for Azure Machine Learning managed compute in East US. All GPU families
> currently show a dedicated-cores limit of 0 in both eastus and westus3; only the legacy
> standardNCFamily is nonzero, at 6 cores. Total Low Priority Cores is also 0, which blocks spot
> capacity across all families.
>
> Requested, East US:
>   - standardNCADSA100v4Family   48 dedicated cores
>   - standardNCADSH100v5Family   40 dedicated cores
>   - Total Low Priority Cores    96
>
> The quota supports an academic research program measuring the robustness of open-weight safety
> classifiers under quantization, paraphrase and long-context conditions. Work to date has produced
> five papers targeted at USENIX Security, IEEE S&P and ACM/IEEE workshops. Workloads are short,
> batched inference and fine-tuning runs on open-weight models in the 0.6B–9B range. There is no
> persistent service and no production traffic, which is why low-priority capacity suits this work
> well.
>
> The automated Quota API was attempted first and returned only "Request failed." with no detail
> (request submitted 2026-09-01T01:46:20Z), which is why this is being raised as a support request.
> Microsoft.MachineLearningServices and Microsoft.Quota are both registered on the subscription.
>
> Spend is covered by an existing Azure credit. No overage or support-plan upgrade is being
> requested. Happy to reduce the amounts or change region if that assists approval.

## Two things worth knowing before you decide

**Nothing is blocked on this today.** The margin-shrinkage experiment ran on Modal for about **$0.70**,
and every remaining cheap idea is a re-analysis of data already on disk. **Azure matters only for the
scale-dependent work** — the benchmark and the scaling-laws study — which is exactly where the $100
ceiling was the real constraint.

**Ask for less if it stalls.** A single A100 (24 cores) is enough to run everything currently
designed. The 48/40 above buys parallelism, not capability, and a smaller request is likelier to
clear quickly.
