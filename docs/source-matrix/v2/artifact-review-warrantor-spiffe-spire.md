# Warrantor SPIFFE/SPIRE artifact review

Status: current deployment rejected; server configuration failure reproduced  
Reviewed: 2026-08-30  
Local surface: `deploy/spire/` and `deploy/helm/aumos/`  
Claim adjudication: `CLM-0018` — contradicted, high confidence  
Pinned local SPIRE version: 1.10.0  
Current observed upstream release: [v1.15.3](https://github.com/spiffe/spire/releases/tag/v1.15.3), 2026-08-21

## Executive decision

**Adopt SPIFFE; consume a supported SPIRE topology; reject the current manifests.** SPIFFE is the
correct standard for workload identity and federation beneath Warrantor. The local server
configuration does not validate with the official pinned binary, and several later deployment
stages cannot work as declared. The Helm switch neither mounts the SPIRE socket nor provides an
mTLS data plane.

Keep mTLS disabled in released profiles until a corrected upstream-based deployment passes a
clean-cluster acceptance suite. Delete or quarantine the current manifests so users cannot mistake
them for a supported secure configuration.

## Reproduced validation

The `server.conf` content embedded in `deploy/spire/spire-server.yaml` was extracted without
changing the repository and passed to the official SPIRE 1.10.0 `spire-server validate` command.

Result:

```text
Unknown configuration detected keys="bundle_endpoint,default_svid_ttl" section=server
```

After removing only those two keys in a temporary copy, the syntax validator accepted the remaining
server configuration. That second result narrows the deterministic syntax failure; it does not
validate Kubernetes identities, tokens, CRDs, workload registration, credential issuance or mTLS.

The agent configuration reached syntax validation after substituting an available certificate file
for the absent bootstrap bundle. Runtime token, audience, attestation and topology defects remain.

## Deployment findings

| ID | Severity | Evidence | Consequence |
|---|---|---|---|
| SP-01 | Critical | `bundle_endpoint` and `default_svid_ttl` rejected by official 1.10.0 validator | SPIRE server cannot start with shipped configuration |
| SP-02 | High | Federation endpoint is not nested under the supported server federation configuration/profile | Declared bundle service is not configured as intended |
| SP-03 | High | `service_account_whitelist` differs from documented `service_account_allow_list` | k8s_psat server plugin cannot apply intended enrollment restriction |
| SP-04 | High | projected path is `psat-token`; agent default expects `spire-agent` and no `token_path` is set | Node attestation cannot find the token |
| SP-05 | High | projected audience is `spire:spire-server`; default server audience is `spire-server` and no override is set | Token audience validation fails |
| SP-06 | High | static parent ID ends at cluster name while actual k8s_psat agent IDs include node/pod UID | Workload entries do not descend from real attested agent IDs |
| SP-07 | High | `SPIFFEEntry` and `SPIFFEBundleEndpoint` are not official controller-manager kinds | Kubernetes rejects resources or no controller reconciles them |
| SP-08 | High | workloads do not define matching service accounts/`serviceAccountName` | selectors such as `k8s:sa:trust-core` do not match pods |
| SP-09 | Critical | DaemonSet init container runs long-lived `spire-agent run` | init never finishes; real agent container never starts |
| SP-10 | High | that init container lacks config, bundle and projected-token mounts | it fails or blocks before intended preparation |
| SP-11 | Critical | Helm uses `spire-agent:latest`, `/spire/agent.sock`, and no matching socket volume | mutable security image and unreachable Workload API |
| SP-12 | Critical | init fetches an SVID once; no application-native TLS or Envoy/SDS path is defined | no ongoing mutual-TLS handshake or rotation |
| SP-13 | Medium | `skip_kubelet_verification=true` | weakens workload-attestation assurance and is unsuitable as a production default |
| SP-14 | High | one server, SQLite, disk keys and disk upstream CA | no production HA, external key custody or tested recovery |

The official SPIRE controller manager uses resources such as
[`ClusterSPIFFEID`](https://github.com/spiffe/spire-controller-manager/blob/main/docs/clusterspiffeid-crd.md),
`ClusterStaticEntry` and `ClusterFederatedTrustDomain`. The local resource names must not be treated
as aliases without an actual CRD/controller implementation.

## Fragmented implementation semantics

Warrantor currently contains two different identity stories:

- `go/agent-identity` generates an in-process Ed25519 JWT-like credential described as
  “SPIFFE-style,” with real SPIRE integration deferred and self-signed TLS fallback; and
- `go/identity-bindings` uses the go-spiffe Workload API and separate registration CLI paths.

These are not interchangeable assurance levels. A self-contained SPIFFE-shaped URI and credential
does not become an SVID merely because the subject starts with `spiffe://`.

## SPIFFE ID is not SVID evidence

The reviewed Warrantor schema calls a `workload_id` string an “SVID,” but stores only the stable
SPIFFE ID. The distinction matters:

| Evidence field | Needed meaning |
|---|---|
| `spiffe_id` | Stable asserted workload identity |
| `svid_type` | X.509-SVID or JWT-SVID profile |
| `credential_digest` or certificate serial | Exact credential validated for the event |
| `not_before` / `not_after` | Credential validity interval |
| `trust_domain` and bundle/version digest | Root material used for validation |
| `validation_time` | When the relying party checked it |
| `status_inputs` | CRL/status/bundle-stream state actually consulted |
| `validation_result` | Typed accepted/rejected fact and reason |
| `peer_binding` | How the credential bound to the TLS/session/request |
| `authorization_result_ref` | Separate W4/W6 action decision |

A stored SPIFFE ID alone cannot support “live and unrevoked at issuance.” At most it records who the
producer says it was.

## Required reference topology

1. Pin supported upstream SPIRE Helm/chart and image digests.
2. Deploy an HA server profile with external database and production key manager where required.
3. Use k8s_psat or another attestor with explicit, matching token path, audience, cluster and
   service-account allow list.
4. Deploy agents with the documented socket, complete mounts and no long-running init process.
5. Install the official controller manager and use supported cluster-scoped identity/federation CRDs.
6. Give every Warrantor workload a matching Kubernetes service account and least-privilege selector.
7. Mount the Workload API socket through CSI or another protected supported path.
8. Terminate mTLS in application code using go-spiffe or in a defined Envoy/SDS data plane.
9. Authorize the peer SPIFFE ID and preserve the initiating human/service principal separately.
10. Stream SVID and trust-bundle rotation and record the exact validation evidence in receipts.

## Acceptance suite before enabling mTLS

- clean-cluster install with no hand-created state;
- correct and incorrect node-attestation token path/audience cases;
- positive and negative service-account/namespace/label selector cases;
- unauthorized pod and host process cannot retrieve another workload's SVID;
- live SVID and bundle rotation without connection downtime or stale-cache acceptance;
- expired, removed, wrong-domain and wrong-bundle peer credentials fail closed;
- federated and non-federated trust-domain cases;
- server outage, agent restart, network partition and clock-skew behavior;
- database/key backup, restore and disaster recovery;
- version upgrade and rollback with bundle continuity;
- mTLS handshake capture proving both peers authenticated and authorized; and
- receipt evidence showing the exact credential/bundle/policy validation, not only the SPIFFE ID.

## Options and recommendation

| Option | Benefits | Costs/risks | Standing |
|---|---|---|---|
| Upstream SPIRE Helm + controller manager + native go-spiffe | Best standards alignment; avoids bespoke control plane | Integration and HA operations still substantial | **Preferred** |
| SPIRE + Envoy/SDS data plane | Centralizes TLS behavior across languages | Sidecar/mesh complexity and peer-policy testing | Pilot where native support is uneven |
| Managed SPIFFE-compatible identity | Operational support and faster enterprise adoption | Vendor, residency, metadata and portability diligence | Valid enterprise option |
| Enterprise PKI interim profile | Simpler first release | Less workload-native rotation/federation; migration cost | Honest interim option |
| Repair current bespoke manifests incrementally | Preserves existing files | Too many interacting defects and weak provenance | Reject |

## Evidence limitations

No Kubernetes cluster, Helm, kubectl or container runtime was available. The server validator result
is executed evidence; the token, parent, CRD, mount, init and data-plane findings are contract-level
static evidence. A live cluster reproduction remains mandatory after replacement and must not be
described as already completed.

