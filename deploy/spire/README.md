# SPIRE mTLS deployment for the AumOS trust domain (`aumos.dev`)

This directory deploys [SPIRE](https://github.com/spiffe/spire) — the reference
implementation of the [SPIFFE](https://spiffe.io/) workload-identity standard —
into a Kubernetes cluster and wires it to the AumOS services defined in
`deploy/helm/aumos/`.

Once SPIRE is running, every AumOS pod (trust-core, inference-proxy,
credential-vault, agent-identity, …) receives an **X.509 SVID** (SPIFFE
Verifiable Identity Document) over the Workload API. Two pods then establish
**mutual TLS** by presenting each other's SVIDs — no static certificates, no
long-lived secrets in `Values.yaml`, no per-service CA.

The trust domain is `aumos.dev`, matching `global.trustDomain` in
`deploy/helm/aumos/values.yaml`.

## Files

| File | Purpose |
|------|---------|
| `spire-server.yaml` | Namespace, RBAC, ConfigMap, Deployment, Service, PVC for the SPIRE **server** (the CA / registration authority). |
| `spire-agent.yaml` | DaemonSet for the SPIRE **agent** that runs on every node and serves the Workload API on `/run/spire/sockets/agent.sock`. |
| `trust-domain-config.yaml` | Trust-domain policy: workload registration entries (`spiffe://aumos.dev/<service>`), federation to `eu.aumos.dev`, and an mTLS-scoped NetworkPolicy. |

## Architecture

```
                       ┌────────────────────────────────────────────┐
                       │              Trust domain: aumos.dev         │
                       └────────────────────────────────────────────┘
                                          │
   ┌─────────────── Workload API ────────┐ │ ┌──── agent gRPC (8081) ────┐
   │                                      │ │                            │
   ▼                                      ▼ ▼                            ▼
 spire-agent (DaemonSet)  ── attest ──►  spire-server  ◄── bundle ── ConfigMap spire-bundle
   │  (NodeAttestor k8s_psat)            (CA, registration)
   │ /run/spire/sockets/agent.sock
   ▼
 AumOS pods (trust-core, inference-proxy, …)  → mTLS to each other using SVIDs
```

## Prerequisites

1. A Kubernetes **1.26+** cluster.
2. The `restricted` Pod Security admission label is set on the `spire` namespace
   (the manifests apply this; on hosted Kubernetes you may need to enable PSS).
3. A **root CA** out of band. `spire-server.yaml` references a Secret
   `spire-server-bootstrap` with `root.crt` / `root.key`. For anything beyond a
   dev cluster use cert-manager, Vault, or AWS Private CA instead of the
   `UpstreamAuthority "disk"` plugin — see the TODO in `server.conf`.

## Deploy

```bash
# 1. Create the bootstrap root CA (dev only — keep this out of git in prod).
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout root.key -out root.crt \
  -subj "/O=AumOS — Open Secure AI Alliance/CN=aumos.dev SPIRE CA"

kubectl create namespace spire
kubectl -n spire create secret generic spire-server-bootstrap \
  --from-file=root.crt --from-file=root.key

# 2. Apply the server, wait for it to be ready.
kubectl apply -f deploy/spire/spire-server.yaml
kubectl -n spire rollout status deploy/spire-server

# 3. Apply the agent DaemonSet.
kubectl apply -f deploy/spire/spire-agent.yaml
kubectl -n spire rollout status daemonset/spire-agent

# 4. Apply trust-domain policy (registration entries + federation).
kubectl apply -f deploy/spire/trust-domain-config.yaml
```

> The `SPIFFEEntry` / `SPIFFEBundleEndpoint` custom resources require the CRDs
> installed by the [SPIRE Helm chart](https://github.com/spiffe/helm-charts-hardened).
> If you don't install the CRDs, use the equivalent `spire-server entry create`
> CLI commands commented in `trust-domain-config.yaml`.

## Wire it to an AumOS service

AumOS services are defined in `deploy/helm/aumos/templates/deployments.yaml`.
Each pod that needs an SVID must (a) mount the agent socket and (b) declare the
matching `SPIFFEEntry`. Example for `trust-core`:

```yaml
# deploy/helm/aumos/templates/deployments.yaml — per-pod changes
spec:
  template:
    spec:
      containers:
        - name: trust-core
          # The mTLS sidecar / library reads SVIDs from the Workload API.
          env:
            - name: SPIFFE_ENDPOINT_SOCKET
              value: unix:///run/spire/sockets/agent.sock
            - name: AUMOS_TRUST_DOMAIN
              value: aumos.dev
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
              readOnly: true
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
            type: Directory
```

Then `verify_model_on_download`-style calls inside `trust-core` can authenticate
peers by their SPIFFE ID (`spiffe://aumos.dev/inference-proxy`) over mTLS.

### Enabling mTLS cluster-wide

In `deploy/helm/aumos/values.yaml`:

```yaml
global:
  mtls:
    enabled: true
    spireServer: spire-server.spire.svc.cluster.local   # default already matches
```

The Helm chart already conditionally injects the `spire-init` initContainer and
`AUMOS_TRUST_DOMAIN` env var when `global.mtls.enabled` is true (see
`templates/deployments.yaml`). Applying the manifests in this directory is what
makes that sidecar succeed.

## Verification

```bash
# Agent fetched its SVID and is healthy?
kubectl -n spire exec daemonset/spire-agent -- \
  /opt/spire/bin/spire-agent api fetch x509 -socketPath /run/spire/sockets/agent.sock

# Trust bundle published to the ConfigMap?
kubectl -n spire get configmap spire-bundle -o jsonpath='{.data.bundle\.crt}'

# A workload can resolve a peer SVID?
kubectl -n aumos exec deploy/trust-core -- \
  curl --cacert /run/spire/bundle/bundle.crt \
       https://inference-proxy.aumos.svc.cluster.local:8444/healthz
```

## Federation

To federate with a second region (e.g. `eu.aumos.dev`):

1. Stand up a SPIRE stack in the EU cluster with `trust_domain = "eu.aumos.dev"`.
2. Apply the `SPIFFEBundleEndpoint` in `trust-domain-config.yaml` — it pulls the
   peer bundle from `https://spire-server.eu.aumos.dev:8443` every 5 minutes.
3. Add `eu.aumos.dev` to the `federatesWith` list of any entry that needs to
   authenticate EU workloads (the `trust-core` entry already does).

## Production notes

- **HA server.** This manifest runs a single SPIRE server with a SQLite
  datastore. For HA, use the official Helm chart with a Postgres-backed
  datastore and 3 server replicas behind a `LoadBalancer`/`Internal` Service.
- **KeyManager.** `disk` keeps the CA key on a PVC. Replace with the `aws-pcs`
  / `vault` / `gcp_kms` KeyManager for HSM-backed key custody.
- **Bundle rotation.** The `Notifier "k8sbundle"` republishes the bundle to the
  `spire-bundle` ConfigMap on every CA rotation; workloads must reload it. The
  SPIFFE CSI driver / Envoy SDS does this automatically.
- **WorkloadAttestor.** `skip_kubelet_verification = true` is set for the dev
  manifest. In prod, run with a verified kubelet certificate (`secure_kubelet`
  options) so a compromised node can't mint arbitrary SVIDs.

## References

- SPIFFE spec: <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md>
- SPIRE docs (configuring): <https://spiffe.io/docs/latest/deploying/configuring/>
- SPIRE Helm chart (production): <https://github.com/spiffe/helm-charts-hardened>
- AumOS trust-core (S1 provenance signing): `rust/trust-core/`, `rust/safe-tensors-pp/`
