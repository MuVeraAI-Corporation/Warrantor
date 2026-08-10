# warrantor-admission

AumOS **Kubernetes validating admission webhook**. Refuses to admit a Pod into
the cluster unless it carries a valid **AumOS Attestation Envelope (AAE)**
annotation. The AAE is the signed attestation produced when the workload
image (and its runtime config) was measured; without it a pod cannot be
trusted to be the thing it claims to be.

The webhook is **policy-light by design**: it enforces annotation presence
and structural validity. The cryptographic verification of the AAE quote is
delegated to the attestation verifier in the AumOS agent running on the node
— the webhook is the *gate*, not the *verifier*.

## Annotations

| Annotation              | Meaning                                            |
| ----------------------- | -------------------------------------------------- |
| `warrantor.dev/aae`          | Required. The base64 attestation envelope blob.    |
| `warrantor.dev/aae-digest`   | Optional. When present, must match `sha256:<hex>`. |

## Behaviour

- Pods in `kube-system`, `kube-public`, `kube-node-lease` are exempt by
  default (override with `allow_namespaces`).
- Optional positive selector: only enforce in namespaces in
  `namespace_selector`.
- Non-`Pod` resources in an `AdmissionReview` are passed through (the webhook
  only enforces `Pod`).

## Usage

```python
from warrantor_admission import AdmissionWebhook

webhook = AdmissionWebhook()
result = webhook.validate_pod(pod_manifest)
if not result.allowed:
    raise RuntimeError(result.reason)

# Or process a full AdmissionReview object:
response = webhook.handle_admission_review(admission_review)
assert response["response"]["allowed"] is True

# Run as a standalone HTTP server:
webhook.serve(port=8443)
```

## Deployment manifests

```yaml
# 1. Service
apiVersion: v1
kind: Service
metadata:
  name: warrantor-admission
  namespace: warrantor-system
spec:
  selector:
    app: warrantor-admission
  ports:
    - port: 443
      targetPort: 8443

---
# 2. Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: warrantor-admission
  namespace: warrantor-system
spec:
  replicas: 2
  selector:
    matchLabels:
      app: warrantor-admission
  template:
    metadata:
      labels:
        app: warrantor-admission
    spec:
      containers:
        - name: webhook
          image: aumos/admission:1.0.0
          ports:
            - containerPort: 8443
          volumeMounts:
            - name: tls
              mountPath: /tls
              readOnly: true
          env:
            - name: AUMOS_ADMISSION_PORT
              value: "8443"
      volumes:
        - name: tls
          secret:
            secretName: warrantor-admission-tls

---
# 3. ValidatingWebhookConfiguration
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: warrantor-admission
webhooks:
  - name: admission.warrantor.dev
    sideEffects: None
    admissionReviewVersions: ["v1"]
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
        operations: ["CREATE", "UPDATE"]
    clientConfig:
      service:
        name: warrantor-admission
        namespace: warrantor-system
        path: /validate
      caBundle: <base64 of the CA cert that signed the webhook's serving cert>
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["kube-system", "kube-public", "kube-node-lease"]
```

The `caBundle` value can be produced with `ca_bundle_for_webhook(pem)`.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```
