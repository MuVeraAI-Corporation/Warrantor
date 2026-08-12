"""Warrantor Kubernetes Admission Controller.

A validating admission webhook that refuses to admit a Pod into a cluster
unless it carries a valid **Warrantor Attestation Envelope (AAE)** annotation.
The AAE is the signed attestation produced when the workload image (and its
runtime config) was measured; without it a pod cannot be trusted to be the
thing it claims to be.

The webhook is policy-light by design: it only enforces annotation presence
and structural validity. The cryptographic verification of the AAE quote is
delegated to the attestation verifier in the Warrantor agent running on the node
— the webhook is the *gate*, not the *verifier*.

The package has no hard third-party dependencies. The HTTP server uses the
standard library ``http.server``, so it runs anywhere Python runs. Deployment
manifests (ValidatingWebhookConfiguration + Service + Deployment) are in the
README.

Usage:
    webhook = AdmissionWebhook(required_annotations={"muveraai.com/aae"})
    result = webhook.validate_pod(manifest)
    if not result.allowed:
        print(result.reason)
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# Default AAE annotation key. Workloads MUST carry this annotation with a
# non-empty value before they are admitted.
DEFAULT_AAE_ANNOTATION = "muveraai.com/aae"

# Optional: the digest annotation. If present, must look like "sha256:<hex>".
DEFAULT_DIGEST_ANNOTATION = "muveraai.com/aae-digest"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-fA-F]{8,128}$")


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class ValidationResult:
    """Outcome of validating a single pod manifest.

    Attributes:
        allowed:               whether the pod should be admitted.
        reason:                human-readable reason (always populated when
                               ``allowed`` is False).
        annotations_required:  the annotation keys the webhook was checking for.
        pod_name:              best-effort name extracted from the manifest.
        uid:                   the Kubernetes object UID (echoed back in the
                               AdmissionResponse), if present.
    """

    allowed: bool
    reason: str = ""
    annotations_required: list[str] = field(default_factory=list)
    pod_name: str = ""
    uid: str = ""


# ---------------------------------------------------------------------------
# AdmissionWebhook
# ---------------------------------------------------------------------------
@dataclass
class AdmissionWebhook:
    """Validating webhook that enforces AAE presence.

    Parameters:
        required_annotations: annotation keys that must be present and non-empty.
        digest_annotation:    annotation key for the SHA-256 digest (optional).
                              When set, if the annotation is present its value
                              must match ``sha256:<hex>``.
        namespace_selector:   optional set of namespaces to *enforce* in. When
                              empty, all namespaces are enforced.
        allow_namespaces:     set of namespaces to skip (e.g. ``kube-system``).
                              Useful to avoid bricking control-plane pods.
    """

    required_annotations: set[str] = field(default_factory=lambda: {DEFAULT_AAE_ANNOTATION})
    digest_annotation: str = DEFAULT_DIGEST_ANNOTATION
    namespace_selector: set[str] = field(default_factory=set)
    allow_namespaces: set[str] = field(
        default_factory=lambda: {"kube-system", "kube-public", "kube-node-lease"}
    )

    def __post_init__(self) -> None:
        if not self.required_annotations:
            raise ValueError("required_annotations must not be empty")

    # ------------------------------------------------------------------
    # Pod validation
    # ------------------------------------------------------------------
    def validate_pod(self, pod_manifest: dict[str, Any]) -> ValidationResult:
        """Validate a single pod manifest (a Kubernetes Pod object)."""
        if not isinstance(pod_manifest, dict):
            return ValidationResult(
                allowed=False,
                reason="manifest must be a JSON object",
                annotations_required=sorted(self.required_annotations),
            )
        meta = pod_manifest.get("metadata", {}) or {}
        name = str(meta.get("name") or meta.get("generateName") or "")
        uid = str(meta.get("uid") or "")
        namespace = str(meta.get("namespace") or "default")
        annotations = dict(meta.get("annotations") or {})

        # Skip control-plane namespaces.
        if namespace in self.allow_namespaces:
            return ValidationResult(
                allowed=True,
                reason=f"namespace {namespace!r} exempted",
                annotations_required=sorted(self.required_annotations),
                pod_name=name,
                uid=uid,
            )

        # Optional positive namespace selector.
        if self.namespace_selector and namespace not in self.namespace_selector:
            return ValidationResult(
                allowed=True,
                reason=f"namespace {namespace!r} not in selector; webhook skipped",
                annotations_required=sorted(self.required_annotations),
                pod_name=name,
                uid=uid,
            )

        # Check every required annotation.
        missing = [k for k in sorted(self.required_annotations) if not annotations.get(k)]
        if missing:
            return ValidationResult(
                allowed=False,
                reason=(
                    "missing required Warrantor attestation annotation(s): " + ", ".join(missing)
                ),
                annotations_required=sorted(self.required_annotations),
                pod_name=name,
                uid=uid,
            )

        # If a digest annotation is configured and present, validate format.
        if self.digest_annotation:
            digest = annotations.get(self.digest_annotation)
            if digest and not _DIGEST_RE.match(str(digest)):
                return ValidationResult(
                    allowed=False,
                    reason=(f"annotation {self.digest_annotation!r} must match 'sha256:<hex>'"),
                    annotations_required=sorted(self.required_annotations),
                    pod_name=name,
                    uid=uid,
                )

        return ValidationResult(
            allowed=True,
            reason="AAE annotation present and valid",
            annotations_required=sorted(self.required_annotations),
            pod_name=name,
            uid=uid,
        )

    # ------------------------------------------------------------------
    # AdmissionReview processing
    # ------------------------------------------------------------------
    def handle_admission_review(self, review: dict[str, Any]) -> dict[str, Any]:
        """Process a Kubernetes ``AdmissionReview`` request object.

        Returns an ``AdmissionReview`` response object with an
        ``AdmissionResponse`` (``allowed: true|false``). When denied, a
        ``status.message`` explains why.
        """
        request = review.get("request") or {}
        uid = str(request.get("uid") or "")
        kind = (request.get("kind") or {}).get("kind", "")
        # The webhook only enforces Pods; everything else is allowed through.
        if kind != "Pod":
            return self._response(uid=uid, allowed=True, reason=f"kind {kind!r} not enforced")
        pod_manifest = request.get("object") or {}
        result = self.validate_pod(pod_manifest)
        if not result.uid and uid:
            result.uid = uid
        return self._response(
            uid=result.uid or uid,
            allowed=result.allowed,
            reason=result.reason,
        )

    @staticmethod
    def _response(*, uid: str, allowed: bool, reason: str) -> dict[str, Any]:
        resp: dict[str, Any] = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": allowed,
            },
        }
        if not allowed:
            resp["response"]["status"] = {
                "code": 403,
                "message": reason,
            }
        return resp

    # ------------------------------------------------------------------
    # HTTP server mode
    # ------------------------------------------------------------------
    def serve(self, port: int = 8443, *, host: str = "0.0.0.0") -> None:
        """Run the webhook as a blocking HTTP server on ``port``.

        Expects TLS in production (configure via the Service / secret). For
        local development call ``serve_in_thread`` from a test instead.
        """
        server = _make_server(self, host, port)
        try:
            server.serve_forever()
        finally:
            server.server_close()


def _make_server(webhook: AdmissionWebhook, host: str, port: int) -> ThreadingHTTPServer:
    """Build a ThreadingHTTPServer bound to ``webhook`` (used by tests)."""

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            # Silence default logging; callers can re-enable if needed.
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                review = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(
                    400,
                    {
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "response": {
                            "uid": "",
                            "allowed": False,
                            "status": {"code": 400, "message": "invalid JSON body"},
                        },
                    },
                )
                return
            response = webhook.handle_admission_review(review)
            self._send_json(200, response)

        def do_GET(self) -> None:
            # Simple liveness probe.
            self._send_json(200, {"ok": True, "ts": time.time()})

        def _send_json(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer((host, port), _Handler)


# ---------------------------------------------------------------------------
# Helpers for the K8s manifests (used by the README / tests)
# ---------------------------------------------------------------------------
def ca_bundle_for_webhook(ca_bundle_pem: str) -> str:
    """Return the base64-encoded CA bundle to embed in the webhook config.

    Kubernetes requires ``clientConfig.caBundle`` as a base64 string. This is
    a tiny convenience helper so callers don't have to remember the encoding.
    """
    if not ca_bundle_pem:
        raise ValueError("ca_bundle_pem must be a non-empty PEM string")
    return base64.b64encode(ca_bundle_pem.encode("utf-8")).decode("ascii")


__all__ = [
    "DEFAULT_AAE_ANNOTATION",
    "DEFAULT_DIGEST_ANNOTATION",
    "AdmissionWebhook",
    "ValidationResult",
    "ca_bundle_for_webhook",
]
