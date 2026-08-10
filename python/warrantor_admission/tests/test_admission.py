"""Tests for warrantor_admission: validation, AdmissionReview, exemptions, server."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from warrantor_admission import (
    DEFAULT_AAE_ANNOTATION,
    DEFAULT_DIGEST_ANNOTATION,
    AdmissionWebhook,
    ValidationResult,
    ca_bundle_for_webhook,
)


# ---------------------------------------------------------------------------
# Construction / validation
# ---------------------------------------------------------------------------
def test_construction_requires_required_annotations() -> None:
    with pytest.raises(ValueError):
        AdmissionWebhook(required_annotations=set())


def test_validate_pod_missing_annotation_denies() -> None:
    webhook = AdmissionWebhook()
    pod = {"metadata": {"name": "p", "namespace": "default"}}
    result = webhook.validate_pod(pod)
    assert isinstance(result, ValidationResult)
    assert result.allowed is False
    assert DEFAULT_AAE_ANNOTATION in result.reason
    assert result.annotations_required == [DEFAULT_AAE_ANNOTATION]
    assert result.pod_name == "p"


def test_validate_pod_present_annotation_allows() -> None:
    webhook = AdmissionWebhook()
    pod = {
        "metadata": {
            "name": "p",
            "namespace": "default",
            "annotations": {DEFAULT_AAE_ANNOTATION: "envelope:abc"},
        }
    }
    result = webhook.validate_pod(pod)
    assert result.allowed is True
    assert result.pod_name == "p"


def test_validate_pod_empty_annotation_denies() -> None:
    webhook = AdmissionWebhook()
    pod = {
        "metadata": {
            "name": "p",
            "annotations": {DEFAULT_AAE_ANNOTATION: ""},
        }
    }
    result = webhook.validate_pod(pod)
    assert result.allowed is False


def test_validate_pod_exempts_kube_system() -> None:
    webhook = AdmissionWebhook()
    pod = {"metadata": {"name": "coredns", "namespace": "kube-system"}}
    result = webhook.validate_pod(pod)
    assert result.allowed is True
    assert "exempted" in result.reason


def test_validate_pod_with_namespace_selector_skips_others() -> None:
    webhook = AdmissionWebhook(namespace_selector={"prod"})
    # Pod in 'dev' namespace -> skipped (allowed)
    pod_dev = {"metadata": {"name": "p", "namespace": "dev"}}
    result_dev = webhook.validate_pod(pod_dev)
    assert result_dev.allowed is True
    assert "not in selector" in result_dev.reason
    # Pod in 'prod' namespace without annotation -> denied
    pod_prod = {"metadata": {"name": "p", "namespace": "prod"}}
    result_prod = webhook.validate_pod(pod_prod)
    assert result_prod.allowed is False


def test_validate_pod_rejects_non_dict_manifest() -> None:
    webhook = AdmissionWebhook()
    result = webhook.validate_pod("not a dict")  # type: ignore[arg-type]
    assert result.allowed is False
    assert "JSON object" in result.reason


def test_validate_pod_with_digest_format_check() -> None:
    webhook = AdmissionWebhook()
    pod_bad = {
        "metadata": {
            "name": "p",
            "annotations": {
                DEFAULT_AAE_ANNOTATION: "x",
                DEFAULT_DIGEST_ANNOTATION: "not-a-digest",
            },
        }
    }
    assert webhook.validate_pod(pod_bad).allowed is False

    pod_good = {
        "metadata": {
            "name": "p",
            "annotations": {
                DEFAULT_AAE_ANNOTATION: "x",
                DEFAULT_DIGEST_ANNOTATION: "sha256:" + "a" * 64,
            },
        }
    }
    assert webhook.validate_pod(pod_good).allowed is True


# ---------------------------------------------------------------------------
# AdmissionReview
# ---------------------------------------------------------------------------
def _admission_review(pod: dict, *, uid: str = "uid-1") -> dict:
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "kind": {"kind": "Pod"},
            "object": pod,
        },
    }


def test_handle_admission_review_allows_valid_pod() -> None:
    webhook = AdmissionWebhook()
    pod = {"metadata": {"name": "p", "annotations": {DEFAULT_AAE_ANNOTATION: "x"}}}
    review = _admission_review(pod)
    response = webhook.handle_admission_review(review)
    assert response["response"]["allowed"] is True
    assert response["response"]["uid"] == "uid-1"


def test_handle_admission_review_denies_missing_annotation() -> None:
    webhook = AdmissionWebhook()
    review = _admission_review({"metadata": {"name": "p"}})
    response = webhook.handle_admission_review(review)
    assert response["response"]["allowed"] is False
    assert response["response"]["status"]["code"] == 403
    assert DEFAULT_AAE_ANNOTATION in response["response"]["status"]["message"]


def test_handle_admission_review_passes_through_non_pod() -> None:
    webhook = AdmissionWebhook()
    review = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "u",
            "kind": {"kind": "Deployment"},
            "object": {"metadata": {"name": "d"}},
        },
    }
    response = webhook.handle_admission_review(review)
    assert response["response"]["allowed"] is True
    assert (
        "Deployment" in response["response"].get("status", {}).get("message", "")
        or response["response"]["allowed"] is True
    )


def test_handle_admission_review_handles_empty_request() -> None:
    webhook = AdmissionWebhook()
    response = webhook.handle_admission_review({})
    assert response["response"]["allowed"] is True  # nothing to enforce


# ---------------------------------------------------------------------------
# CA bundle helper
# ---------------------------------------------------------------------------
def test_ca_bundle_for_webhook_encodes_pem() -> None:
    pem = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"
    encoded = ca_bundle_for_webhook(pem)
    # Round-trips as base64
    import base64

    assert base64.b64decode(encoded).decode("utf-8") == pem


def test_ca_bundle_for_webhook_rejects_empty() -> None:
    with pytest.raises(ValueError):
        ca_bundle_for_webhook("")


# ---------------------------------------------------------------------------
# HTTP server (smoke test against a live port)
# ---------------------------------------------------------------------------
def test_serve_handles_post(tmp_path: Path) -> None:
    import socket
    import threading

    # Find a free port.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    webhook = AdmissionWebhook()
    from warrantor_admission import _make_server  # type: ignore[attr-defined]

    server = _make_server(webhook, "127.0.0.1", port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Deny: missing annotation
        review = _admission_review({"metadata": {"name": "p"}})
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/validate",
            data=json.dumps(review).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        assert body["response"]["allowed"] is False
        assert body["response"]["uid"] == "uid-1"

        # GET liveness
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as resp:
            live = json.loads(resp.read().decode("utf-8"))
        assert live["ok"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
