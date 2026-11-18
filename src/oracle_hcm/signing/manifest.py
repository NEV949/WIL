"""Signed artifact manifest.

The manifest pins every file of an accepted build: the hash of each file, the
root hash over the whole description, the hashes of the test, security and
acceptance reports, the risk tier, the models that produced the artifact, the
two administrator approvals and the audit log head at signing time.

The signature covers the root hash. The root hash covers every other field,
so a valid signature over the root hash covers the whole manifest.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from oracle_hcm.canonical import canonical_bytes, sha256_hex
from oracle_hcm.signing.signer import Signer, Verifier

__all__ = [
    "ApprovalPin",
    "Manifest",
    "ManifestEntry",
    "ModelPin",
    "SignedManifest",
    "build_manifest",
    "compute_root_hash",
    "manifest_bytes",
    "sign_manifest",
    "signature_payload",
    "verify_manifest",
    "verify_signed_manifest",
]

SIGNATURE_CONTEXT = b"oracle-hcm/manifest/v1\x00"
"""Domain separator, so that a signature cannot be replayed in another context."""


class ManifestEntry(BaseModel):
    """One file pinned by the manifest."""

    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str
    size: int = Field(ge=0)


class ModelPin(BaseModel):
    """One model that took part in the build.

    The version is the version of the model registry that assigned the model
    to the role, so that a manifest names the exact configuration that ran.
    """

    model_config = ConfigDict(extra="forbid")

    role: str
    model_id: str
    version: str


class ApprovalPin(BaseModel):
    """One administrator approval, pinned by the hash of its record."""

    model_config = ConfigDict(extra="forbid")

    gate_id: str
    stage: int = Field(ge=0)
    approval_id: str
    status: str
    sha256: str


class Manifest(BaseModel):
    """The signed description of an accepted build."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    artifact_id: str
    requirement_id: str
    files: list[ManifestEntry] = Field(default_factory=list)
    root_hash: str
    test_report_hash: str
    security_report_hash: str
    acceptance_result_hash: str
    risk_tier: str
    models: list[ModelPin] = Field(default_factory=list)
    approvals: list[ApprovalPin] = Field(default_factory=list)
    log_head_hash: str
    created_at: str


class SignedManifest(BaseModel):
    """A manifest plus its detached signature."""

    model_config = ConfigDict(extra="forbid")

    manifest: Manifest
    signature: str


def build_manifest(
    files: Mapping[str, bytes],
    *,
    artifact_id: str,
    requirement_id: str,
    test_report_hash: str,
    security_report_hash: str,
    acceptance_result_hash: str,
    risk_tier: str,
    models: Sequence[ModelPin],
    approvals: Sequence[ApprovalPin],
    log_head_hash: str,
    created_at: str,
) -> Manifest:
    """Build a manifest over the given files."""
    entries = [
        ManifestEntry(path=path, sha256=sha256_hex(content), size=len(content))
        for path, content in sorted(files.items())
    ]
    manifest = Manifest(
        artifact_id=artifact_id,
        requirement_id=requirement_id,
        files=entries,
        root_hash="",
        test_report_hash=test_report_hash,
        security_report_hash=security_report_hash,
        acceptance_result_hash=acceptance_result_hash,
        risk_tier=risk_tier,
        models=list(models),
        approvals=list(approvals),
        log_head_hash=log_head_hash,
        created_at=created_at,
    )
    return manifest.model_copy(update={"root_hash": compute_root_hash(manifest)})


def compute_root_hash(manifest: Manifest) -> str:
    """Hash over the pinned metadata, excluding the root hash itself."""
    body: dict[str, Any] = {
        "schema_version": manifest.schema_version,
        "artifact_id": manifest.artifact_id,
        "requirement_id": manifest.requirement_id,
        "files": [entry.model_dump(mode="json") for entry in manifest.files],
        "test_report_hash": manifest.test_report_hash,
        "security_report_hash": manifest.security_report_hash,
        "acceptance_result_hash": manifest.acceptance_result_hash,
        "risk_tier": manifest.risk_tier,
        "models": [pin.model_dump(mode="json") for pin in manifest.models],
        "approvals": [pin.model_dump(mode="json") for pin in manifest.approvals],
        "log_head_hash": manifest.log_head_hash,
        "created_at": manifest.created_at,
    }
    return sha256_hex(canonical_bytes(body))


def manifest_bytes(manifest: Manifest) -> bytes:
    """The canonical form of a manifest, used to store it on disk."""
    return canonical_bytes(manifest.model_dump(mode="json"))


def signature_payload(root_hash: str) -> bytes:
    """The bytes a manifest signature covers."""
    return SIGNATURE_CONTEXT + root_hash.encode("ascii")


def sign_manifest(manifest: Manifest, signer: Signer) -> SignedManifest:
    """Sign the root hash of a manifest."""
    return SignedManifest(
        manifest=manifest,
        signature=signer.sign(signature_payload(manifest.root_hash)),
    )


def verify_manifest(manifest: Manifest) -> bool:
    """Recompute the root hash and compare it with the stored one."""
    return compute_root_hash(manifest) == manifest.root_hash


def verify_signed_manifest(signed: SignedManifest, verifier: Verifier) -> bool:
    """Verify both the detached signature and the internal root hash."""
    if not verify_manifest(signed.manifest):
        return False
    return verifier.verify(
        signature_payload(signed.manifest.root_hash),
        signed.signature,
    )
