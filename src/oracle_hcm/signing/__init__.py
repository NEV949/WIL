"""Signing subsystem."""

from __future__ import annotations

from oracle_hcm.signing.keys import (
    KeyPair,
    generate_keypair,
    load_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)
from oracle_hcm.signing.manifest import (
    ApprovalPin,
    Manifest,
    ManifestEntry,
    ModelPin,
    SignedManifest,
    build_manifest,
    manifest_bytes,
    sign_manifest,
    verify_manifest,
    verify_signed_manifest,
)
from oracle_hcm.signing.service import (
    ArtifactSigner,
    collect_artifact_files,
    load_signed_manifest,
    save_signed_manifest,
)
from oracle_hcm.signing.signer import Signer, Verifier
from oracle_hcm.signing.verify import (
    ArtifactVerifier,
    VerificationCheck,
    VerificationResult,
)

__all__ = [
    "ApprovalPin",
    "ArtifactSigner",
    "ArtifactVerifier",
    "KeyPair",
    "Manifest",
    "ManifestEntry",
    "ModelPin",
    "SignedManifest",
    "Signer",
    "VerificationCheck",
    "VerificationResult",
    "Verifier",
    "build_manifest",
    "collect_artifact_files",
    "generate_keypair",
    "load_keypair",
    "load_private_key",
    "load_public_key",
    "load_signed_manifest",
    "manifest_bytes",
    "save_keypair",
    "save_signed_manifest",
    "sign_manifest",
    "verify_manifest",
    "verify_signed_manifest",
]
