"""The signer of accepted artifacts.

The private key stays inside this module. The agents, the sandbox, the audit
log and the manifest only ever see the signature of the root hash, never the
key and never a way to sign anything else.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from oracle_hcm.canonical import canonical_bytes, sha256_hex
from oracle_hcm.config.models import ModelRegistry
from oracle_hcm.errors import SigningError
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.paths import keys_dir
from oracle_hcm.schemas.artifacts import utc_now_iso
from oracle_hcm.signing.keys import KeyPair, load_keypair
from oracle_hcm.signing.manifest import (
    ApprovalPin,
    Manifest,
    ModelPin,
    SignedManifest,
    build_manifest,
    sign_manifest,
)
from oracle_hcm.signing.signer import Signer

__all__ = [
    "ARTIFACT_SKIP_DIRS",
    "ARTIFACT_SKIP_FILES",
    "MANIFEST_NAME",
    "SIGNATURE_NAME",
    "ArtifactSigner",
    "collect_artifact_files",
    "load_signed_manifest",
    "report_hash",
    "save_signed_manifest",
]

MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"

ARTIFACT_SKIP_DIRS = frozenset(
    {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".oracle"}
)
"""Directories of a workspace that hold no artifact."""

ARTIFACT_SKIP_FILES = frozenset({"_oracle_runner.py"})
"""The harness of the engine itself, which is not part of the artifact."""


def collect_artifact_files(workspace: Path) -> dict[str, bytes]:
    """The files of a workspace that belong to the artifact."""
    files: dict[str, bytes] = {}
    if not workspace.is_dir():
        return files
    for path in sorted(workspace.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(workspace)
        if relative.parts and relative.parts[0] in ARTIFACT_SKIP_DIRS:
            continue
        if relative.name in ARTIFACT_SKIP_FILES:
            continue
        files[relative.as_posix()] = path.read_bytes()
    return files


def report_hash(payload: Any) -> str:
    """The hash of a report or of any artifact."""
    if isinstance(payload, BaseModel):
        payload = payload.model_dump(mode="json")
    return sha256_hex(canonical_bytes(payload))


def save_signed_manifest(signed: SignedManifest, directory: Path) -> tuple[Path, Path]:
    """Write the manifest and its detached signature."""
    directory.mkdir(parents=True, exist_ok=True)
    manifest_path = directory / MANIFEST_NAME
    signature_path = directory / SIGNATURE_NAME
    manifest_path.write_text(signed.manifest.model_dump_json(indent=2), encoding="utf-8")
    signature_path.write_text(signed.signature, encoding="utf-8")
    return manifest_path, signature_path


def load_signed_manifest(directory: Path) -> SignedManifest:
    """Read the manifest and its detached signature from disk."""
    manifest_path = directory / MANIFEST_NAME
    signature_path = directory / SIGNATURE_NAME
    if not manifest_path.is_file():
        raise SigningError(f"the manifest is missing: {manifest_path}")
    if not signature_path.is_file():
        raise SigningError(f"the signature is missing: {signature_path}")
    manifest = Manifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    signature = signature_path.read_text(encoding="utf-8").strip()
    if not signature:
        raise SigningError(f"the signature is empty: {signature_path}")
    return SignedManifest(manifest=manifest, signature=signature)


class ArtifactSigner:
    """Signs an accepted artifact with the Ed25519 key of the host.

    The key is loaded inside this module and is never handed out: the caller
    receives the signed manifest and nothing else.
    """

    def __init__(
        self,
        *,
        registry: ModelRegistry,
        event_log: EventLog,
        artifact_root: Path,
        keys_directory: Path | None = None,
    ) -> None:
        self._registry = registry
        self._event_log = event_log
        self._artifact_root = artifact_root
        self._keys_directory = keys_directory

    def _keypair(self) -> KeyPair:
        directory = self._keys_directory if self._keys_directory is not None else keys_dir()
        return load_keypair(directory)

    def artifact_directory(self, artifact_id: str) -> Path:
        """Where the manifest of an artifact is kept."""
        return self._artifact_root / artifact_id

    def _signer(self) -> Signer:
        return Signer(self._keypair().private_key)

    def model_pins(self) -> list[ModelPin]:
        """The models that are configured for the build."""
        return [
            ModelPin(
                role=role.value,
                model_id=spec.configured_model,
                version=str(self._registry.version),
            )
            for role, spec in sorted(self._registry.roles.items(), key=lambda item: item[0].value)
        ]

    def sign_artifact(
        self,
        *,
        artifact_id: str,
        requirement_id: str,
        workspace: Path,
        test_report: Any,
        security_report: Any,
        acceptance_result: Any,
        risk_tier: str,
        approvals: Sequence[ApprovalPin],
        tenant_id: str,
        run_id: str,
    ) -> SignedManifest:
        """Build the manifest of an accepted artifact and sign its root hash."""
        files = collect_artifact_files(workspace)
        if not files:
            raise SigningError(f"the workspace holds no artifact file: {workspace}")
        manifest = build_manifest(
            files,
            artifact_id=artifact_id,
            requirement_id=requirement_id,
            test_report_hash=report_hash(test_report),
            security_report_hash=report_hash(security_report),
            acceptance_result_hash=report_hash(acceptance_result),
            risk_tier=risk_tier,
            models=self.model_pins(),
            approvals=list(approvals),
            log_head_hash=self._event_log.head_hash(),
            created_at=utc_now_iso(),
        )
        signed = sign_manifest(manifest, self._signer())
        directory = self._artifact_root / artifact_id
        manifest_path, signature_path = save_signed_manifest(signed, directory)
        self._event_log.append(
            tenant_id=tenant_id,
            actor="signer",
            action="artifact_signed",
            payload={
                "run_id": run_id,
                "artifact_id": artifact_id,
                "requirement_id": requirement_id,
                "root_hash": manifest.root_hash,
                "manifest_path": str(manifest_path),
                "signature_path": str(signature_path),
                "manifest_signature": signed.signature,
            },
            signer=self._signer(),
        )
        return signed
