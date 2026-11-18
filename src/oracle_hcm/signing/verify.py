"""Verification of a signed artifact, before it is deployed.

Every file hash, the root hash, the signature and the link to the audit log
are recomputed. A single mismatch refuses the deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from oracle_hcm.canonical import sha256_hex
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.signing.manifest import SignedManifest, signature_payload, verify_manifest
from oracle_hcm.signing.service import collect_artifact_files
from oracle_hcm.signing.signer import Verifier

__all__ = ["ArtifactVerifier", "VerificationCheck", "VerificationResult"]


@dataclass(frozen=True)
class VerificationCheck:
    """One check of a signed artifact."""

    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of the verification."""

    verified: bool
    reason: str
    checks: tuple[VerificationCheck, ...] = ()

    def failures(self) -> list[VerificationCheck]:
        """The checks that did not pass."""
        return [check for check in self.checks if not check.passed]


class ArtifactVerifier:
    """Recomputes everything the manifest pins and refuses any mismatch."""

    def __init__(
        self,
        *,
        workspace: Path,
        signed: SignedManifest,
        verifier: Verifier,
        event_log: EventLog,
    ) -> None:
        self._workspace = workspace
        self._signed = signed
        self._verifier = verifier
        self._event_log = event_log

    def verify(self) -> VerificationResult:
        """Run every check and report the first failure."""
        checks = (
            self._files(),
            self._root_hash(),
            self._signature(),
            self._log_head(),
        )
        failures = [check for check in checks if not check.passed]
        reason = failures[0].detail if failures else "the artifact matches its signed manifest"
        return VerificationResult(verified=not failures, reason=reason, checks=checks)

    def _files(self) -> VerificationCheck:
        """Every pinned file must be present and unchanged."""
        manifest = self._signed.manifest
        if not self._workspace.is_dir():
            return VerificationCheck(
                "files",
                False,
                f"the workspace of the artifact is missing: {self._workspace}",
            )
        present = collect_artifact_files(self._workspace)
        for entry in manifest.files:
            content = present.get(entry.path)
            if content is None:
                return VerificationCheck("files", False, f"the file '{entry.path}' is missing")
            if sha256_hex(content) != entry.sha256:
                return VerificationCheck(
                    "files",
                    False,
                    f"the file '{entry.path}' does not match its pinned hash",
                )
        pinned = {entry.path for entry in manifest.files}
        extra = sorted(set(present) - pinned)
        if extra:
            return VerificationCheck(
                "files",
                False,
                f"the workspace holds a file that the manifest does not pin: '{extra[0]}'",
            )
        return VerificationCheck(
            "files",
            True,
            f"{len(manifest.files)} file(s) match their pinned hash",
        )

    def _root_hash(self) -> VerificationCheck:
        """The root hash must match the body of the manifest."""
        if verify_manifest(self._signed.manifest):
            return VerificationCheck("root_hash", True, "the root hash matches the manifest body")
        return VerificationCheck(
            "root_hash",
            False,
            "the root hash does not match the manifest body",
        )

    def _signature(self) -> VerificationCheck:
        """The signature must verify against the public key."""
        manifest = self._signed.manifest
        if self._verifier.verify(
            signature_payload(manifest.root_hash),
            self._signed.signature,
        ):
            return VerificationCheck(
                "signature",
                True,
                "the signature verifies against the public key",
            )
        return VerificationCheck(
            "signature",
            False,
            "the signature does not verify against the public key",
        )

    def _log_head(self) -> VerificationCheck:
        """The audit log must still hold the head that was signed."""
        head = self._signed.manifest.log_head_hash
        if not self._event_log.verify():
            return VerificationCheck("log_head", False, "the audit log chain is broken")
        if not self._event_log.contains_hash(head):
            return VerificationCheck(
                "log_head",
                False,
                f"the audit log does not hold the signed head '{head}'",
            )
        return VerificationCheck("log_head", True, "the audit log holds the signed head")
