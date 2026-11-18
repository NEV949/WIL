"""Tampering with a signed artifact.

Every case below must be refused before anything is deployed, with a reason
that says what did not match, and with an event in the audit log.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from oracle_hcm.config.models import ModelRegistry, ModelRole, ModelSpec
from oracle_hcm.config.providers import Provider
from oracle_hcm.deploy.service import DeploymentConfig, DeploymentRequest, DeploymentService
from oracle_hcm.errors import SigningError
from oracle_hcm.log.eventlog import EventLog, verify_event_signature
from oracle_hcm.schemas.artifacts import ExecutionReport
from oracle_hcm.signing.keys import generate_keypair, load_keypair, load_public_key, save_keypair
from oracle_hcm.signing.manifest import ApprovalPin, ModelPin, SignedManifest, sign_manifest
from oracle_hcm.signing.service import ArtifactSigner, collect_artifact_files, load_signed_manifest
from oracle_hcm.signing.signer import Signer, Verifier

WORKSPACE_FILES = {
    "pkg/overtime.py": (
        b"def overtime_pay(hours: float, rate: float) -> float:\n    return hours * rate\n"
    ),
    "tests/test_overtime.py": b"def test_pay() -> None:\n    assert True\n",
}


def _report() -> ExecutionReport:
    return ExecutionReport(
        run_id="run-1",
        requirement_id="REQ-1",
        command="pytest",
        exit_code=0,
        tests_passed=1,
    )


def _registry() -> ModelRegistry:
    return ModelRegistry(
        version=1,
        roles={
            ModelRole.CODER: ModelSpec(
                model="fake/coder", provider=Provider.FAKE, rpm=1000, tpm=1_000_000
            )
        },
    )


class Artifact:
    """A signed artifact and the services that sign and verify it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.keys = root / "keys"
        self.keys.mkdir(parents=True, exist_ok=True)
        save_keypair(generate_keypair(), self.keys)
        self.workspace = root / "workspace"
        for name, content in WORKSPACE_FILES.items():
            path = self.workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.log = EventLog(root / "audit.jsonl")
        self.signer = ArtifactSigner(
            registry=_registry(),
            event_log=self.log,
            artifact_root=root / "artifacts",
            keys_directory=self.keys,
        )
        self.signed = self.signer.sign_artifact(
            artifact_id="run-1-REQ-1",
            requirement_id="REQ-1",
            workspace=self.workspace,
            test_report=_report(),
            security_report=_report(),
            acceptance_result={"conditions": []},
            risk_tier="low",
            approvals=[
                ApprovalPin(
                    gate_id="approval_spec",
                    stage=1,
                    approval_id="apr-1",
                    status="approved",
                    sha256="a" * 64,
                )
            ],
            tenant_id="default",
            run_id="run-1",
        )

    def service(self, *, keys: Path | None = None) -> DeploymentService:
        return DeploymentService(
            config=DeploymentConfig(
                project_name="oracle-deploy-tamper",
                network_name="oracle-deploy-tamper",
                router_port=8099,
            ),
            root=self.root / "deploy",
            event_log=self.log,
            keys_directory=keys if keys is not None else self.keys,
        )


@pytest.fixture
def artifact(tmp_path: Path) -> Artifact:
    return Artifact(tmp_path)


async def _refuse(
    artifact: Artifact,
    signed: SignedManifest,
    *,
    service: DeploymentService | None = None,
) -> tuple[str, str]:
    """Deploy a tampered artifact and return the status and the reason."""
    deployment = service if service is not None else artifact.service()
    outcome = await deployment.deploy(
        DeploymentRequest(
            signed=signed,
            workspace=artifact.workspace,
            tenant_id="default",
            run_id="run-1",
        )
    )
    refusals = [
        event for event in artifact.log.read_all() if event.action == "deployment_refused"
    ]
    assert refusals, "the refusal was not written to the audit log"
    payload = refusals[-1].payload
    assert outcome.status == "refused"
    return outcome.status, str(payload["reason"])


async def test_a_changed_file_is_refused(artifact: Artifact) -> None:
    (artifact.workspace / "pkg" / "overtime.py").write_bytes(
        b"def overtime_pay() -> None:\n    return\n"
    )

    status, reason = await _refuse(artifact, artifact.signed)

    assert status == "refused"
    assert "overtime.py" in reason


async def test_a_swapped_signature_is_refused(artifact: Artifact) -> None:
    swapped = artifact.signed.model_copy(
        update={"signature": base64.b64encode(b"0" * 64).decode("ascii")}
    )

    status, reason = await _refuse(artifact, swapped)

    assert status == "refused"
    assert "signature" in reason


async def test_the_wrong_public_key_is_refused(artifact: Artifact, tmp_path: Path) -> None:
    other = tmp_path / "other-keys"
    other.mkdir()
    save_keypair(generate_keypair(), other)

    status, reason = await _refuse(artifact, artifact.signed, service=artifact.service(keys=other))

    assert status == "refused"
    assert "signature" in reason


async def test_a_missing_file_is_refused(artifact: Artifact) -> None:
    (artifact.workspace / "pkg" / "overtime.py").unlink()

    status, reason = await _refuse(artifact, artifact.signed)

    assert status == "refused"
    assert "missing" in reason


async def test_a_log_head_mismatch_is_refused(artifact: Artifact) -> None:
    manifest = artifact.signed.manifest.model_copy(update={"log_head_hash": "f" * 64})
    from oracle_hcm.signing.manifest import build_manifest

    rebuilt = build_manifest(
        collect_artifact_files(artifact.workspace),
        artifact_id=manifest.artifact_id,
        requirement_id=manifest.requirement_id,
        test_report_hash=manifest.test_report_hash,
        security_report_hash=manifest.security_report_hash,
        acceptance_result_hash=manifest.acceptance_result_hash,
        risk_tier=manifest.risk_tier,
        models=manifest.models,
        approvals=manifest.approvals,
        log_head_hash="f" * 64,
        created_at=manifest.created_at,
    )
    keypair = load_keypair(artifact.keys)
    signed = sign_manifest(rebuilt, Signer(keypair.private_key))

    status, reason = await _refuse(artifact, signed)

    assert status == "refused"
    assert "audit log" in reason


async def test_an_untouched_artifact_verifies(artifact: Artifact) -> None:
    result = artifact.service().verify(artifact.signed, artifact.workspace)

    assert result.verified is True
    assert [check.name for check in result.checks] == [
        "files",
        "root_hash",
        "signature",
        "log_head",
    ]


def test_the_signing_event_is_signed(artifact: Artifact) -> None:
    verifier = Verifier(load_public_key(artifact.keys / "signer_public.pem"))
    signed_events = [event for event in artifact.log.read_all() if "signature" in event.payload]

    assert len(signed_events) == 1
    assert signed_events[0].action == "artifact_signed"
    assert verify_event_signature(signed_events[0], verifier) is True
    assert artifact.log.verify_signatures(verifier) == []


def test_the_manifest_holds_no_key_material(artifact: Artifact) -> None:
    private = (artifact.keys / "signer_private.pem").read_text(encoding="utf-8")

    directory = artifact.root / "artifacts" / "run-1-REQ-1"
    manifest = (directory / "manifest.json").read_text(encoding="utf-8")

    assert "PRIVATE KEY" not in manifest
    assert private.strip() not in manifest


def test_the_model_pins_are_in_the_manifest(artifact: Artifact) -> None:
    assert artifact.signed.manifest.models == [
        ModelPin(role="coder", model_id="fake/coder", version="1"),
    ]


@pytest.mark.parametrize("missing", ["manifest.json", "manifest.sig"])
def test_a_missing_manifest_file_is_refused(artifact: Artifact, missing: str) -> None:
    directory = artifact.root / "artifacts" / "run-1-REQ-1"
    (directory / missing).unlink()

    with pytest.raises(SigningError):
        load_signed_manifest(directory)
