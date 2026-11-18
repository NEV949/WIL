"""The deployment scenarios, observed for real.

Every scenario below runs against the docker daemon: the image of the artifact
is built, the container is started beside the running version and the traffic
is shifted through nginx. The report in docs/deployment_evaluation.md is built
from the outcomes of these scenarios.
"""

from __future__ import annotations

import base64
import socket
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import requests

from oracle_hcm.config.models import ModelRegistry, ModelRole, ModelSpec
from oracle_hcm.config.providers import Provider
from oracle_hcm.deploy.service import DeploymentConfig, DeploymentRequest, DeploymentService
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.schemas.artifacts import DeploymentOutcome, ExecutionReport
from oracle_hcm.signing.keys import generate_keypair, load_keypair, save_keypair
from oracle_hcm.signing.manifest import ApprovalPin, SignedManifest, build_manifest, sign_manifest
from oracle_hcm.signing.service import ArtifactSigner, collect_artifact_files
from oracle_hcm.signing.signer import Signer

__all__ = [
    "BROKEN_PROBE",
    "DowntimeOutcome",
    "Harness",
    "RollbackOutcome",
    "RolloutOutcome",
    "TamperOutcome",
    "downtime_scenario",
    "rollback_scenario",
    "rollout_scenario",
    "tamper_scenarios",
]

GOOD = {
    "pkg/overtime.py": (
        b"def overtime_pay(hours: float, rate: float) -> float:\n    return hours * rate\n"
    ),
    "tests/test_overtime.py": b"def test_pay() -> None:\n    assert True\n",
}

SECOND = {
    **GOOD,
    "pkg/second.py": b"def second() -> int:\n    return 2\n",
}

BROKEN = {
    **GOOD,
    "pkg/broken.py": (
        b"def boom() -> str:\n    raise RuntimeError('the new version is broken')\n"
    ),
}

BROKEN_PROBE = "/call?module=pkg.broken&function=boom"


@dataclass(frozen=True)
class TamperOutcome:
    """One tamper case and how the engine refused it."""

    case: str
    refused: bool
    reason: str
    logged_event: str


@dataclass(frozen=True)
class RolloutOutcome:
    """The steps of a canary rollout."""

    status: str
    steps: list[tuple[int, int, int, float]]
    retired_version: str
    version: str


@dataclass(frozen=True)
class RollbackOutcome:
    """The outcome of a rollout that failed."""

    status: str
    reason: str
    logged_event: str
    restored_version: str


@dataclass(frozen=True)
class DowntimeOutcome:
    """The requests that were sent while the traffic was shifted."""

    requests: int
    failures: int
    status: str
    steps: list[tuple[int, int, int, float]] = field(default_factory=list)


def free_port() -> int:
    """A port that nothing listens on."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def docker_is_ready() -> bool:
    """Whether the docker daemon answers."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
    except Exception:
        return False
    return True


def registry() -> ModelRegistry:
    """The model registry of the fake backend."""
    return ModelRegistry(
        version=1,
        roles={
            ModelRole.CODER: ModelSpec(
                model="fake/coder", provider=Provider.FAKE, rpm=1000, tpm=1_000_000
            )
        },
    )


def report() -> ExecutionReport:
    """A passing test report."""
    return ExecutionReport(
        run_id="run-1", requirement_id="REQ-1", command="pytest", exit_code=0
    )


class Harness:
    """A deployment with its own keys, its own log and its own network."""

    def __init__(self, root: Path, name: str) -> None:
        self.root = root
        self.name = name
        self.keys = root / "keys"
        self.keys.mkdir(parents=True, exist_ok=True)
        save_keypair(generate_keypair(), self.keys)
        self.log = EventLog(root / "audit.jsonl")
        self.signer = ArtifactSigner(
            registry=registry(),
            event_log=self.log,
            artifact_root=root / "artifacts",
            keys_directory=self.keys,
        )
        self.service = DeploymentService(
            config=DeploymentConfig(
                project_name=name,
                network_name=name,
                router_port=free_port(),
                measure_requests=100,
                stability_rounds=1,
            ),
            root=root / "deploy",
            event_log=self.log,
            keys_directory=self.keys,
        )

    def workspace(self, files: dict[str, bytes], name: str) -> Path:
        """Write a workspace with the given files."""
        directory = self.root / "workspaces" / name
        for path, content in files.items():
            target = directory / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        return directory

    def sign(self, workspace: Path, artifact_id: str) -> SignedManifest:
        """Sign the artifact of a workspace."""
        return self.signer.sign_artifact(
            artifact_id=artifact_id,
            requirement_id="REQ-1",
            workspace=workspace,
            test_report=report(),
            security_report=report(),
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

    async def deploy(
        self,
        workspace: Path,
        *,
        artifact_id: str,
        probe: str = "",
        signed: SignedManifest | None = None,
    ) -> DeploymentOutcome:
        """Deploy a workspace and return the outcome."""
        artifact = signed if signed is not None else self.sign(workspace, artifact_id)
        return await self.service.deploy(
            DeploymentRequest(
                signed=artifact,
                workspace=workspace,
                tenant_id="default",
                run_id="run-1",
                probe_path=probe,
            )
        )

    def shutdown(self) -> None:
        """Remove the containers and the network of the deployment."""
        self.service.shutdown()


def _steps(outcome: DeploymentOutcome) -> list[tuple[int, int, int, float]]:
    return [(step.percent, step.requests, step.errors, step.error_rate) for step in outcome.steps]


async def rollout_scenario(harness: Harness) -> RolloutOutcome:
    """Deploy a first version and then shift the traffic to a second one."""
    first = harness.workspace(GOOD, "v1")
    second = harness.workspace(SECOND, "v2")

    await harness.deploy(first, artifact_id="v1")
    new = await harness.deploy(second, artifact_id="v2")

    return RolloutOutcome(
        status=new.status,
        steps=_steps(new),
        retired_version=new.retired_version,
        version=new.version,
    )


async def rollback_scenario(harness: Harness) -> RollbackOutcome:
    """Deploy a version that fails and let the engine roll it back."""
    first = harness.workspace(GOOD, "v1")
    second = harness.workspace(BROKEN, "v2")

    await harness.deploy(first, artifact_id="v1")
    new = await harness.deploy(second, artifact_id="v2", probe=BROKEN_PROBE)

    rollbacks = [
        event for event in harness.log.read_all() if event.action == "deployment_rolled_back"
    ]
    reason = str(rollbacks[-1].payload["reason"]) if rollbacks else new.rollback_reason
    restored = str(rollbacks[-1].payload.get("restored_version", "")) if rollbacks else ""
    return RollbackOutcome(
        status=new.status,
        reason=reason,
        logged_event="deployment_rolled_back",
        restored_version=restored,
    )


async def downtime_scenario(harness: Harness) -> DowntimeOutcome:
    """Send a steady stream of requests while the traffic is shifted."""
    first = harness.workspace(GOOD, "v1")
    second = harness.workspace(SECOND, "v2")

    await harness.deploy(first, artifact_id="v1")

    base = f"http://127.0.0.1:{harness.service.config.router_port}"
    failures: list[str] = []
    counts: list[int] = []
    stop = threading.Event()

    def _stream() -> None:
        count = 0
        while not stop.is_set():
            try:
                response = requests.get(f"{base}/health", timeout=5)
                if response.status_code != 200:
                    failures.append(f"status {response.status_code}")
            except requests.RequestException as exc:
                failures.append(str(exc))
            count += 1
            time.sleep(0.01)
        counts.append(count)

    stream = threading.Thread(target=_stream, daemon=True)
    stream.start()
    try:
        outcome = await harness.deploy(second, artifact_id="v2")
    finally:
        stop.set()
        stream.join(timeout=30)

    return DowntimeOutcome(
        requests=counts[0] if counts else 0,
        failures=len(failures),
        status=outcome.status,
        steps=_steps(outcome),
    )


async def tamper_scenarios() -> list[TamperOutcome]:
    """Tamper with a signed artifact in five ways and record the refusals."""
    outcomes: list[TamperOutcome] = []
    with tempfile.TemporaryDirectory(prefix="oracle-tamper-") as directory:
        root = Path(directory)
        harness = Harness(root, "oracle-deploy-tamper")

        async def refuse(
            case: str,
            tamper: Callable[[Path, SignedManifest], SignedManifest | None],
            *,
            service: DeploymentService | None = None,
        ) -> None:
            name = f"case-{len(outcomes)}"
            workspace = harness.workspace(GOOD, name)
            signed = harness.sign(workspace, name)
            mutated = tamper(workspace, signed)
            deployment = service if service is not None else harness.service
            outcome = await deployment.deploy(
                DeploymentRequest(
                    signed=mutated if mutated is not None else signed,
                    workspace=workspace,
                    tenant_id="default",
                    run_id="run-1",
                )
            )
            refusals = [
                event for event in harness.log.read_all() if event.action == "deployment_refused"
            ]
            reason = str(refusals[-1].payload["reason"]) if refusals else ""
            outcomes.append(
                TamperOutcome(
                    case=case,
                    refused=outcome.status == "refused",
                    reason=reason,
                    logged_event="deployment_refused" if refusals else "",
                )
            )

        def _changed(workspace: Path, signed: SignedManifest) -> None:
            (workspace / "pkg" / "overtime.py").write_bytes(b"def overtime_pay() -> None:\n    x\n")

        def _swapped(workspace: Path, signed: SignedManifest) -> SignedManifest:
            return signed.model_copy(
                update={"signature": base64.b64encode(b"0" * 64).decode("ascii")}
            )

        def _missing(workspace: Path, signed: SignedManifest) -> None:
            (workspace / "pkg" / "overtime.py").unlink()

        def _log_head(workspace: Path, signed: SignedManifest) -> SignedManifest:
            manifest = signed.manifest
            rebuilt = build_manifest(
                collect_artifact_files(workspace),
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
            keypair = load_keypair(harness.keys)
            return sign_manifest(rebuilt, Signer(keypair.private_key))

        await refuse("a file changed after the signing", _changed)
        await refuse("the signature was swapped", _swapped)

        other = root / "other-keys"
        other.mkdir()
        save_keypair(generate_keypair(), other)
        wrong_key = DeploymentService(
            config=harness.service.config,
            root=harness.root / "deploy",
            event_log=harness.log,
            keys_directory=other,
        )
        await refuse("the wrong public key was used", lambda ws, signed: None, service=wrong_key)
        await refuse("a pinned file was missing", _missing)
        await refuse("the audit log head did not match", _log_head)

    return outcomes
