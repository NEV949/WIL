"""Deployment of a verified artifact.

A verified artifact becomes a small container on the deploy network, which is
separate from oracle-net and from the network of the sandbox. nginx is the
weighted router: it is the only component published on the host, and it shifts
the traffic from the old version to the new one in steps. The error rate is
measured at every step, and a rate above the threshold rolls the deployment
back to the old version.
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import shutil
import string
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
from docker import DockerClient
from docker.errors import DockerException, NotFound

from oracle_hcm.errors import OracleHcmError
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.paths import keys_dir, project_root
from oracle_hcm.schemas.artifacts import DeploymentOutcome, RolloutStep
from oracle_hcm.signing.keys import PUBLIC_KEY_NAME, load_public_key
from oracle_hcm.signing.manifest import SignedManifest
from oracle_hcm.signing.service import ARTIFACT_SKIP_FILES
from oracle_hcm.signing.signer import Verifier
from oracle_hcm.signing.verify import ArtifactVerifier, VerificationResult

__all__ = [
    "SLOTS",
    "DeploymentConfig",
    "DeploymentError",
    "DeploymentRequest",
    "DeploymentService",
    "SlotState",
    "compose_command",
    "dockerfile",
    "service_app_source",
]

SLOTS = ("blue", "green")
"""The two slots of a deployment. A new version takes the free slot."""

SERVICE_PORT = 8080
"""The port the deployed service listens on inside its container."""

ROUTER_PORT = 8080
"""The port the router listens on inside its container."""


class DeploymentError(OracleHcmError):
    """The deployment could not be carried out."""


@dataclass(frozen=True)
class DeploymentConfig:
    """The topology and the thresholds of a deployment."""

    network_name: str = "oracle-deploy"
    project_name: str = "oracle-deploy"
    router_image: str = "nginx:1.27-alpine"
    base_image: str = "python:3.12-slim"
    image_prefix: str = "oracle-service"
    router_port: int = 8088
    traffic_steps: tuple[int, ...] = (10, 50, 100)
    measure_requests: int = 60
    error_rate_threshold: float = 0.0
    health_timeout_seconds: int = 120
    stability_rounds: int = 2
    probe_path: str = "/health"
    compose_template: str = "infra/deploy-compose.yml"
    nginx_template: str = "infra/nginx.conf"


@dataclass
class SlotState:
    """One of the two deployment slots."""

    slot: str
    version: str = ""
    image: str = ""
    container: str = ""
    name: str = ""
    root_hash: str = ""
    files: tuple[str, ...] = ()
    modules: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeploymentRequest:
    """What has to be deployed."""

    signed: SignedManifest
    workspace: Path
    tenant_id: str = "default"
    run_id: str = ""
    probe_path: str = ""


def docker_bin_dir() -> Path | None:
    """The directory of the tools of the local Docker installation."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return None
    candidate = Path(local) / "Programs" / "DockerDesktop" / "resources" / "bin"
    return candidate if candidate.is_dir() else None


def ensure_docker_path() -> None:
    """Put the tools of the local Docker installation on PATH.

    The credential helper of Docker Desktop lives in that directory. The
    Docker SDK needs it to read the credentials of the local installation.
    """
    directory = docker_bin_dir()
    if directory is None:
        return
    current = os.environ.get("PATH", "")
    if str(directory) in current.split(os.pathsep):
        return
    os.environ["PATH"] = os.pathsep.join([str(directory), current])


def compose_command() -> list[str]:
    """The command that runs docker compose."""
    override = os.environ.get("ORACLE_COMPOSE_BIN")
    if override:
        return [override]
    home = Path.home()
    desktop = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "DockerDesktop"
    candidates: list[Path] = [
        home / ".docker" / "cli-plugins" / "docker-compose.exe",
        home / ".docker" / "cli-plugins" / "docker-compose",
        desktop / "resources" / "bin" / "docker-compose.exe",
        desktop / "resources" / "bin" / "docker-compose",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return [str(candidate)]
    found = shutil.which("docker-compose")
    if found:
        return [found]
    found = shutil.which("docker")
    if found:
        return [found, "compose"]
    raise DeploymentError("no docker compose command was found")


def service_app_source() -> str:
    """The HTTP wrapper that is copied into the image of the artifact."""
    path = Path(__file__).resolve().parent / "service_app.py"
    return path.read_text(encoding="utf-8")


def dockerfile(base_image: str) -> str:
    """The image of a deployed artifact: a non-root user, nothing else."""
    return (
        f"FROM {base_image}\n"
        "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1\n"
        "RUN groupadd --gid 10001 service "
        "&& useradd --uid 10001 --gid 10001 --create-home service\n"
        "WORKDIR /app\n"
        "COPY --chown=10001:10001 app/ /app/\n"
        "USER 10001:10001\n"
        f"EXPOSE {SERVICE_PORT}\n"
        'CMD ["python", "/app/_oracle_service.py"]\n'
    )


def _modules_of(manifest: Any) -> list[str]:
    """The modules of the artifact, taken from the files it pins."""
    modules: list[str] = []
    for entry in manifest.files:
        parts = entry.path.split("/")
        if len(parts) < 2 or not parts[0] or parts[0] == "tests":
            continue
        name = parts[-1]
        if not name.endswith(".py"):
            continue
        module = ".".join([*parts[:-1], name[:-3]])
        if module not in modules:
            modules.append(module)
    return modules


class DeploymentService:
    """Deploys a verified artifact and shifts the traffic to it."""

    def __init__(
        self,
        *,
        config: DeploymentConfig | None = None,
        root: Path | None = None,
        event_log: EventLog | None = None,
        client: DockerClient | None = None,
        keys_directory: Path | None = None,
    ) -> None:
        self._config = config if config is not None else DeploymentConfig()
        self._root = root if root is not None else project_root() / "data" / "deploy"
        self._event_log = event_log
        self._client = client
        self._keys_directory = keys_directory
        self._slots: dict[str, SlotState] = {
            "blue": SlotState(slot="blue"),
            "green": SlotState(slot="green"),
        }
        self._active: str | None = None

    @property
    def config(self) -> DeploymentConfig:
        """The topology of the deployment."""
        return self._config

    @property
    def compose_dir(self) -> Path:
        """Where the compose file and the router configuration live."""
        return self._root / "compose"

    @property
    def active_slot(self) -> str | None:
        """The slot that currently carries the traffic."""
        return self._active

    def _docker(self) -> DockerClient:
        if self._client is None:
            import docker

            ensure_docker_path()
            self._client = docker.from_env()
        return self._client

    def _router_container(self) -> str:
        return f"{self._config.project_name}-router"

    def _slot_container(self, slot: str) -> str:
        return f"{self._config.project_name}-{slot}"

    def _base_url(self) -> str:
        return f"http://127.0.0.1:{self._config.router_port}"

    def _log(self, tenant_id: str, action: str, payload: dict[str, Any]) -> None:
        if self._event_log is None:
            return
        self._event_log.append(
            tenant_id=tenant_id,
            actor="deployer",
            action=action,
            payload=payload,
        )

    # --- verification -------------------------------------------------

    def _verifier(self) -> Verifier:
        directory = self._keys_directory if self._keys_directory is not None else keys_dir()
        path = directory / PUBLIC_KEY_NAME
        if not path.is_file():
            raise DeploymentError(f"the public key is missing: {path}")
        return Verifier(load_public_key(path))

    def verify(self, signed: SignedManifest, workspace: Path) -> VerificationResult:
        """Recompute every hash, the signature and the link to the audit log."""
        if self._event_log is None:
            raise DeploymentError("the deployment needs an audit log")
        return ArtifactVerifier(
            workspace=workspace,
            signed=signed,
            verifier=self._verifier(),
            event_log=self._event_log,
        ).verify()

    # --- files of the deployment ---------------------------------------

    def _render(self) -> None:
        """Write the compose file and the configuration of the router."""
        template = (project_root() / self._config.compose_template).read_text(encoding="utf-8")
        values: dict[str, str] = {
            "DEPLOYMENT_PROJECT": self._config.project_name,
            "DEPLOY_DIR": self.compose_dir.as_posix(),
            "NETWORK_NAME": self._config.network_name,
            "ROUTER_IMAGE": self._config.router_image,
            "ROUTER_CONTAINER": self._router_container(),
            "ROUTER_PORT": str(self._config.router_port),
        }
        for slot in SLOTS:
            state = self._slots[slot]
            prefix = slot.upper()
            values[f"{prefix}_IMAGE"] = state.image or f"{self._config.image_prefix}:empty"
            values[f"{prefix}_CONTAINER"] = state.container or self._slot_container(slot)
            values[f"{prefix}_NAME"] = state.name or "oracle-service"
            values[f"{prefix}_VERSION"] = state.version or "0"
            values[f"{prefix}_ROOT_HASH"] = state.root_hash or ""
            values[f"{prefix}_FILES"] = ",".join(state.files)
            values[f"{prefix}_MODULES"] = ",".join(state.modules)
        self.compose_dir.mkdir(parents=True, exist_ok=True)
        rendered = string.Template(template).substitute(values)
        (self.compose_dir / "docker-compose.yml").write_text(rendered, encoding="utf-8")
        nginx = (project_root() / self._config.nginx_template).read_text(encoding="utf-8")
        (self.compose_dir / "nginx.conf").write_text(nginx, encoding="utf-8")

    def _write_upstream(self, entries: list[tuple[str, int]]) -> None:
        """Write the upstream of the router with the weights of the slots."""
        servers = "\n".join(
            f"    server app-{slot}:{SERVICE_PORT} weight={weight};"
            for slot, weight in entries
        )
        content = (
            "upstream oracle_backend {\n"
            f"{servers}\n"
            "    keepalive 32;\n"
            "}\n"
            "server {\n"
            f"    listen {ROUTER_PORT};\n"
            "    server_name _;\n"
            "    location / {\n"
            "        proxy_pass http://oracle_backend;\n"
            "        proxy_next_upstream off;\n"
            "        proxy_http_version 1.1;\n"
            '        proxy_set_header Connection "";\n'
            "        proxy_connect_timeout 2s;\n"
            "        proxy_read_timeout 10s;\n"
            "    }\n"
            "}\n"
        )
        self.compose_dir.mkdir(parents=True, exist_ok=True)
        (self.compose_dir / "upstream.conf").write_text(content, encoding="utf-8")

    # --- docker compose ------------------------------------------------

    def _compose(self, *args: str) -> subprocess.CompletedProcess[str]:
        command = [
            *compose_command(),
            "-f",
            str(self.compose_dir / "docker-compose.yml"),
            "-p",
            self._config.project_name,
            *args,
        ]
        # The command is resolved from a fixed list of known paths and the
        # arguments are internal constants, so no request data reaches it.
        result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise DeploymentError(f"docker compose {' '.join(args)} failed: {detail}")
        return result

    def _compose_up(self, service: str) -> None:
        self._compose("up", "-d", service)

    def _compose_rm(self, service: str) -> None:
        try:
            self._compose("rm", "-s", "-f", service)
        except DeploymentError:
            return

    def shutdown(self) -> None:
        """Stop the deployment and remove its containers and its network."""
        if not (self.compose_dir / "docker-compose.yml").is_file():
            return
        try:
            self._compose("down", "--remove-orphans")
        except DeploymentError:
            return
        self._active = None

    # --- containers ----------------------------------------------------

    def _build_image(self, version: str, workspace: Path) -> str:
        """Build the image of the artifact."""
        tag = f"{self._config.image_prefix}:{version}"
        context = self._root / "builds" / version
        if context.exists():
            shutil.rmtree(context)
        app = context / "app"
        app.mkdir(parents=True)
        for path in sorted(workspace.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(workspace)
            if relative.parts and relative.parts[0] in ("tests", "__pycache__", ".pytest_cache"):
                continue
            if relative.name in ARTIFACT_SKIP_FILES:
                continue
            target = app / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        (app / "_oracle_service.py").write_text(service_app_source(), encoding="utf-8")
        (context / "Dockerfile").write_text(dockerfile(self._config.base_image), encoding="utf-8")
        try:
            client = self._docker()
            client.images.build(
                path=str(context),
                tag=tag,
                rm=True,
                dockerfile="Dockerfile",
            )
        except DockerException as exc:
            raise DeploymentError(f"the image of the artifact could not be built: {exc}") from exc
        return tag

    def _health_status(self, container_name: str) -> str:
        """The health of a container, as the daemon reports it."""
        try:
            container = self._docker().containers.get(container_name)
        except NotFound:
            return "missing"
        state = container.attrs.get("State", {})
        health = state.get("Health", {})
        status = health.get("Status") or state.get("Status") or "unknown"
        return str(status)

    async def _wait_healthy(self, container_name: str) -> bool:
        """Wait until the container reports that it is healthy."""
        deadline = time.monotonic() + self._config.health_timeout_seconds
        while time.monotonic() < deadline:
            status = await asyncio.to_thread(self._health_status, container_name)
            if status == "healthy":
                return True
            if status in ("unhealthy", "exited", "dead", "missing"):
                return False
            await asyncio.sleep(1.0)
        return False

    def _reload_router(self) -> None:
        """Make the router read the new weights."""
        try:
            container = self._docker().containers.get(self._router_container())
        except NotFound as exc:
            raise DeploymentError("the router is not running") from exc
        test = container.exec_run(["nginx", "-t"])
        if test.exit_code != 0:
            detail = test.output.decode("utf-8", errors="replace").strip()
            raise DeploymentError(f"the router refused the new configuration: {detail}")
        reload_result = container.exec_run(["nginx", "-s", "reload"])
        if reload_result.exit_code != 0:
            detail = reload_result.output.decode("utf-8", errors="replace").strip()
            raise DeploymentError(f"the router could not be reloaded: {detail}")
        time.sleep(1.0)

    async def _restore_router(self, old_slot: str | None) -> None:
        """Put the router back on the slot that was in service."""
        if old_slot is None:
            await asyncio.to_thread(self._compose_rm, "router")
            return
        await asyncio.to_thread(self._write_upstream, [(old_slot, 100)])
        try:
            await asyncio.to_thread(self._reload_router)
        except DeploymentError:
            return

    # --- traffic -------------------------------------------------------

    async def _measure(self, probe: str) -> tuple[int, int]:
        """Send the requests through the router and count the failures."""
        count = self._config.measure_requests
        base = self._base_url()

        def _run() -> tuple[int, int]:
            errors = 0
            with requests.Session() as session:
                for _ in range(count):
                    try:
                        response = session.get(f"{base}{probe}", timeout=10)
                        if response.status_code != 200:
                            errors += 1
                    except requests.RequestException:
                        errors += 1
            return count, errors

        return await asyncio.to_thread(_run)

    async def _step(
        self,
        request: DeploymentRequest,
        old_slot: str | None,
        new_slot: str,
        percent: int,
        probe: str,
    ) -> RolloutStep:
        """Shift the traffic and measure the error rate of the new version."""
        entries: list[tuple[str, int]] = []
        if old_slot is not None and percent < 100:
            entries.append((old_slot, 100 - percent))
        entries.append((new_slot, max(percent, 1)))
        await asyncio.to_thread(self._write_upstream, entries)
        await asyncio.to_thread(self._reload_router)
        self._log(
            request.tenant_id,
            "traffic_shift",
            {
                "run_id": request.run_id,
                "percent": percent,
                "weights": dict(entries),
            },
        )
        count, errors = await self._measure(probe)
        error_rate = errors / count if count else 0.0
        healthy = error_rate <= self._config.error_rate_threshold
        step = RolloutStep(
            percent=percent,
            requests=count,
            errors=errors,
            error_rate=round(error_rate, 4),
            healthy=healthy,
            detail=f"{count} request(s) through the router, {errors} failed",
        )
        self._log(
            request.tenant_id,
            "traffic_measured",
            {
                "run_id": request.run_id,
                "percent": percent,
                "requests": count,
                "errors": errors,
                "error_rate": step.error_rate,
                "threshold": self._config.error_rate_threshold,
                "healthy": healthy,
            },
        )
        return step

    # --- the deployment ------------------------------------------------

    async def deploy(self, request: DeploymentRequest) -> DeploymentOutcome:
        """Verify the artifact and roll it out behind the router."""
        if self._event_log is None:
            raise DeploymentError("the deployment needs an audit log")
        manifest = request.signed.manifest
        version = manifest.root_hash[:12]
        deployment_id = uuid.uuid4().hex[:12]
        outcome_base: dict[str, Any] = {
            "deployment_id": deployment_id,
            "version": version,
            "root_hash": manifest.root_hash,
            "artifact_id": manifest.artifact_id,
            "error_rate_threshold": self._config.error_rate_threshold,
            "router_port": self._config.router_port,
        }

        verification = self.verify(request.signed, request.workspace)
        self._log(
            request.tenant_id,
            "deployment_verified",
            {
                "run_id": request.run_id,
                "deployment_id": deployment_id,
                "verified": verification.verified,
                "reason": verification.reason,
                "checks": [dataclasses.asdict(check) for check in verification.checks],
            },
        )
        if not verification.verified:
            self._log(
                request.tenant_id,
                "deployment_refused",
                {
                    "run_id": request.run_id,
                    "deployment_id": deployment_id,
                    "reason": verification.reason,
                    "checks": [dataclasses.asdict(check) for check in verification.failures()],
                },
            )
            return DeploymentOutcome(**outcome_base, status="refused")

        image = await asyncio.to_thread(self._build_image, version, request.workspace)
        old_slot = self._active
        target_slot = "green" if old_slot == "blue" else "blue"
        previous_slot = self._slots[target_slot]
        state = SlotState(
            slot=target_slot,
            version=version,
            image=image,
            container=self._slot_container(target_slot),
            name=manifest.artifact_id,
            root_hash=manifest.root_hash,
            files=tuple(entry.path for entry in manifest.files),
            modules=tuple(_modules_of(manifest)),
        )
        self._slots[target_slot] = state
        # The router may only reference containers that exist, so it starts
        # with the slot that is already in service.
        start_entries = [(old_slot, 100)] if old_slot else [(target_slot, 100)]
        await asyncio.to_thread(self._write_upstream, start_entries)
        self._render()
        self._log(
            request.tenant_id,
            "deployment_started",
            {
                "run_id": request.run_id,
                "deployment_id": deployment_id,
                "version": version,
                "image": image,
                "slot": target_slot,
                "root_hash": manifest.root_hash,
                "network": self._config.network_name,
            },
        )
        await asyncio.to_thread(self._compose_up, f"app-{target_slot}")
        await asyncio.to_thread(self._compose_up, "router")
        healthy = await self._wait_healthy(state.container)
        self._log(
            request.tenant_id,
            "deployment_health_check",
            {
                "run_id": request.run_id,
                "deployment_id": deployment_id,
                "version": version,
                "container": state.container,
                "healthy": healthy,
            },
        )
        if not healthy:
            await asyncio.to_thread(self._compose_rm, f"app-{target_slot}")
            self._slots[target_slot] = previous_slot
            await asyncio.to_thread(self._write_upstream, start_entries)
            self._render()
            await self._restore_router(old_slot)
            reason = "the new version did not pass the health check"
            self._log(
                request.tenant_id,
                "deployment_rolled_back",
                {
                    "run_id": request.run_id,
                    "deployment_id": deployment_id,
                    "reason": reason,
                },
            )
            return DeploymentOutcome(
                **outcome_base,
                status="rolled_back",
                image=image,
                rolled_back=True,
                rollback_reason=reason,
            )

        probe = request.probe_path or self._config.probe_path
        steps: list[RolloutStep] = []
        if old_slot is None:
            steps.append(await self._step(request, None, target_slot, 100, probe))
        else:
            for percent in self._config.traffic_steps:
                step = await self._step(request, old_slot, target_slot, percent, probe)
                steps.append(step)
                if not step.healthy:
                    return await self._rollback(
                        request,
                        deployment_id,
                        old_slot,
                        target_slot,
                        previous_slot,
                        (
                            f"the error rate of the new version was {step.error_rate:.4f} "
                            f"at {step.percent}% traffic, above the threshold of "
                            f"{self._config.error_rate_threshold:.4f}"
                        ),
                        steps,
                        image,
                    )
        for _ in range(self._config.stability_rounds):
            count, errors = await self._measure(probe)
            error_rate = errors / count if count else 0.0
            self._log(
                request.tenant_id,
                "traffic_measured",
                {
                    "run_id": request.run_id,
                    "deployment_id": deployment_id,
                    "percent": 100,
                    "requests": count,
                    "errors": errors,
                    "error_rate": round(error_rate, 4),
                    "threshold": self._config.error_rate_threshold,
                    "healthy": error_rate <= self._config.error_rate_threshold,
                    "stability": True,
                },
            )
            if error_rate > self._config.error_rate_threshold:
                return await self._rollback(
                    request,
                    deployment_id,
                    old_slot,
                    target_slot,
                    previous_slot,
                    (
                        f"the error rate of the new version was {error_rate:.4f} after the "
                        f"rollout, above the threshold of "
                        f"{self._config.error_rate_threshold:.4f}"
                    ),
                    steps,
                    image,
                )

        retired = ""
        if old_slot is not None:
            await asyncio.to_thread(self._compose_rm, f"app-{old_slot}")
            retired = self._slots[old_slot].version
            self._log(
                request.tenant_id,
                "old_version_retired",
                {
                    "run_id": request.run_id,
                    "deployment_id": deployment_id,
                    "version": retired,
                },
            )
        self._active = target_slot
        self._log(
            request.tenant_id,
            "deployment_completed",
            {
                "run_id": request.run_id,
                "deployment_id": deployment_id,
                "version": version,
                "retired_version": retired,
            },
        )
        return DeploymentOutcome(
            **outcome_base,
            status="deployed",
            image=image,
            steps=steps,
            retired_version=retired,
        )

    async def _rollback(
        self,
        request: DeploymentRequest,
        deployment_id: str,
        old_slot: str | None,
        target_slot: str,
        previous_slot: SlotState,
        reason: str,
        steps: list[RolloutStep],
        image: str,
    ) -> DeploymentOutcome:
        """Send the traffic back to the old version and remove the new one."""
        if old_slot is not None:
            await asyncio.to_thread(self._write_upstream, [(old_slot, 100)])
            await asyncio.to_thread(self._reload_router)
        else:
            await asyncio.to_thread(self._compose_rm, "router")
        await asyncio.to_thread(self._compose_rm, f"app-{target_slot}")
        self._slots[target_slot] = previous_slot
        self._render()
        self._log(
            request.tenant_id,
            "deployment_rolled_back",
            {
                "run_id": request.run_id,
                "deployment_id": deployment_id,
                "reason": reason,
                "restored_version": self._slots[old_slot].version if old_slot else "",
            },
        )
        return DeploymentOutcome(
            deployment_id=deployment_id,
            version=self._slots[target_slot].version,
            status="rolled_back",
            image=image,
            rolled_back=True,
            rollback_reason=reason,
            steps=steps,
            error_rate_threshold=self._config.error_rate_threshold,
            router_port=self._config.router_port,
        )


@dataclass
class DeploymentSlots:
    """The slots of a deployment, for the callers that inspect them."""

    slots: dict[str, SlotState] = field(default_factory=dict)
