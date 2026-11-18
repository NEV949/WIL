"""The sandbox execution service."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from oracle_hcm.schemas.artifacts import CodePatch, DebugPatch, FileChange, TestCase, TestSuite
from oracle_hcm.services.sandbox import (
    TIMEOUT_EXIT_CODE,
    SandboxConfig,
    SandboxError,
    SandboxRunnerAgent,
    SandboxService,
    build_workspace,
    coverage_targets,
    source_targets,
)


@dataclass
class FakeExecResult:
    exit_code: int
    output: tuple[bytes, bytes]


@dataclass
class FakeContainer:
    """Minimal stand-in for a docker container object."""

    exit_code: int = 0
    stdout: bytes = b"1 passed in 0.1s\n"
    stderr: bytes = b""
    delay: float = 0.0
    started: bool = False
    removed: bool = False
    killed: bool = False
    commands: list[list[str]] = field(default_factory=list)
    environments: list[dict[str, str]] = field(default_factory=list)

    def start(self) -> None:
        self.started = True

    def exec_run(
        self,
        command: list[str],
        demux: bool = False,
        workdir: str = "",
        environment: dict[str, str] | None = None,
    ) -> FakeExecResult:
        self.commands.append(command)
        self.environments.append(environment or {})
        if self.delay:
            import time

            time.sleep(self.delay)
        return FakeExecResult(exit_code=self.exit_code, output=(self.stdout, self.stderr))

    def kill(self) -> None:
        self.killed = True

    def remove(self, force: bool = False) -> None:
        self.removed = True


class FakeContainers:
    """Records the create call so the hardening flags can be asserted."""

    def __init__(self, container: FakeContainer) -> None:
        self.container = container
        self.create_kwargs: dict[str, Any] = {}
        self.error: Exception | None = None

    def create(self, **kwargs: Any) -> FakeContainer:
        self.create_kwargs = kwargs
        if self.error is not None:
            raise self.error
        return self.container


class FakeClient:
    def __init__(self, container: FakeContainer | None = None) -> None:
        self.containers = FakeContainers(container if container is not None else FakeContainer())


def _patch() -> CodePatch:
    return CodePatch(
        patch_id="PATCH-1",
        requirement_id="REQ-1",
        files=[
            FileChange(
                path="pkg/overtime.py",
                operation="create",
                content="def overtime_pay(hours, rate):\n    return hours * rate\n",
            )
        ],
    )


def _suite() -> TestSuite:
    return TestSuite(
        suite_id="SUITE-1",
        requirement_id="REQ-1",
        tests=[
            TestCase(
                test_id="t1",
                requirement_ids=["REQ-1"],
                target_module="pkg.overtime",
                test_code="def test_x():\n    assert True\n",
            )
        ],
    )


def _service(client: FakeClient, **config: Any) -> SandboxService:
    return SandboxService(client=client, config=SandboxConfig(**config))


def test_root_level_python_file_uses_an_importable_coverage_target(tmp_path: Path) -> None:
    patch = CodePatch(
        patch_id="PATCH-ROOT",
        requirement_id="REQ-1",
        files=[FileChange(path="microservice.py", operation="create", content="value = 1\n")],
    )
    (tmp_path / "microservice.py").write_text("value = 1\n", encoding="utf-8")

    assert coverage_targets(patch) == ["microservice"]
    assert source_targets(tmp_path) == ["microservice.py"]


def test_package_directory_remains_a_coverage_target() -> None:
    assert coverage_targets(_patch()) == ["pkg"]


def test_workspace_holds_the_code_and_the_tests() -> None:
    files = build_workspace(_patch(), _suite())
    paths = [item.path for item in files]
    assert paths == ["pkg/overtime.py", "tests/test_overtime.py"]
    assert "sys.path.insert" in files[1].content


def test_debug_patch_replaces_the_file_in_the_workspace() -> None:
    repair = DebugPatch(
        patch_id="DEBUG-1",
        requirement_id="REQ-1",
        attempt=1,
        proposed_changes=[
            FileChange(path="pkg/overtime.py", operation="modify", content="fixed = True\n")
        ],
    )
    files = build_workspace(_patch(), _suite(), repair)
    assert files[0].content == "fixed = True\n"


async def test_run_returns_a_structured_report() -> None:
    container = FakeContainer(exit_code=0, stdout=b"1 passed in 0.2s\n")
    client = FakeClient(container)

    report = await _service(client).run(patch=_patch(), tests=_suite())

    assert report.exit_code == 0
    assert report.tests_passed == 1
    assert report.tests_failed == 0
    assert "1 passed" in report.stdout
    assert report.stderr == ""
    assert report.produced_files
    assert container.started is True
    assert container.removed is True


async def test_stdout_and_stderr_stay_apart() -> None:
    container = FakeContainer(exit_code=1, stdout=b"2 failed in 0.3s\n", stderr=b"boom\n")
    client = FakeClient(container)

    report = await _service(client).run(patch=_patch(), tests=_suite())

    assert report.stdout == "2 failed in 0.3s\n"
    assert report.stderr == "boom\n"
    assert report.tests_failed == 2


async def test_the_container_is_hardened() -> None:
    client = FakeClient()

    await _service(client).run(patch=_patch(), tests=_suite())

    kwargs = client.containers.create_kwargs
    assert kwargs["network_disabled"] is True
    assert kwargs["read_only"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges"]
    assert kwargs["user"] == "1000:1000"
    assert kwargs["mem_limit"] == "512m"
    assert kwargs["memswap_limit"] == "512m"
    assert kwargs["pids_limit"] == 64
    assert "/tmp" in kwargs["tmpfs"]


async def test_the_workspace_is_a_bind_mount() -> None:
    client = FakeClient()

    await _service(client).run(patch=_patch(), tests=_suite())

    volumes = client.containers.create_kwargs["volumes"]
    assert len(volumes) == 1
    bind = next(iter(volumes.values()))
    assert bind["bind"] == "/workspace"
    assert bind["mode"] == "ro"


async def test_the_sources_are_read_only_and_the_writes_go_to_the_tmpfs() -> None:
    client = FakeClient()

    report = await _service(client).run(patch=_patch(), tests=_suite())

    assert report.workspace_mount == "ro"
    assert report.writable_paths == ["/tmp", "/scratch"]


async def test_the_host_workspace_is_removed_after_the_run() -> None:
    client = FakeClient()

    await _service(client).run(patch=_patch(), tests=_suite())

    volumes = client.containers.create_kwargs["volumes"]
    host_path = Path(next(iter(volumes)))
    assert not await asyncio.to_thread(host_path.exists)


async def test_a_timeout_kills_the_container_and_reports_124() -> None:
    container = FakeContainer(delay=5.0)
    client = FakeClient(container)

    report = await _service(client, timeout_seconds=1).run(patch=_patch(), tests=_suite())

    assert report.exit_code == TIMEOUT_EXIT_CODE
    assert "time limit" in report.stderr
    assert container.killed is True


async def test_a_missing_image_is_reported() -> None:
    from docker.errors import ImageNotFound

    client = FakeClient()
    client.containers.error = ImageNotFound("oracle-sandbox:1.0")

    with pytest.raises(SandboxError, match="not available"):
        await _service(client).run(patch=_patch(), tests=_suite())


async def test_the_agent_adapter_validates_its_input() -> None:
    client = FakeClient()
    agent = SandboxRunnerAgent(_service(client))

    report = await agent(
        {
            "code": _patch().model_dump(mode="json"),
            "tests": _suite().model_dump(mode="json"),
            "patch": None,
        }
    )

    assert report.exit_code == 0


async def test_the_code_is_materialised_in_the_workspace_directory(tmp_path: Path) -> None:
    client = FakeClient()
    workspace = tmp_path / "workspace"

    report = await _service(client).run(
        patch=_patch(), tests=_suite(), workspace_dir=workspace
    )

    assert (workspace / "pkg" / "overtime.py").is_file()
    assert (workspace / "tests" / "test_overtime.py").is_file()
    assert report.workspace_path == str(workspace)
    assert report.produced_files == ["pkg/overtime.py", "tests/test_overtime.py"]


async def test_the_workspace_directory_is_replaced_on_every_run(tmp_path: Path) -> None:
    client = FakeClient()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    stale = workspace / "stale.py"
    stale.write_text("x = 1\n", encoding="utf-8")

    await _service(client).run(patch=_patch(), tests=_suite(), workspace_dir=workspace)

    assert not stale.exists()
    assert (workspace / "pkg" / "overtime.py").is_file()


async def test_the_runner_agent_keeps_the_workspace_below_the_root(tmp_path: Path) -> None:
    client = FakeClient()
    root = tmp_path / "workspaces"
    agent = SandboxRunnerAgent(_service(client), workspace_root=root)

    report = await agent(
        {
            "code": _patch().model_dump(mode="json"),
            "tests": _suite().model_dump(mode="json"),
            "run_id": "run-42",
        }
    )

    assert report.workspace_path == str(root / "run-42")
    assert (root / "run-42" / "pkg" / "overtime.py").is_file()


async def test_the_run_id_cannot_escape_the_workspace_root(tmp_path: Path) -> None:
    client = FakeClient()
    root = tmp_path / "workspaces"
    agent = SandboxRunnerAgent(_service(client), workspace_root=root)

    report = await agent(
        {
            "code": _patch().model_dump(mode="json"),
            "tests": _suite().model_dump(mode="json"),
            "run_id": "../../evil",
        }
    )

    assert Path(report.workspace_path).parent == root
    assert ".." not in Path(report.workspace_path).name
