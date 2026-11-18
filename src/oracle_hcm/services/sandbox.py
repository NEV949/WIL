"""Sandbox execution service.

Code and tests are copied into a disposable container that has no network, a
read-only root filesystem and no capabilities. The sources are mounted
read-only; every write goes to a scratch tmpfs. The run is bounded by a
timeout that is enforced on the host, and the result is returned as a
structured ExecutionReport with stdout and stderr kept apart.
A run may carry a scan gate. The gate contributes commands that run before
the suite, and it can stop the run when it finds a blocking problem, so that
the code never reaches the test run.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

from docker import DockerClient
from docker.errors import DockerException, ImageNotFound, NotFound

from oracle_hcm.errors import OracleHcmError
from oracle_hcm.schemas.artifacts import (
    CodePatch,
    DebugPatch,
    ExecutionReport,
    SecurityFinding,
    TestSuite,
)
from oracle_hcm.security.suite_runner import MARKER

__all__ = [
    "SECURITY_BLOCKED_EXIT_CODE",
    "TIMEOUT_EXIT_CODE",
    "CommandResult",
    "GateDecision",
    "MountReport",
    "SandboxConfig",
    "SandboxError",
    "SandboxRunnerAgent",
    "SandboxService",
    "ScanGate",
]

TIMEOUT_EXIT_CODE = 124
SECURITY_BLOCKED_EXIT_CODE = 125

_PASSED = re.compile(r"(\d+) passed")
_FAILED = re.compile(r"(\d+) failed")
_ERRORS = re.compile(r"(\d+) error")
_SKIPPED = re.compile(r"(\d+) skipped")
_COVERAGE = re.compile(r"TOTAL\s+.*?(\d+(?:\.\d+)?)%")
_RESULT_LINE = re.compile(
    r"^(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\s+(\S+)", re.MULTILINE
)

RUNNER_NAME = "_oracle_runner.py"


class SandboxError(OracleHcmError):
    """The sandbox could not be started or produced no usable result."""


@dataclass(frozen=True)
class SandboxConfig:
    """Hardening and resource limits of the sandbox container."""

    image: str = "oracle-sandbox:1.0"
    workspace: str = "/workspace"
    scratch: str = "/scratch"
    python: str = "/opt/venv/bin/python"
    network_disabled: bool = True
    memory: str = "512m"
    memory_swap: str = "512m"
    cpus: float = 0.5
    pids_limit: int = 64
    read_only: bool = True
    tmpfs: dict[str, str] = field(
        default_factory=lambda: {
            "/tmp": "rw,noexec,nosuid,size=64m,mode=1777",
            "/scratch": "rw,nosuid,size=128m,uid=1000,gid=1000,mode=0750",
        }
    )
    cap_drop: tuple[str, ...] = ("ALL",)
    security_opt: tuple[str, ...] = ("no-new-privileges",)
    user: str = "1000:1000"
    timeout_seconds: int = 300
    coverage_target: str | None = None
    type_check: bool = False
    workspace_bind_mode: str = "ro"


@dataclass(frozen=True)
class WorkspaceFile:
    """One file that is copied into the sandbox."""

    path: str
    content: str


@dataclass(frozen=True)
class MountReport:
    """How the workspace and the writable paths are mounted."""

    workspace: str
    workspace_mode: str
    scratch: str
    writable_paths: tuple[str, ...]
    root_filesystem: str

    @property
    def workspace_read_only(self) -> bool:
        return self.workspace_mode == "ro"


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one command that ran inside the sandbox."""

    command: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float


@dataclass(frozen=True)
class GateDecision:
    """What a scan gate decided about the code it inspected."""

    findings: tuple[SecurityFinding, ...] = ()
    blocked: bool = False


class ScanGate(Protocol):
    """Checks that run inside the sandbox before the suite."""

    def commands(self) -> list[list[str]]:
        """The commands the gate needs."""

    def files(self) -> list[WorkspaceFile]:
        """The files the gate needs inside the sandbox."""

    def evaluate(self, results: list[CommandResult]) -> GateDecision:
        """Judge the output of the gate commands."""


class PreRunChecker(Protocol):
    """Checks that run on the host before the sandbox is started."""

    async def check(
        self, payload: dict[str, Any], files: list[WorkspaceFile]
    ) -> list[SecurityFinding]: ...


def _test_path(target_module: str) -> str:
    leaf = target_module.replace(".", "/").rsplit("/", 1)[-1]
    return f"tests/test_{leaf}.py"


def _safe_name(value: str) -> str:
    """A directory name that cannot escape the workspace root."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", value).strip("._")
    return cleaned[:64] or "run"


def _test_source(case_source: str) -> str:
    header = "import sys\n\nsys.path.insert(0, '/workspace')\n\n"
    return header + case_source.rstrip() + "\n"


def build_workspace(
    patch: CodePatch,
    tests: TestSuite,
    debug_patch: DebugPatch | None = None,
) -> list[WorkspaceFile]:
    """Collect the files that make up the run."""
    contents: dict[str, str] = {}
    for change in patch.files:
        contents[change.path] = change.content
    if debug_patch is not None:
        for change in debug_patch.proposed_changes:
            contents[change.path] = change.content
    for case in tests.tests:
        contents[_test_path(case.target_module)] = _test_source(case.test_code)
    return [WorkspaceFile(path=path, content=content) for path, content in sorted(contents.items())]


def materialise(files: list[WorkspaceFile], root: Path) -> None:
    """Write the workspace files into the directory that is bind mounted."""
    for item in files:
        target = root / item.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(item.content, encoding="utf-8")


def coverage_targets(patch: CodePatch) -> list[str]:
    """Importable top-level modules or packages added by the patch."""
    targets: list[str] = []
    for change in patch.files:
        parts = change.path.split("/")
        if not parts or not parts[-1].endswith(".py"):
            continue
        head = parts[0] if len(parts) > 1 else parts[-1][:-3]
        if head and head not in targets and head not in (".", ".."):
            targets.append(head)
    return targets


def source_targets(root: Path) -> list[str]:
    """Top-level source paths for mypy and coverage, excluding test/tool files."""
    targets: list[str] = []
    for entry in sorted(root.iterdir()):
        if entry.name.startswith((".", "_")) or entry.name == "tests":
            continue
        if entry.is_dir() or (entry.is_file() and entry.suffix == ".py"):
            targets.append(entry.name)
    return targets


class SandboxService:
    """Runs code and tests inside a disposable container."""

    def __init__(
        self,
        client: DockerClient | None = None,
        config: SandboxConfig | None = None,
    ) -> None:
        self._config = config if config is not None else SandboxConfig()
        self._client = client

    @property
    def config(self) -> SandboxConfig:
        return self._config

    def mount_report(self) -> MountReport:
        """Describe how the workspace is mounted."""
        config = self._config
        return MountReport(
            workspace=config.workspace,
            workspace_mode=config.workspace_bind_mode,
            scratch=config.scratch,
            writable_paths=tuple(config.tmpfs),
            root_filesystem="read-only" if config.read_only else "read-write",
        )

    def _docker(self) -> DockerClient:
        if self._client is None:
            import docker

            self._client = cast("DockerClient", docker.from_env())
        return self._client

    def _create_container(self, client: DockerClient, workspace_root: Path) -> Any:
        config = self._config
        try:
            return client.containers.create(
                image=config.image,
                command=["sleep", "infinity"],
                detach=True,
                network_disabled=config.network_disabled,
                mem_limit=config.memory,
                memswap_limit=config.memory_swap,
                nano_cpus=int(config.cpus * 1_000_000_000),
                pids_limit=config.pids_limit,
                read_only=config.read_only,
                tmpfs=dict(config.tmpfs),
                volumes={
                    str(workspace_root): {
                        "bind": config.workspace,
                        "mode": config.workspace_bind_mode,
                    }
                },
                cap_drop=list(config.cap_drop),
                security_opt=list(config.security_opt),
                user=config.user,
            )
        except ImageNotFound as exc:
            raise SandboxError(f"sandbox image '{config.image}' is not available") from exc
        except DockerException as exc:
            raise SandboxError(f"cannot create the sandbox container: {exc}") from exc

    def _environment(self) -> dict[str, str]:
        config = self._config
        scratch = config.scratch
        return {
            "HOME": scratch,
            "TMPDIR": scratch,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": config.workspace,
            "XDG_CACHE_HOME": f"{scratch}/.cache",
            "XDG_CONFIG_HOME": f"{scratch}/.config",
            "COVERAGE_FILE": f"{scratch}/.coverage",
            "MYPY_CACHE_DIR": f"{scratch}/.cache/mypy",
            "PIP_CACHE_DIR": f"{scratch}/.cache/pip",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "RUFF_CACHE_DIR": f"{scratch}/.cache/ruff",
        }

    def pytest_command(self, targets: list[str]) -> list[str]:
        """The command that runs the suite inside the sandbox."""
        config = self._config
        command = [
            config.python,
            f"{config.workspace}/{RUNNER_NAME}",
            "-q",
            "-p",
            "no:cacheprovider",
            "-rA",
            "tests",
        ]
        if targets:
            for target in targets:
                module = target[:-3] if target.endswith(".py") else target
                command += ["--cov", module]
            command += ["--cov-report", "term"]
        return command

    def mypy_command(self, targets: list[str]) -> list[str]:
        """The command that type checks the generated code inside the sandbox."""
        config = self._config
        command = [
            "/opt/venv/bin/mypy",
            "--strict",
            "--no-error-summary",
            "--cache-dir",
            f"{config.scratch}/.cache/mypy",
        ]
        command += [f"{config.workspace}/{target}" for target in targets]
        return command

    def _pytest_command(self, patch: CodePatch) -> list[str]:
        return self.pytest_command(coverage_targets(patch))

    def _run_in_container(
        self,
        container: Any,
        command: list[str],
        environment: dict[str, str],
    ) -> tuple[int, bytes, bytes]:
        result = container.exec_run(
            command,
            demux=True,
            workdir=self._config.workspace,
            environment=environment,
        )
        exit_code = int(result.exit_code or 0)
        stdout, stderr = result.output if isinstance(result.output, tuple) else (result.output, b"")
        return exit_code, stdout or b"", stderr or b""

    def _execute(
        self,
        files: list[WorkspaceFile],
        commands: list[list[str]],
        timeout_seconds: int,
        directory: Path | None = None,
        should_continue: Callable[[list[CommandResult]], bool] | None = None,
        reset: bool = False,
    ) -> list[CommandResult]:
        client = self._docker()
        temporary = directory is None
        if temporary:
            workspace_root = Path(tempfile.mkdtemp(prefix="oracle-sandbox-"))
        else:
            workspace_root = cast(Path, directory)
            if reset:
                shutil.rmtree(workspace_root, ignore_errors=True)
                workspace_root.mkdir(parents=True, exist_ok=True)
        materialise(files, workspace_root)
        container = self._create_container(client, workspace_root)
        environment = self._environment()
        results: list[CommandResult] = []
        try:
            container.start()
            for command in commands:
                outcome: dict[str, Any] = {}
                finished = threading.Event()

                def _worker(
                    current: list[str] = command,
                    store: dict[str, Any] = outcome,
                    done: threading.Event = finished,
                ) -> None:
                    try:
                        store["value"] = self._run_in_container(container, current, environment)
                    except Exception as exc:
                        store["error"] = exc
                    finally:
                        done.set()

                worker = threading.Thread(target=_worker, daemon=True)
                worker.start()
                started = time.monotonic()
                if not finished.wait(timeout_seconds):
                    container.kill()
                    worker.join(timeout=10)
                    results.append(
                        CommandResult(
                            command=" ".join(command),
                            exit_code=TIMEOUT_EXIT_CODE,
                            stdout="",
                            stderr="run exceeded the time limit",
                            timed_out=True,
                            duration_seconds=round(time.monotonic() - started, 3),
                        )
                    )
                    break
                worker.join(timeout=10)
                duration = round(time.monotonic() - started, 3)
                error = outcome.get("error")
                if error is not None:
                    raise SandboxError(f"the sandbox run failed: {error}")
                exit_code, stdout, stderr = outcome["value"]
                results.append(
                    CommandResult(
                        command=" ".join(command),
                        exit_code=exit_code,
                        stdout=stdout.decode("utf-8", errors="replace"),
                        stderr=stderr.decode("utf-8", errors="replace"),
                        timed_out=False,
                        duration_seconds=duration,
                    )
                )
                if should_continue is not None and not should_continue(results):
                    break
        except NotFound as exc:
            raise SandboxError(f"the sandbox container disappeared: {exc}") from exc
        finally:
            with contextlib.suppress(DockerException):
                container.remove(force=True)
            if temporary:
                shutil.rmtree(workspace_root, ignore_errors=True)
        return results

    async def run_commands(
        self,
        *,
        files: list[WorkspaceFile],
        commands: list[list[str]],
        timeout_seconds: int | None = None,
        directory: Path | None = None,
        should_continue: Callable[[list[CommandResult]], bool] | None = None,
        reset: bool = False,
    ) -> list[CommandResult]:
        """Run commands in one container and return their outcomes."""
        limit = timeout_seconds if timeout_seconds is not None else self._config.timeout_seconds
        return await asyncio.wait_for(
            asyncio.to_thread(
                self._execute,
                files,
                commands,
                limit,
                directory,
                should_continue,
                reset,
            ),
            timeout=limit * max(len(commands), 1) + 30,
        )

    async def run_command(
        self,
        *,
        files: list[WorkspaceFile],
        command: list[str],
        timeout_seconds: int | None = None,
    ) -> CommandResult:
        """Run one command in the sandbox."""
        results = await self.run_commands(
            files=files, commands=[command], timeout_seconds=timeout_seconds
        )
        return results[0]

    async def run_in_directory(
        self,
        *,
        directory: Path,
        commands: list[list[str]],
        timeout_seconds: int | None = None,
    ) -> list[CommandResult]:
        """Run commands against a workspace that already exists on the host."""
        return await self.run_commands(
            files=[],
            commands=commands,
            timeout_seconds=timeout_seconds,
            directory=directory,
        )

    async def run(
        self,
        *,
        patch: CodePatch,
        tests: TestSuite,
        debug_patch: DebugPatch | None = None,
        timeout_seconds: int | None = None,
        workspace_dir: Path | None = None,
        gate: ScanGate | None = None,
    ) -> ExecutionReport:
        """Run the patch and its tests in the sandbox.

        When a gate is given, its commands run first. A gate that blocks stops
        the run before the suite, and the report carries its findings.
        """
        files = build_workspace(patch, tests, debug_patch)
        files = [*files, WorkspaceFile(path=RUNNER_NAME, content=_runner_source())]
        commands: list[list[str]] = []
        gate_commands: list[str] = []
        if gate is not None:
            files = [*files, *gate.files()]
            gate_commands = [" ".join(command) for command in gate.commands()]
            commands.extend(gate.commands())
        pytest_command = self._pytest_command(patch)
        commands.append(pytest_command)

        def _should_continue(results: list[CommandResult]) -> bool:
            if gate is None:
                return True
            own = [item for item in results if item.command in gate_commands]
            return not gate.evaluate(own).blocked

        limit = timeout_seconds if timeout_seconds is not None else self._config.timeout_seconds
        started = time.monotonic()
        results = await self.run_commands(
            files=files,
            commands=commands,
            timeout_seconds=limit,
            directory=workspace_dir,
            should_continue=_should_continue,
            reset=True,
        )
        duration = round(time.monotonic() - started, 3)
        decision = GateDecision()
        if gate is not None:
            own = [item for item in results if item.command in gate_commands]
            decision = gate.evaluate(own)
        suite = next(
            (item for item in results if item.command == " ".join(pytest_command)),
            None,
        )
        stdout = suite.stdout if suite is not None else ""
        stderr = suite.stderr if suite is not None else ""
        coverage = _COVERAGE.search(stdout)
        outcomes = _RESULT_LINE.findall(stdout)
        exit_code = suite.exit_code if suite is not None else SECURITY_BLOCKED_EXIT_CODE
        if decision.blocked:
            exit_code = SECURITY_BLOCKED_EXIT_CODE
        mount = self.mount_report()
        return ExecutionReport(
            run_id=f"run-{patch.patch_id}-{int(time.time())}",
            requirement_id=patch.requirement_id,
            command=" ".join(pytest_command),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            tests_passed=_count(_PASSED, stdout),
            tests_failed=_count(_FAILED, stdout) + _count(_ERRORS, stdout),
            tests_skipped=_count(_SKIPPED, stdout),
            coverage_percent=float(coverage.group(1)) if coverage else 0.0,
            duration_seconds=duration,
            produced_files=[item.path for item in files if item.path != RUNNER_NAME],
            passed_tests=[node for status, node in outcomes if status == "PASSED"],
            failed_tests=[node for status, node in outcomes if status in ("FAILED", "ERROR")],
            security_events=_security_events(stdout),
            security_findings=list(decision.findings),
            workspace_mount=mount.workspace_mode,
            writable_paths=list(mount.writable_paths),
            workspace_path=str(workspace_dir) if workspace_dir is not None else "",
        )


def _runner_source() -> str:
    """The suite runner that is copied into the sandbox."""
    return (Path(__file__).resolve().parents[1] / "security" / "suite_runner.py").read_text(
        encoding="utf-8"
    )


def _security_events(stdout: str) -> list[str]:
    """Read the events the suite runner reported."""
    if MARKER not in stdout:
        return []
    tail = stdout.split(MARKER, 1)[1]
    line = tail.strip().splitlines()[0] if tail.strip() else "[]"
    try:
        events = json.loads(line)
    except ValueError:
        return []
    if not isinstance(events, list):
        return []
    return [f"{item.get('category', 'unknown')}:{item.get('detail', '')}" for item in events]


def _count(pattern: re.Pattern[str], text: str) -> int:
    match = pattern.search(text)
    return int(match.group(1)) if match else 0


class SandboxRunnerAgent:
    """Adapter that lets the SOP engine call the sandbox like any agent.

    The optional checker runs on the host before the container is started. A
    blocking finding stops the run before any code is executed, and the
    findings are carried in the report so the debugger can act on them.

    The workspace of a run is kept on the host below the workspace root, so
    that the post-run gate can scan the code that was actually executed.
    """

    def __init__(
        self,
        service: SandboxService,
        gate: ScanGate | None = None,
        checker: PreRunChecker | None = None,
        workspace_root: Path | None = None,
    ) -> None:
        self._service = service
        self._gate = gate
        self._checker = checker
        self._workspace_root = workspace_root

    def _materialise_blocked_workspace(
        self, directory: Path, files: list[WorkspaceFile]
    ) -> None:
        """Persist the latest blocked sources for post-run security feedback."""
        if self._workspace_root is not None:
            root = self._workspace_root.resolve()
            target = directory.resolve()
            if not target.is_relative_to(root):
                raise ValueError("blocked workspace escaped its configured root")
            if target.exists():
                shutil.rmtree(target)
        directory.mkdir(parents=True, exist_ok=True)
        materialise(files, directory)

    def _workspace_dir(self, payload: dict[str, Any]) -> Path | None:
        """Where the workspace of this run is kept on the host."""
        raw = payload.get("workspace_dir")
        if raw:
            return Path(str(raw))
        if self._workspace_root is None:
            return None
        run_id = _safe_name(str(payload.get("run_id", "")))
        return self._workspace_root / run_id

    async def __call__(self, payload: dict[str, Any]) -> ExecutionReport:
        code = CodePatch.model_validate(payload.get("code", {}))
        tests = TestSuite.model_validate(payload.get("tests", {}))
        raw_patch = payload.get("patch")
        debug_patch = DebugPatch.model_validate(raw_patch) if raw_patch else None
        directory = self._workspace_dir(payload)
        files = build_workspace(code, tests, debug_patch)
        findings: list[SecurityFinding] = []
        if self._checker is not None:
            findings = await self._checker.check(payload, files)
            if any(finding.blocking for finding in findings):
                if directory is not None:
                    await asyncio.to_thread(
                        self._materialise_blocked_workspace, directory, files
                    )
                return ExecutionReport(
                    run_id=f"run-{code.patch_id}-blocked",
                    requirement_id=code.requirement_id,
                    command="pre_run_gate",
                    exit_code=SECURITY_BLOCKED_EXIT_CODE,
                    security_findings=findings,
                    produced_files=[item.path for item in files],
                    workspace_path=str(directory) if directory is not None else "",
                )
        report = await self._service.run(
            patch=code,
            tests=tests,
            debug_patch=debug_patch,
            workspace_dir=directory,
            gate=self._gate,
        )
        report.security_findings = [*findings, *report.security_findings]
        return report
