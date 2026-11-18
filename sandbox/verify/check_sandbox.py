"""Phase 1.3 sandbox hardening verification.

Runs INSIDE the container under the restricted docker run flags.
Prints one PASS/FAIL line per check and exits non-zero if any check fails.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""), flush=True)


def check_tools() -> None:
    # distribution name -> (import name, CLI version command or None)
    tools: dict[str, tuple[str, list[str] | None]] = {
        "pytest": ("pytest", ["pytest", "--version"]),
        "pytest-cov": ("pytest_cov", None),
        "mutmut": ("mutmut", None),
        "mypy": ("mypy", ["mypy", "--version"]),
        "ruff": ("ruff", ["ruff", "--version"]),
        "bandit": ("bandit", ["bandit", "--version"]),
        "semgrep": ("semgrep", ["semgrep", "--version"]),
        "detect-secrets": ("detect_secrets", ["detect-secrets", "--version"]),
        "faker": ("faker", None),
        "hypothesis": ("hypothesis", None),
        "polyfactory": ("polyfactory", None),
        "pydantic": ("pydantic", None),
    }
    for dist, (module, cli) in tools.items():
        pip_show = subprocess.run(
            ["pip", "show", dist], capture_output=True, text=True, timeout=120
        )
        version = ""
        for line in pip_show.stdout.splitlines():
            if line.startswith("Version:"):
                version = line.split(":", 1)[1].strip()
        importable = subprocess.run(
            ["python", "-c", f"import {module}"], capture_output=True, text=True, timeout=120
        )
        ok = pip_show.returncode == 0 and importable.returncode == 0 and bool(version)
        detail = f"{version or 'no-version'}"
        if ok and cli is not None:
            proc = subprocess.run(cli, capture_output=True, text=True, timeout=300)
            first = (proc.stdout + proc.stderr).strip().splitlines()
            cli_ok = proc.returncode == 0 and bool(first)
            ok = ok and cli_ok
            detail = f"{version} | {cli[0]} -> {first[0] if first else 'no output'}"
        record(f"tool_installed:{dist}", ok, detail)


def check_non_root() -> None:
    uid = os.getuid()
    gid = os.getgid()
    record("runs_as_non_root", uid != 0 and uid == 1000 and gid == 1000, f"uid={uid} gid={gid}")


def check_network_blocked() -> None:
    blocked = False
    detail = ""
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53), ("93.184.216.34", 80)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((host, port))
        except OSError as exc:
            blocked = True
            detail = f"{host}:{port} -> {type(exc).__name__}: {exc}"
            break
        finally:
            sock.close()
    record("network_blocked", blocked, detail or "outbound connect SUCCEEDED (not blocked)")


def check_rootfs_read_only() -> None:
    target = Path("/etc/.oracle_sandbox_write_probe")
    failed = False
    detail = ""
    try:
        target.write_text("probe")
        target.unlink(missing_ok=True)
        detail = "write to /etc SUCCEEDED (rootfs is writable)"
    except OSError as exc:
        failed = True
        detail = f"{type(exc).__name__}: {exc}"
    record("rootfs_read_only", failed, detail)


def check_pytest_runs() -> None:
    workspace = Path("/workspace")
    src = Path("/opt/verify/smoke_test.py")
    target = workspace / "test_smoke_test.py"
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target)
    except OSError as exc:
        record("pytest_runs_in_workspace", False, f"copy failed: {exc}")
        return
    proc = subprocess.run(
        ["pytest", "-q", "-p", "no:cacheprovider", str(target)],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=300,
    )
    tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
    record("pytest_runs_in_workspace", proc.returncode == 0, " | ".join(tail))


def main() -> int:
    print(f"python={sys.version.split()[0]} exe={sys.executable}", flush=True)
    check_tools()
    check_non_root()
    check_network_blocked()
    check_rootfs_read_only()
    check_pytest_runs()
    failed = [name for name, ok, _ in RESULTS if not ok]
    print("-" * 60, flush=True)
    print(f"total={len(RESULTS)} passed={len(RESULTS) - len(failed)} failed={len(failed)}", flush=True)
    if failed:
        print("failed_checks=" + ",".join(failed), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
