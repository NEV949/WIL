"""Suite runner for the sandbox.

The script installs a Python audit hook, runs pytest and reports every
operation the suite tried to make that the container is supposed to forbid.
It is copied into the sandbox workspace and executed with the interpreter of
the image. It must not import anything from the engine.
"""

from __future__ import annotations

import json
import sys
from types import FrameType

MARKER = "=== ORACLE_SECURITY_EVENTS ==="

WORKSPACE = "/workspace"
RUNNER = __file__
MAX_EVENTS = 500

WRITABLE = ("/scratch", "/tmp")
SENSITIVE_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/sudoers",
    "/proc/self/environ",
    "/proc/self/maps",
    "/root/",
    "/home/",
    "/run/secrets/",
    "/var/run/",
)
WRITE_FLAGS = ("w", "a", "x", "+")

events: list[dict[str, str]] = []
_inspecting = False


def _record(category: str, detail: str) -> None:
    if len(events) >= MAX_EVENTS:
        return
    events.append({"category": category, "detail": detail[:200]})


def _in_workspace(filename: str) -> bool:
    return filename.startswith(WORKSPACE) and not filename.startswith(RUNNER)


def _caller_frame() -> FrameType | None:
    """The frame of the code that triggered the audit event."""
    try:
        return sys._getframe(2)
    except ValueError:
        return None


def _generated_code_involved(frame: FrameType) -> bool:
    """Whether the generated code is on the stack that caused the event.

    The test framework compiles and executes code of its own, which would
    otherwise be reported as the generated code trying to escape.
    """
    current: FrameType | None = frame
    while current is not None:
        if _in_workspace(current.f_code.co_filename):
            return True
        current = current.f_back
    return False


def _hook(event: str, args: tuple[object, ...]) -> None:
    global _inspecting
    if _inspecting:
        return
    _inspecting = True
    try:
        frame = _caller_frame()
        if frame is None:
            return
        _inspect(event, args, frame)
    except Exception:
        return
    finally:
        _inspecting = False


def _inspect(event: str, args: tuple[object, ...], frame: FrameType) -> None:
    if event in ("exec", "compile"):
        if not _in_workspace(frame.f_code.co_filename):
            return
    elif not _generated_code_involved(frame):
        return
    if event == "open":
        path = args[0] if args else ""
        if not isinstance(path, str):
            return
        mode = args[1] if len(args) > 1 and isinstance(args[1], str) else "r"
        if any(flag in mode for flag in WRITE_FLAGS) and not path.startswith(WRITABLE):
            _record("file_write_outside_scratch", path)
            return
        if path.startswith(SENSITIVE_PATHS):
            _record("sensitive_file_read", path)
        return
    if event in ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname"):
        _record("network", str(args[0] if args else ""))
        return
    if event.startswith("subprocess.") or event in (
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.fork",
        "os.spawn",
    ):
        _record("process", event)
        return
    if event in (
        "os.remove",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.mkdir",
        "os.chmod",
        "os.chown",
        "os.truncate",
        "os.link",
        "os.symlink",
    ):
        _record("file_write", str(args[0] if args else ""))
        return
    if event in ("exec", "compile"):
        _record("dynamic_exec", event)
        return
    if event == "ctypes.dlopen":
        _record("native_code", str(args[0] if args else ""))


def main() -> int:
    """Run the suite and print the collected events."""
    sys.addaudithook(_hook)
    import pytest

    code = int(pytest.main(sys.argv[1:]))
    sys.stdout.write(f"{MARKER}\n")
    sys.stdout.write(json.dumps(events))
    sys.stdout.write("\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
