"""Default-deny policy for generated code.

The policy is default-deny: generated code is allowed to do only what the
requirement declared. Everything else is reported as a finding.

The module deliberately depends on nothing but the standard library so that it
can be copied into the sandbox and run next to the code it inspects.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

__all__ = [
    "ALLOWED_IMPORTS",
    "DECLARED_CAPABILITIES",
    "AstFinding",
    "AstPolicy",
    "Capability",
    "PolicyResult",
    "check_permissions",
    "modules_of",
    "workspace_modules",
]

Severity = Literal["low", "medium", "high", "critical"]


class Capability:
    """Capabilities a piece of code may ask for."""

    NETWORK = "network"
    PROCESS = "process"
    DYNAMIC_EXEC = "dynamic_exec"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    SYSTEM_INFO = "system_info"
    OBFUSCATION = "obfuscation"
    SERIALISATION = "serialisation"
    IMPORT = "import"


DECLARED_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        Capability.NETWORK,
        Capability.PROCESS,
        Capability.DYNAMIC_EXEC,
        Capability.FILE_WRITE,
    }
)
"""Capabilities a requirement has to declare before the code may use them."""

ALLOWED_IMPORTS: Final[frozenset[str]] = frozenset(
    {
        "__future__",
        "abc",
        "base64",
        "bisect",
        "calendar",
        "collections",
        "copy",
        "dataclasses",
        "datetime",
        "decimal",
        "enum",
        "fractions",
        "functools",
        "hashlib",
        "heapq",
        "itertools",
        "json",
        "logging",
        "math",
        "numbers",
        "operator",
        "os",
        "pathlib",
        "random",
        "re",
        "statistics",
        "string",
        "sys",
        "textwrap",
        "time",
        "typing",
        "unicodedata",
        "unittest",
        "uuid",
    }
)
"""Modules generated code may import. Everything else is reported."""


@dataclass(frozen=True)
class AstFinding:
    """One problem found in a source file."""

    rule: str
    severity: Severity = "medium"
    file: str = ""
    line: int = 0
    message: str = ""
    tool: str = "ast"
    capability: str = ""

    @property
    def blocking(self) -> bool:
        return self.severity in ("high", "critical")

    def to_dict(self) -> dict[str, str | int]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "tool": self.tool,
            "capability": self.capability,
        }


@dataclass(frozen=True)
class PolicyResult:
    """Findings and the capabilities a file uses."""

    findings: tuple[AstFinding, ...]
    capabilities: frozenset[str]

    @property
    def blocking(self) -> bool:
        return any(finding.blocking for finding in self.findings)


@dataclass(frozen=True)
class _Sink:
    """A call that is only allowed when the requirement asked for it."""

    rule: str
    severity: Severity
    capability: str
    message: str


_EXACT_SINKS: Final[dict[str, _Sink]] = {
    "os.system": _Sink("S605", "high", Capability.PROCESS, "os.system() runs a shell command"),
    "os.popen": _Sink("S606", "high", Capability.PROCESS, "os.popen() runs a shell command"),
    "os.fork": _Sink("S404-fork", "high", Capability.PROCESS, "a process is forked"),
    "os.forkpty": _Sink("S404-fork", "high", Capability.PROCESS, "a process is forked"),
    "os.execl": _Sink("S607-exec", "high", Capability.PROCESS, "a program is executed"),
    "os.execv": _Sink("S607-exec", "high", Capability.PROCESS, "a program is executed"),
    "os.spawnl": _Sink("S606-spawn", "high", Capability.PROCESS, "a program is spawned"),
    "os.posix_spawn": _Sink("S606-spawn", "high", Capability.PROCESS, "a program is spawned"),
    "pickle.loads": _Sink(
        "S301", "medium", Capability.SERIALISATION, "pickle deserialisation executes code"
    ),
    "pickle.load": _Sink(
        "S301", "medium", Capability.SERIALISATION, "pickle deserialisation executes code"
    ),
    "marshal.loads": _Sink(
        "S301-marshal", "high", Capability.SERIALISATION, "marshal deserialisation executes code"
    ),
    "yaml.load": _Sink(
        "S506", "medium", Capability.SERIALISATION, "yaml.load without a safe loader"
    ),
    "tarfile.extractall": _Sink(
        "S202", "medium", Capability.SERIALISATION, "tarfile extraction without a filter"
    ),
    "hashlib.md5": _Sink(
        "S324", "medium", Capability.SERIALISATION, "a weak hash algorithm is used"
    ),
    "hashlib.sha1": _Sink(
        "S324", "medium", Capability.SERIALISATION, "a weak hash algorithm is used"
    ),
    "os.getcwd": _Sink("S211", "low", Capability.SYSTEM_INFO, "the working directory is read"),
    "os.getenv": _Sink("S211", "low", Capability.SYSTEM_INFO, "the environment is read"),
    "socket.gethostname": _Sink(
        "S211-host", "low", Capability.SYSTEM_INFO, "the host name is read"
    ),
    "platform.uname": _Sink("S211", "low", Capability.SYSTEM_INFO, "system information is read"),
}

_PREFIX_SINKS: Final[dict[str, _Sink]] = {
    "subprocess": _Sink(
        "S404", "high", Capability.PROCESS, "the subprocess module runs other programs"
    ),
    "socket": _Sink("S104", "high", Capability.NETWORK, "the socket module opens a connection"),
    "requests": _Sink("S113", "high", Capability.NETWORK, "the requests module opens a connection"),
    "httpx": _Sink("S105", "high", Capability.NETWORK, "the httpx module opens a connection"),
    "urllib": _Sink("S310", "high", Capability.NETWORK, "the urllib module opens a connection"),
    "http": _Sink("S112", "high", Capability.NETWORK, "the http module opens a connection"),
    "aiohttp": _Sink(
        "S113-aiohttp", "high", Capability.NETWORK, "the aiohttp module opens a connection"
    ),
}

_MODULE_SINKS: Final[dict[str, _Sink]] = {
    "subprocess": _PREFIX_SINKS["subprocess"],
    "socket": _PREFIX_SINKS["socket"],
    "requests": _PREFIX_SINKS["requests"],
    "httpx": _PREFIX_SINKS["httpx"],
    "urllib": _PREFIX_SINKS["urllib"],
    "http": _PREFIX_SINKS["http"],
    "multiprocessing": _Sink(
        "S403-mp", "high", Capability.PROCESS, "the multiprocessing module is imported"
    ),
    "ctypes": _Sink("S404-ctypes", "high", Capability.PROCESS, "the ctypes module is imported"),
    "pickle": _Sink(
        "S301-import", "medium", Capability.SERIALISATION, "the pickle module is imported"
    ),
    "marshal": _Sink(
        "S301-marshal", "high", Capability.SERIALISATION, "the marshal module is imported"
    ),
}

_EXEC_SINKS: Final[dict[str, _Sink]] = {
    "eval": _Sink("S307", "high", Capability.DYNAMIC_EXEC, "eval() executes arbitrary code"),
    "exec": _Sink("S102", "high", Capability.DYNAMIC_EXEC, "exec() executes arbitrary code"),
    "__import__": _Sink(
        "S403", "high", Capability.DYNAMIC_EXEC, "__import__() loads code at runtime"
    ),
    "compile": _Sink(
        "S307-compile", "medium", Capability.DYNAMIC_EXEC, "compile() builds code at runtime"
    ),
}

_DECODERS: Final[frozenset[str]] = frozenset(
    {
        "base64.b64decode",
        "base64.b64encode",
        "base64.b32decode",
        "base64.b16decode",
        "base64.urlsafe_b64decode",
        "base64.decodebytes",
        "codecs.decode",
        "bytes.fromhex",
        "zlib.decompress",
        "gzip.decompress",
        "bz2.decompress",
        "lzma.decompress",
    }
)

_SENSITIVE_FIELDS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "credential",
    "bearer_token",
    "authorization",
    "session_token",
    "ssn",
    "national_id",
    "tax_id",
    "bank_account",
    "iban",
    "card_number",
    "cvv",
    "pin_code",
    "salary",
    "compensation",
    "balance",
    "payroll",
)

_WRITE_MODES: Final[frozenset[str]] = frozenset({"w", "a", "x", "+"})

_WRITE_CALLS: Final[dict[str, str]] = {
    "os.remove": "a file is deleted",
    "os.unlink": "a file is deleted",
    "os.rename": "a file is renamed",
    "os.replace": "a file is replaced",
    "os.rmdir": "a directory is removed",
    "os.mkdir": "a directory is created",
    "os.makedirs": "a directory is created",
    "os.chmod": "file permissions are changed",
    "os.chown": "file ownership is changed",
    "os.truncate": "a file is truncated",
    "shutil.rmtree": "a directory tree is deleted",
    "shutil.move": "a file is moved",
    "shutil.copy": "a file is copied",
    "pathlib.Path.write_text": "a file is written",
    "pathlib.Path.write_bytes": "a file is written",
    "pathlib.Path.unlink": "a file is deleted",
    "pathlib.Path.mkdir": "a directory is created",
    "pathlib.Path.rmdir": "a directory is removed",
}


def _dotted(node: ast.AST) -> str:
    """Render a call target as a dotted name."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _match_sink(name: str) -> _Sink | None:
    """Find the rule that covers one call."""
    exact = _EXACT_SINKS.get(name)
    if exact is not None:
        return exact
    root = name.split(".", 1)[0]
    return _PREFIX_SINKS.get(root)


@dataclass(frozen=True)
class AstPolicy:
    """Default-deny check of a generated source file."""

    allowed_imports: frozenset[str] = ALLOWED_IMPORTS

    def analyze(
        self,
        source: str,
        path: str,
        local_modules: frozenset[str] = frozenset(),
    ) -> PolicyResult:
        """Check one file and report what it does and what it violates.

        ``local_modules`` holds the packages of the workspace the file belongs
        to; they may always be imported.
        """
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as exc:
            finding = AstFinding(
                rule="E999",
                severity="high",
                file=path,
                line=exc.lineno or 0,
                message=f"the file does not parse: {exc.msg}",
                tool="ast",
            )
            return PolicyResult(findings=(finding,), capabilities=frozenset())

        findings: list[AstFinding] = []
        capabilities: set[str] = set()
        decoders: set[str] = set()
        exec_sinks: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    sink = _MODULE_SINKS.get(root)
                    if sink is not None:
                        capabilities.add(sink.capability)
                        findings.append(self._finding(sink, path, node.lineno))
                    elif not self._import_allowed(root, local_modules):
                        capabilities.add(Capability.IMPORT)
                        findings.append(self._import_finding(root, path, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue
                root = (node.module or "").split(".")[0]
                sink = _MODULE_SINKS.get(root)
                if sink is not None:
                    capabilities.add(sink.capability)
                    findings.append(self._finding(sink, path, node.lineno))
                elif not self._import_allowed(root, local_modules):
                    capabilities.add(Capability.IMPORT)
                    findings.append(self._import_finding(root, path, node.lineno))
            elif isinstance(node, ast.Call):
                name = _dotted(node.func)
                short = name.rsplit(".", 1)[-1]
                if name in _DECODERS or short in _DECODERS:
                    decoders.add(name)
                    capabilities.add(Capability.OBFUSCATION)
                if short in _EXEC_SINKS:
                    exec_sinks.add(short)
                    capabilities.add(Capability.DYNAMIC_EXEC)
                    findings.append(self._finding(_EXEC_SINKS[short], path, node.lineno))
                sink = _match_sink(name)
                if sink is not None:
                    capabilities.add(sink.capability)
                    findings.append(self._finding(sink, path, node.lineno))
                if name in _WRITE_CALLS:
                    capabilities.add(Capability.FILE_WRITE)
                    findings.append(
                        AstFinding(
                            rule="S307-write",
                            severity="medium",
                            file=path,
                            line=node.lineno,
                            message=f"{_WRITE_CALLS[name]} ({name})",
                            tool="ast",
                            capability=Capability.FILE_WRITE,
                        )
                    )
                if short == "open":
                    self._check_open(node, path, findings, capabilities)
            elif isinstance(node, ast.Attribute):
                if node.attr in _SENSITIVE_FIELDS:
                    findings.append(
                        AstFinding(
                            rule="S105-sensitive",
                            severity="medium",
                            file=path,
                            line=node.lineno,
                            message=f"the code touches the sensitive field '{node.attr}'",
                            tool="ast",
                        )
                    )
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                lowered = node.value.lower()
                for field in _SENSITIVE_FIELDS:
                    if field in lowered and len(node.value) > 6:
                        findings.append(
                            AstFinding(
                                rule="S105-sensitive-literal",
                                severity="low",
                                file=path,
                                line=node.lineno,
                                message=f"a literal mentions the sensitive name '{field}'",
                                tool="ast",
                            )
                        )
                        break

        if decoders and exec_sinks:
            findings.append(
                AstFinding(
                    rule="S306-obfuscated-exec",
                    severity="critical",
                    file=path,
                    line=0,
                    message=(
                        "decoded content is passed to a dynamic executor "
                        f"({sorted(decoders)[0]} -> {sorted(exec_sinks)[0]})"
                    ),
                    tool="ast",
                )
            )
            capabilities.add(Capability.DYNAMIC_EXEC)

        return PolicyResult(
            findings=tuple(findings),
            capabilities=frozenset(capabilities),
        )

    def _check_open(
        self,
        node: ast.Call,
        path: str,
        findings: list[AstFinding],
        capabilities: set[str],
    ) -> None:
        mode = "r"
        if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
            mode = str(node.args[1].value)
        for keyword in node.keywords:
            if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                mode = str(keyword.value.value)
        if any(flag in mode for flag in _WRITE_MODES):
            capabilities.add(Capability.FILE_WRITE)
            findings.append(
                AstFinding(
                    rule="S108-write",
                    severity="medium",
                    file=path,
                    line=node.lineno,
                    message=f"the code opens a file for writing (mode '{mode}')",
                    tool="ast",
                    capability=Capability.FILE_WRITE,
                )
            )
        else:
            capabilities.add(Capability.FILE_READ)

    def _import_allowed(self, root: str, local_modules: frozenset[str]) -> bool:
        """A module may be imported when it is on the allowlist or local."""
        if not root:
            return True
        if root in self.allowed_imports or root in local_modules:
            return True
        return root.startswith("_")

    def _import_finding(self, root: str, path: str, line: int) -> AstFinding:
        return AstFinding(
            rule="S403-import-not-allowed",
            severity="high",
            file=path,
            line=line,
            message=f"the module '{root}' is not on the import allowlist",
            tool="ast",
            capability=Capability.IMPORT,
        )

    def _finding(self, sink: _Sink, path: str, line: int) -> AstFinding:
        return AstFinding(
            rule=sink.rule,
            severity=sink.severity,
            file=path,
            line=line,
            message=sink.message,
            tool="ast",
            capability=sink.capability,
        )


def modules_of(paths: Iterable[str]) -> frozenset[str]:
    """The packages the given file paths belong to."""
    names: set[str] = set()
    for path in paths:
        head = path.split("/", 1)[0]
        if not head or head in (".", ".."):
            continue
        names.add(head[:-3] if head.endswith(".py") else head)
    return frozenset(names)


def workspace_modules(root: Path) -> frozenset[str]:
    """The packages of a workspace, which the code of the workspace may import."""
    names: set[str] = set()
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return frozenset()
    for entry in entries:
        if entry.name.startswith((".", "_")):
            continue
        if entry.is_dir():
            names.add(entry.name)
        elif entry.suffix == ".py":
            names.add(entry.stem)
    return frozenset(names)


def check_permissions(
    declared: list[str],
    used: frozenset[str],
    path: str = "",
    findings: tuple[AstFinding, ...] = (),
) -> list[AstFinding]:
    """Compare the permissions a requirement declared with the ones the code uses."""
    results: list[AstFinding] = []
    declared_set = {item.strip().lower() for item in declared}
    for capability in sorted(used & DECLARED_CAPABILITIES):
        if capability not in declared_set:
            results.append(
                AstFinding(
                    rule="S104-permission",
                    severity="high",
                    file=path,
                    line=_line_of(findings, capability),
                    message=(
                        f"the code uses the '{capability}' capability, "
                        "which the requirement did not declare"
                    ),
                    tool="permissions",
                    capability=capability,
                )
            )
    return results


def _line_of(findings: tuple[AstFinding, ...], capability: str) -> int:
    """The first line where the code used the capability."""
    for finding in findings:
        if finding.capability == capability:
            return finding.line
    return 0
