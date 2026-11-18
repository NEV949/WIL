"""AST scanner for the sandbox.

The script is copied into the sandbox workspace and runs next to the code it
inspects, with the same hardening as the test run: no network, read-only
sources and no capabilities. It reports the findings of the default-deny
allowlist as JSON.

The policy module is loaded from the file that sits next to this script, so
that the scanner stays independent of the engine and of the installation of
the package it belongs to.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from oracle_hcm.security.ast_policy import AstPolicy

MARKER = "=== ORACLE_AST_FINDINGS ==="

SKIP_DIRS = (".oracle", ".git", "__pycache__", ".pytest_cache", ".mypy_cache", "_scanners")
SKIP_FILES = ("_oracle_runner.py",)
"""The harness of the engine itself, which is not generated code."""


def _policy_module() -> ModuleType:
    """Load the policy module that sits next to this script."""
    path = Path(__file__).resolve().parent / "ast_policy.py"
    spec = importlib.util.spec_from_file_location("oracle_ast_policy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"the AST policy at {path} could not be loaded")
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sources(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in SKIP_DIRS:
            continue
        if relative.name in SKIP_FILES:
            continue
        paths.append(path)
    return paths


def main() -> int:
    """Scan the tree and print the findings as JSON."""
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/workspace")
    module = _policy_module()
    policy_class = cast("type[AstPolicy]", module.AstPolicy)
    local_modules = cast("frozenset[str]", module.workspace_modules(root))
    policy = policy_class()
    findings: list[dict[str, str | int]] = []
    for path in _sources(root):
        relative = str(path.relative_to(root))
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        result = policy.analyze(source, relative, local_modules)
        findings.extend(finding.to_dict() for finding in result.findings)
    sys.stdout.write(f"{MARKER}\n")
    sys.stdout.write(json.dumps(findings))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
