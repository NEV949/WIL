"""Security checks of generated code and of the requirement text.

The package holds the pieces that decide whether a piece of code may run:

* ``ast_policy`` - the default-deny allowlist for generated code.
* ``risk`` - the risk tier of a task and the signals behind it.
* ``prompt_guard`` - the check of the requirement text for injected instructions.
* ``scanners`` - the static scanners that run inside the sandbox image.
* ``suite_runner`` - the script that runs the suite and reports blocked attempts.
"""

from __future__ import annotations

from oracle_hcm.security.ast_policy import (
    AstFinding,
    AstPolicy,
    Capability,
    PolicyResult,
    check_permissions,
)
from oracle_hcm.security.prompt_guard import (
    FakePromptGuard,
    GuardVerdict,
    PromptGuardClient,
    RegexPromptGuard,
)
from oracle_hcm.security.risk import RiskAssessment, RiskClassifier

__all__ = [
    "AstFinding",
    "AstPolicy",
    "Capability",
    "FakePromptGuard",
    "GuardVerdict",
    "PolicyResult",
    "PromptGuardClient",
    "RegexPromptGuard",
    "RiskAssessment",
    "RiskClassifier",
    "check_permissions",
]
