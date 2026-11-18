"""SOP definitions and execution engine."""

from __future__ import annotations

from oracle_hcm.sop.engine import (
    AgentCallable,
    GateEvaluator,
    GateOutcome,
    SopEngine,
    SopRunResult,
    StepResult,
    resolve_template,
)
from oracle_hcm.sop.loader import load_sop, load_sops
from oracle_hcm.sop.models import GateSpec, SopDefinition, SopStep

__all__ = [
    "AgentCallable",
    "GateEvaluator",
    "GateOutcome",
    "GateSpec",
    "SopDefinition",
    "SopEngine",
    "SopRunResult",
    "SopStep",
    "StepResult",
    "load_sop",
    "load_sops",
    "resolve_template",
]
