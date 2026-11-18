"""The agents that turn inputs into the six allowed artifacts."""

from __future__ import annotations

from oracle_hcm.agents.base import AgentError, ArtifactAgent, extract_json_object
from oracle_hcm.agents.coder import CoderAgent
from oracle_hcm.agents.debugger import DebuggerAgent
from oracle_hcm.agents.requirements import RequirementsAgent
from oracle_hcm.agents.test_designer import TestDesignerAgent

__all__ = [
    "AgentError",
    "ArtifactAgent",
    "CoderAgent",
    "DebuggerAgent",
    "RequirementsAgent",
    "TestDesignerAgent",
    "extract_json_object",
]
