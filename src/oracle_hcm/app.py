"""Application wiring.

This module assembles the pieces into a runnable orchestrator. It is the only
place that decides which backend is used, so the engine never talks to a
provider by accident.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from oracle_hcm.agents.coder import CoderAgent
from oracle_hcm.agents.debugger import DebuggerAgent
from oracle_hcm.agents.requirements import RequirementsAgent
from oracle_hcm.agents.test_designer import TestDesignerAgent
from oracle_hcm.config.models import ModelRegistry, load_model_registry
from oracle_hcm.config.settings import Settings
from oracle_hcm.deploy.service import DeploymentConfig, DeploymentService
from oracle_hcm.knowledge.embeddings import DeterministicEmbedder, Embedder
from oracle_hcm.knowledge.litellm_embedding import build_embedder
from oracle_hcm.knowledge.memory import MemoryWriter
from oracle_hcm.knowledge.retrieval import RetrievalHandle, RetrievalService
from oracle_hcm.knowledge.vectors import DEFAULT_QDRANT_URL, VectorStore, qdrant_client
from oracle_hcm.llm.fake import FakeBackend, fake_registry, fake_settings
from oracle_hcm.llm.limits import DailyTokenCounter
from oracle_hcm.llm.router import LLMRouter
from oracle_hcm.log.conversation import ConversationStore
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.paths import data_dir
from oracle_hcm.schemas.artifacts import (
    CodePatch,
    DebugPatch,
    ExecutionReport,
    RequirementSpec,
    TaskPlan,
    TestSuite,
)
from oracle_hcm.security.ast_policy import AstPolicy
from oracle_hcm.security.prompt_guard import PromptGuardClient, RegexPromptGuard
from oracle_hcm.security.risk import RiskClassifier
from oracle_hcm.security.scanners import ScannerSuite
from oracle_hcm.services.acceptance import (
    AcceptanceGate,
    AcceptanceGateAgent,
    RiskTierGate,
    SecurityCleanGate,
)
from oracle_hcm.services.approvals import AdminApprovalGate, ApprovalService
from oracle_hcm.services.deployment import DeploymentGate, DeploymentStep
from oracle_hcm.services.orchestrator import Orchestrator
from oracle_hcm.services.sandbox import SandboxRunnerAgent, SandboxService
from oracle_hcm.services.security_gate import (
    PreRunSecurityGate,
    RequirementChecker,
    SecurityGateAgent,
)
from oracle_hcm.services.security_repair import SecurityRepairAgent
from oracle_hcm.services.signing import SigningStep
from oracle_hcm.signing.service import ArtifactSigner
from oracle_hcm.sop.engine import AgentCallable, GateEvaluator, SopEngine
from oracle_hcm.sop.loader import load_sops

__all__ = ["ARTIFACT_SCHEMAS", "AppConfig", "build_orchestrator"]

_LOGGER = logging.getLogger(__name__)

ARTIFACT_SCHEMAS: dict[str, type[BaseModel]] = {
    "RequirementSpec": RequirementSpec,
    "TaskPlan": TaskPlan,
    "CodePatch": CodePatch,
    "TestSuite": TestSuite,
    "ExecutionReport": ExecutionReport,
    "DebugPatch": DebugPatch,
}


@dataclass(frozen=True)
class AppConfig:
    """How the application is started."""

    sop_id: str = "sop_lightweight"
    tenant_id: str = "default"
    max_phase: int = 5
    use_fake_backend: bool = True
    sandbox_image: str = "oracle-sandbox:1.0"
    sandbox_timeout_seconds: int = 300
    coverage_target: float = 80.0
    prompt_guard: PromptGuardClient | None = None
    keys_directory: Path | None = None
    deployment_root: Path | None = None
    probe_path: str = "/health"
    qdrant_url: str = DEFAULT_QDRANT_URL
    embedder: Embedder | None = None
    run_token_cap: int = 60_000


def _event_log(data_root: Path) -> EventLog:
    data_root.mkdir(parents=True, exist_ok=True)
    return EventLog(data_root / "audit.jsonl")


def _default_embedder(registry: ModelRegistry, config: AppConfig, settings: Settings) -> Embedder:
    """The embedder of the run.

    The offline runs and the tests keep the deterministic embedder: they
    never reach a provider. A live run uses the embedding model of the
    configuration, whose length of vectors the collections of Qdrant are
    built with.
    """
    if config.use_fake_backend or registry.embeddings is None:
        return DeterministicEmbedder()
    return build_embedder(registry.embeddings, settings=settings)


def build_orchestrator(
    config: AppConfig | None = None,
    *,
    registry: ModelRegistry | None = None,
    settings: Settings | None = None,
    backend: Any | None = None,
    sandbox: SandboxService | None = None,
    approvals: ApprovalService | None = None,
    event_log: EventLog | None = None,
    data_root: Path | None = None,
    guard: PromptGuardClient | None = None,
    vector_store: VectorStore | None = None,
    retrieval: RetrievalService | None = None,
) -> Orchestrator:
    """Assemble the orchestrator and its dependencies."""
    if config is None:
        config = AppConfig()
    settings = settings if settings is not None else Settings.from_env()
    if config.use_fake_backend:
        registry = registry if registry is not None else fake_registry()
        settings = fake_settings(settings)
        backend = backend if backend is not None else FakeBackend()
    else:
        registry = registry if registry is not None else load_model_registry()

    data_root = data_root if data_root is not None else data_dir()
    event_log = event_log if event_log is not None else _event_log(data_root)
    conversations = ConversationStore(data_root / "conversations")
    counter = DailyTokenCounter(
        daily_budget=config.run_token_cap if not config.use_fake_backend else None
    )
    router = LLMRouter(
        registry=registry,
        settings=settings,
        backend=backend,
        conversation_store=conversations,
        event_log=event_log,
        counter=counter,
    )
    approvals = approvals if approvals is not None else ApprovalService(data_root / "approvals")
    embedder = (
        config.embedder
        if config.embedder is not None
        else _default_embedder(registry, config, settings)
    )
    store = (
        vector_store
        if vector_store is not None
        else VectorStore(qdrant_client(config.qdrant_url), embedder, event_log=event_log)
    )
    try:
        store.ensure_collections()
    except Exception as exc:
        _LOGGER.warning("could not initialize qdrant collections: %s", exc)
    retrieval = (
        retrieval
        if retrieval is not None
        else RetrievalService(store=store, conversations=conversations)
    )
    handle = RetrievalHandle(retrieval)
    memory = MemoryWriter(
        store=store,
        event_log=event_log,
        keys_directory=config.keys_directory,
        retrieval=retrieval,
    )
    sandbox_service = (
        sandbox if sandbox is not None else SandboxService(config=_sandbox_config(config))
    )
    prompt_guard = guard or config.prompt_guard or RegexPromptGuard()

    sops = load_sops()
    try:
        sop = sops[config.sop_id]
    except KeyError as exc:
        raise KeyError(f"unknown SOP '{config.sop_id}'") from exc

    policy = AstPolicy()
    classifier = RiskClassifier(policy)
    scanners = ScannerSuite()
    gate = PreRunSecurityGate(scanners=scanners, policy=policy)
    checker = RequirementChecker(policy=policy, guard=prompt_guard)

    signer = ArtifactSigner(
        registry=registry,
        event_log=event_log,
        artifact_root=data_root / "artifacts",
        keys_directory=config.keys_directory,
    )
    deployer = DeploymentService(
        config=DeploymentConfig(probe_path=config.probe_path),
        root=config.deployment_root,
        event_log=event_log,
        keys_directory=config.keys_directory,
    )

    coder = CoderAgent(router, retrieval=handle)
    debugger = DebuggerAgent(router, retrieval=handle)
    sandbox_runner = SandboxRunnerAgent(
        sandbox_service,
        gate=gate,
        checker=checker,
        workspace_root=data_root / "workspaces",
    )
    security_gate = SecurityGateAgent(
        sandbox_service,
        scanners=scanners,
        policy=policy,
        classifier=classifier,
        guard=prompt_guard,
        declared_tier=sop.risk_tier,
    )
    security_repair = SecurityRepairAgent(
        coder=coder,
        debugger=debugger,
        sandbox_runner=sandbox_runner,
        security_gate=security_gate,
        conversations=conversations,
        max_attempts=settings.security_repair_attempts,
    )
    agents: dict[str, AgentCallable] = {
        "requirements": RequirementsAgent(router, retrieval=handle),
        "coder": coder,
        "test_designer": TestDesignerAgent(router, retrieval=handle),
        "debugger": debugger,
        "sandbox_runner": sandbox_runner,
        "security_gate": security_gate,
        "security_repair": security_repair,
        "acceptance_gate": AcceptanceGateAgent(
            sandbox_service,
            approvals=approvals,
            classifier=classifier,
            coverage_target=config.coverage_target,
            declared_tier=sop.risk_tier,
            conversations=conversations,
        ),
        "signer": SigningStep(signer=signer, approvals=approvals),
        "deployer": DeploymentStep(service=deployer, memory=memory),
    }
    gates: dict[str, GateEvaluator] = {
        "admin_approval": AdminApprovalGate(approvals),
        "risk_tier": RiskTierGate(approvals),
        "security_clean": SecurityCleanGate(),
        "acceptance": AcceptanceGate(),
        "deployment": DeploymentGate(),
    }
    engine = SopEngine(agents=agents, schemas=ARTIFACT_SCHEMAS, gates=gates)
    return Orchestrator(
        engine=engine,
        sop=sop,
        approvals=approvals,
        event_log=event_log,
        schemas=ARTIFACT_SCHEMAS,
        state_directory=data_root / "runs",
        max_phase=config.max_phase,
        retrieval=retrieval,
        artifact_root=data_root / "artifacts",
        keys_directory=config.keys_directory,
    )


def _sandbox_config(config: AppConfig) -> Any:
    from oracle_hcm.services.sandbox import SandboxConfig

    return SandboxConfig(
        image=config.sandbox_image,
        timeout_seconds=config.sandbox_timeout_seconds,
    )
