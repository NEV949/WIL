"""Command line entry point.

    python -m oracle_hcm run "Add overtime calculation"
    python -m oracle_hcm pending
    python -m oracle_hcm approve <approval_id>
    python -m oracle_hcm resume <run_id>
    python -m oracle_hcm create-admin --username admin
    python -m oracle_hcm serve

The .env file is loaded at start-up. Its contents are never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from typing import cast

from oracle_hcm.api.gateway import ApiConfig, build_api
from oracle_hcm.api.users import (
    ROLE_ADMIN,
    ROLE_USER,
    UserExistsError,
    UserRole,
    UserStore,
    WeakPasswordError,
)
from oracle_hcm.app import AppConfig, build_orchestrator
from oracle_hcm.config.env import load_env
from oracle_hcm.config.models import load_model_registry
from oracle_hcm.config.settings import Settings
from oracle_hcm.knowledge.embeddings import DeterministicEmbedder, Embedder
from oracle_hcm.knowledge.litellm_embedding import OpenAIEmbedder, build_embedder
from oracle_hcm.log.access import AccessLog
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.paths import data_dir, keys_dir
from oracle_hcm.services.approvals import ApprovalService
from oracle_hcm.services.orchestrator import Orchestrator
from oracle_hcm.signing.keys import generate_keypair, save_keypair

__all__ = ["main"]


def _embedder(name: str) -> Embedder | None:
    """The embedder of the run, chosen by name.

    The name "auto" leaves the choice to the application: the offline runs
    keep the deterministic embedder and a live run uses the embedding model
    of the configuration.
    """
    if name == "auto":
        return None
    if name == "openai":
        return OpenAIEmbedder()
    if name == "configured":
        return build_embedder(load_model_registry().require_embeddings())
    return DeterministicEmbedder()


def _approvals() -> ApprovalService:
    return ApprovalService(data_dir() / "approvals")


def _build(config: AppConfig) -> Orchestrator:
    return build_orchestrator(config)


async def _run(request: str, config: AppConfig) -> int:
    orchestrator = _build(config)
    result = await orchestrator.run(request)
    print(f"run_id: {result.run_id}")
    print(f"status: {result.status}")
    if result.approval is not None:
        print(f"approval_id: {result.approval.approval_id}")
        print(f"approval_stage: {result.approval.stage}")
        print(f"artifact: {result.approval.artifact_type}")
    if result.report is not None:
        print(f"exit_code: {result.report.exit_code}")
        print(f"tests_passed: {result.report.tests_passed}")
        print(f"tests_failed: {result.report.tests_failed}")
    if result.failure:
        print(f"failure: {result.failure}")
    return 0 if result.status == "completed" else 1


async def _resume(run_id: str, config: AppConfig) -> int:
    orchestrator = _build(config)
    result = await orchestrator.resume(run_id)
    print(f"run_id: {result.run_id}")
    print(f"status: {result.status}")
    if result.approval is not None:
        print(f"approval_id: {result.approval.approval_id}")
        print(f"approval_stage: {result.approval.stage}")
    if result.report is not None:
        print(f"exit_code: {result.report.exit_code}")
        print(f"tests_passed: {result.report.tests_passed}")
        print(f"tests_failed: {result.report.tests_failed}")
    if result.failure:
        print(f"failure: {result.failure}")
    return 0 if result.status == "completed" else 1


def _pending() -> int:
    service = _approvals()
    requests = service.pending()
    if not requests:
        print("no pending approvals")
        return 0
    for request in requests:
        print(f"{request.approval_id} stage={request.stage} artifact={request.artifact_type}")
    return 0


def _keygen() -> int:
    """Create the signing key of the host, when it does not exist yet."""
    directory = keys_dir()
    private_path = directory / "signer_private.pem"
    if private_path.is_file():
        print(f"the signing key already exists: {private_path}")
        return 0
    private_path, public_path = save_keypair(generate_keypair(), directory)
    print(f"private key: {private_path}")
    print(f"public key: {public_path}")
    return 0


def _approve(approval_id: str, approve: bool) -> int:
    service = _approvals()
    request = service.decide(approval_id, approved=approve, decided_by="admin")
    print(f"{request.approval_id} -> {request.status}")
    return 0


def _create_admin(username: str, tenant_id: str, role: str) -> int:
    """Create a user and store the hash of its password.

    The password is read from the terminal and never from the command line,
    so it does not end up in the shell history or in the list of processes.
    """
    password = getpass.getpass("password: ")
    confirmation = getpass.getpass("password again: ")
    if password != confirmation:
        print("the two passwords do not match")
        return 1
    store = UserStore()
    try:
        user = store.create(
            user_id=username,
            password=password,
            role=cast(UserRole, role),
            tenant_id=tenant_id,
        )
    except UserExistsError as exc:
        print(str(exc))
        return 1
    except WeakPasswordError as exc:
        print(str(exc))
        return 1
    print(f"user '{user.user_id}' created with the role '{user.role}'")
    print(f"users file: {store.path}")
    return 0


def _serve(config: AppConfig, host: str, port: int) -> int:
    """Run the HTTP gateway."""
    import uvicorn

    settings = Settings.from_env()
    orchestrator = _build(config)
    root = data_dir()
    app = build_api(
        config=ApiConfig(
            host=host,
            port=port,
            cors_origins=settings.cors_origins,
            max_request_bytes=settings.max_request_bytes,
            jwt_ttl_seconds=settings.jwt_ttl_seconds,
            cookie_secure=settings.cookie_secure,
            login_max_attempts=settings.login_max_attempts,
            login_window_seconds=settings.login_window_seconds,
            login_lockout_seconds=settings.login_lockout_seconds,
            login_max_attempts_per_ip=settings.login_max_attempts_per_ip,
            keep_alive_seconds=settings.keep_alive_seconds,
            web_dist=settings.web_dist_path(),
        ),
        orchestrator=orchestrator,
        event_log=EventLog(root / "audit.jsonl"),
        approvals=ApprovalService(root / "approvals"),
        access_log=AccessLog(root / "access.jsonl"),
        users=UserStore(),
        settings=settings,
    )
    print(f"the gateway listens on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse the command line and run the requested command."""
    load_env()
    parser = argparse.ArgumentParser(prog="oracle_hcm")
    parser.add_argument("--sop", default="sop_lightweight")
    parser.add_argument("--live", action="store_true", help="use the configured models")
    parser.add_argument(
        "--token-cap",
        type=int,
        default=60_000,
        dest="token_cap",
        help="per-run token budget (live backend only; default 60000)",
    )
    parser.add_argument(
        "--embeddings",
        choices=["auto", "deterministic", "openai", "configured"],
        default="auto",
        help="the embedder of the knowledge store",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="start a run")
    run_parser.add_argument("request")

    sub.add_parser("pending", help="list the pending approvals")

    approve_parser = sub.add_parser("approve", help="decide an approval")
    approve_parser.add_argument("approval_id")
    approve_parser.add_argument("--reject", action="store_true")

    resume_parser = sub.add_parser("resume", help="continue a suspended run")
    resume_parser.add_argument("run_id")

    sub.add_parser("keygen", help="create the signing key of the host")

    admin_parser = sub.add_parser("create-admin", help="create a user of the gateway")
    admin_parser.add_argument("--username", required=True)
    admin_parser.add_argument("--tenant", default="default")
    admin_parser.add_argument("--role", choices=[ROLE_ADMIN, ROLE_USER], default=ROLE_ADMIN)

    serve_parser = sub.add_parser("serve", help="run the HTTP gateway")
    serve_parser.add_argument("--host", default=None, help="the address to bind to")
    serve_parser.add_argument("--port", type=int, default=None)

    args = parser.parse_args(argv)
    config = AppConfig(
        sop_id=args.sop,
        use_fake_backend=not args.live,
        embedder=_embedder(args.embeddings),
        run_token_cap=args.token_cap,
    )

    if args.command == "run":
        return asyncio.run(_run(args.request, config))
    if args.command == "resume":
        return asyncio.run(_resume(args.run_id, config))
    if args.command == "pending":
        return _pending()
    if args.command == "approve":
        return _approve(args.approval_id, not args.reject)
    if args.command == "keygen":
        return _keygen()
    if args.command == "create-admin":
        return _create_admin(args.username, args.tenant, args.role)
    if args.command == "serve":
        settings = Settings.from_env()
        host = args.host or settings.api_host
        port = args.port or settings.api_port
        return _serve(config, host, port)
    return 1


if __name__ == "__main__":
    sys.exit(main())
