"""The HTTP gateway.

The gateway is thin: it authenticates the caller, checks its role and its
tenant, and then calls the methods of the orchestrator. It keeps no state of
its own beyond the sessions, and it never returns a secret.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from oracle_hcm.api.auth import (
    COOKIE_NAME,
    CSRF_HEADER,
    LoginLimiter,
    Principal,
    SessionStore,
    TokenService,
)
from oracle_hcm.api.errors import (
    ApiError,
    AuthenticationError,
    ConflictError,
    NotFoundError,
    PayloadTooLargeError,
    PermissionDeniedError,
)
from oracle_hcm.api.models import (
    ApprovalDecisionRequest,
    ApprovalView,
    ArtifactView,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    MetricsView,
    TaskCreatedResponse,
    TaskCreateRequest,
    TaskEventView,
    TaskSummary,
    TaskView,
)
from oracle_hcm.api.runs import RunManager
from oracle_hcm.api.static import SPA_CSP, WebConsole
from oracle_hcm.api.stream import EventStream
from oracle_hcm.api.tasks import TaskService, artifact_hash
from oracle_hcm.api.users import ROLE_ADMIN, UserStore
from oracle_hcm.config.settings import Settings
from oracle_hcm.log.access import AccessLog
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.schemas.events import AuditEvent
from oracle_hcm.services.approvals import ApprovalService
from oracle_hcm.services.orchestrator import Orchestrator

__all__ = ["ApiConfig", "build_api"]

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
"""The methods that do not change anything, and need no CSRF token."""

KEEP_ALIVE_SECONDS = 15.0
"""How long the stream waits before it sends a keep-alive."""

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}



@dataclass(frozen=True)
class ApiConfig:
    """How the gateway is started."""

    host: str = "127.0.0.1"
    port: int = 8000
    cors_origins: tuple[str, ...] = ()
    max_request_bytes: int = 65536
    jwt_ttl_seconds: int = 3600
    cookie_secure: bool = False
    login_max_attempts: int = 5
    login_window_seconds: int = 900
    login_lockout_seconds: int = 900
    login_max_attempts_per_ip: int = 30
    keep_alive_seconds: float = KEEP_ALIVE_SECONDS
    web_dist: Path | None = None
    """The build of the console. Without one the gateway serves the API alone."""

    @classmethod
    def from_settings(cls, settings: Settings) -> ApiConfig:
        """The configuration of the gateway, taken from the environment."""
        return cls(
            host=settings.api_host,
            port=settings.api_port,
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
        )


class _Gateway:
    """The state the routes share."""

    def __init__(
        self,
        *,
        config: ApiConfig,
        orchestrator: Orchestrator,
        event_log: EventLog,
        approvals: ApprovalService,
        access_log: AccessLog,
        users: UserStore,
        sessions: SessionStore,
        tokens: TokenService,
        limiter: LoginLimiter,
        tasks: TaskService,
        runs: RunManager,
        stream: EventStream,
    ) -> None:
        self.config = config
        self.orchestrator = orchestrator
        self.event_log = event_log
        self.approvals = approvals
        self.access_log = access_log
        self.users = users
        self.sessions = sessions
        self.tokens = tokens
        self.limiter = limiter
        self.tasks = tasks
        self.runs = runs
        self.stream = stream


def _client_ip(request: Request) -> str:
    """The address of the client.

    The address of the proxy is used when the request goes through one: the
    headers that name the real client are not trusted, because anybody may
    send them.
    """
    client = request.client
    return client.host if client is not None else "unknown"


def _iso(moment: float) -> str:
    """A moment as an ISO timestamp."""
    return datetime.fromtimestamp(moment, tz=UTC).isoformat()


def _error_response(exc: ApiError) -> JSONResponse:
    """The JSON body of an error."""
    headers: dict[str, str] = {}
    retry_after = getattr(exc, "retry_after", 0)
    if retry_after:
        headers["Retry-After"] = str(retry_after)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.code, "message": exc.message},
        headers=headers,
    )


def _event_payload(event: AuditEvent) -> dict[str, Any]:
    """The body of one event of the stream."""
    return {
        "event_id": event.event_id,
        "seq": event.seq,
        "timestamp": event.timestamp,
        "tenant_id": event.tenant_id,
        "actor": event.actor,
        "action": event.action,
        "payload": event.payload,
    }


async def _call[T](function: Callable[..., T], *args: Any) -> T:
    """Run a blocking call of the services in a worker thread."""
    return await asyncio.to_thread(function, *args)


def build_api(
    *,
    config: ApiConfig | None = None,
    orchestrator: Orchestrator,
    event_log: EventLog,
    approvals: ApprovalService,
    access_log: AccessLog,
    users: UserStore,
    settings: Settings,
    sessions: SessionStore | None = None,
    tokens: TokenService | None = None,
    limiter: LoginLimiter | None = None,
    tasks: TaskService | None = None,
    runs: RunManager | None = None,
    stream: EventStream | None = None,
) -> FastAPI:
    """Assemble the gateway."""
    config = config if config is not None else ApiConfig.from_settings(settings)
    secret = settings.jwt_secret
    if not secret:
        raise PermissionDeniedError(
            "the gateway needs a JWT secret: set JWT_SECRET in the environment"
        )
    sessions = (
        sessions if sessions is not None else SessionStore(ttl_seconds=config.jwt_ttl_seconds)
    )
    tokens = (
        tokens
        if tokens is not None
        else TokenService(secret, ttl_seconds=config.jwt_ttl_seconds)
    )
    limiter = (
        limiter
        if limiter is not None
        else LoginLimiter(
            max_attempts=config.login_max_attempts,
            window_seconds=config.login_window_seconds,
            lockout_seconds=config.login_lockout_seconds,
            max_attempts_per_ip=config.login_max_attempts_per_ip,
        )
    )
    runs = runs if runs is not None else RunManager(orchestrator=orchestrator, event_log=event_log)
    stream = stream if stream is not None else EventStream(event_log)
    tasks = (
        tasks
        if tasks is not None
        else TaskService(
            event_log=event_log,
            approvals=approvals,
            runs_directory=orchestrator.state_directory,
            artifact_root=orchestrator.artifact_root,
            keys_directory=orchestrator.keys_directory,
        )
    )
    state = _Gateway(
        config=config,
        orchestrator=orchestrator,
        event_log=event_log,
        approvals=approvals,
        access_log=access_log,
        users=users,
        sessions=sessions,
        tokens=tokens,
        limiter=limiter,
        tasks=tasks,
        runs=runs,
        stream=stream,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Tail the audit log while the gateway serves."""
        await state.stream.start()
        try:
            yield
        finally:
            await state.stream.stop()
            await state.runs.shutdown()

    app = FastAPI(
        title="Oracle-HCM gateway",
        version="1.0",
        description="The thin HTTP gateway of the auto-coding engine.",
        lifespan=lifespan,
    )
    app.state.gateway = state

    if config.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(config.cors_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", CSRF_HEADER],
            max_age=600,
        )

    @app.middleware("http")
    async def _guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Refuse an oversized body, and answer with the security headers."""
        length = request.headers.get("content-length")
        if length is not None:
            try:
                size = int(length)
            except ValueError:
                size = 0
            if size > config.max_request_bytes:
                return _error_response(
                    PayloadTooLargeError(
                        f"the request body is larger than {config.max_request_bytes} bytes"
                    )
                )
        response = await call_next(request)
        renewed_session = getattr(request.state, "renewed_session", None)
        if renewed_session is not None:
            token = state.tokens.issue(renewed_session)
            response.set_cookie(
                key=COOKIE_NAME,
                value=token,
                max_age=config.jwt_ttl_seconds,
                httponly=True,
                samesite="strict",
                secure=config.cookie_secure,
                path="/",
            )
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        """Every error of the gateway is a JSON body without any internals."""
        return _error_response(exc)

    # --- the dependencies ----------------------------------------------

    async def current_principal(request: Request) -> Principal:
        """The caller of the request."""
        token = request.cookies.get(COOKIE_NAME)
        if not token:
            raise AuthenticationError("the request carries no session")
        try:
            claims = state.tokens.decode(token)
        except AuthenticationError as exc:
            raise AuthenticationError("the session token is not valid") from exc
        session = state.sessions.touch(claims.get("sid", ""))
        if session is None:
            raise AuthenticationError("the session has expired")
        request.state.renewed_session = session
        return Principal(
            user_id=session.user_id,
            tenant_id=session.tenant_id,
            role=session.role,
            session_id=session.session_id,
        )

    async def admin_principal(request: Request) -> Principal:
        """The caller of the request, when it is an administrator."""
        principal = await current_principal(request)
        if principal.role != ROLE_ADMIN:
            raise PermissionDeniedError("this action needs the role 'admin'")
        return principal

    async def verified_principal(request: Request) -> Principal:
        """The caller of the request, when it carries a valid CSRF token."""
        principal = await current_principal(request)
        if request.method in SAFE_METHODS:
            return principal
        session = state.sessions.get(principal.session_id)
        provided = request.headers.get(CSRF_HEADER, "")
        if session is None or not provided:
            raise PermissionDeniedError("the CSRF token is missing")
        if not secrets.compare_digest(provided, session.csrf_token):
            raise PermissionDeniedError("the CSRF token is not valid")
        return principal

    # --- the routes ----------------------------------------------------

    @app.get("/health")
    async def health() -> dict[str, str]:
        """The gateway is up."""
        return {"status": "ok"}

    @app.post("/auth/login")
    async def login(
        payload: LoginRequest, request: Request, response: Response
    ) -> LoginResponse:
        """Open a session and hand the cookie to the caller."""
        ip = _client_ip(request)
        state.limiter.check(user_id=payload.username, ip=ip)
        state.limiter.record_attempt(ip=ip)
        user = state.users.authenticate(payload.username, payload.password)
        if user is None:
            state.limiter.record_failure(user_id=payload.username)
            state.access_log.record(
                user_id=payload.username,
                action="login",
                target="session",
                result="failure",
                tenant_id="unknown",
                ip=ip,
                detail="the credentials were refused",
            )
            raise AuthenticationError("the credentials are not valid")
        state.limiter.record_success(user_id=user.user_id)
        session = state.sessions.create(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            role=user.role,
        )
        token = state.tokens.issue(session)
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            max_age=config.jwt_ttl_seconds,
            httponly=True,
            samesite="strict",
            secure=config.cookie_secure,
            path="/",
        )
        state.access_log.record(
            user_id=user.user_id,
            action="login",
            target="session",
            result="success",
            tenant_id=user.tenant_id,
            ip=ip,
            correlation_id=session.session_id,
        )
        return LoginResponse(
            user_id=user.user_id,
            role=user.role,
            tenant_id=user.tenant_id,
            csrf_token=session.csrf_token,
            expires_at=_iso(session.expires_at),
        )

    @app.post("/auth/logout")
    async def logout(
        request: Request, response: Response, principal: Principal = Depends(verified_principal)
    ) -> LogoutResponse:
        """Close the session of the caller."""
        state.sessions.drop(principal.session_id)
        response.delete_cookie(key=COOKIE_NAME, path="/")
        state.access_log.record(
            user_id=principal.user_id,
            action="logout",
            target="session",
            result="success",
            tenant_id=principal.tenant_id,
            ip=_client_ip(request),
            correlation_id=principal.session_id,
        )
        return LogoutResponse(user_id=principal.user_id)

    @app.post("/tasks")
    async def create_task(
        payload: TaskCreateRequest,
        request: Request,
        principal: Principal = Depends(verified_principal),
    ) -> TaskCreatedResponse:
        """Submit a requirement and start its run in the background."""
        task_id = state.runs.new_task_id()
        state.event_log.append(
            tenant_id=principal.tenant_id,
            actor=principal.user_id,
            action="task_submitted",
            payload={
                "run_id": task_id,
                "sop_id": payload.sop_id,
                "correlation_id": principal.session_id,
            },
        )
        state.access_log.record(
            user_id=principal.user_id,
            action="task_submit",
            target=task_id,
            result="success",
            tenant_id=principal.tenant_id,
            ip=_client_ip(request),
            correlation_id=principal.session_id,
        )
        await state.runs.start(
            task_id=task_id,
            request=payload.request,
            tenant_id=principal.tenant_id,
        )
        return TaskCreatedResponse(
            task_id=task_id,
            tenant_id=principal.tenant_id,
            status="running",
            stage="started",
        )

    @app.get("/tasks")
    async def list_tasks(
        principal: Principal = Depends(current_principal),
    ) -> list[TaskSummary]:
        """The tasks of the tenant of the caller."""
        return await _call(state.tasks.list_tasks, principal.tenant_id)

    @app.get("/tasks/{task_id}")
    async def get_task(
        task_id: str, principal: Principal = Depends(current_principal)
    ) -> TaskView:
        """One task of the tenant of the caller."""
        return await _call(state.tasks.get_task, task_id, principal.tenant_id)

    @app.get("/tasks/{task_id}/events")
    async def task_events(
        task_id: str, principal: Principal = Depends(current_principal)
    ) -> list[TaskEventView]:
        """The audit events of one task."""
        return await _call(state.tasks.task_events, task_id, principal.tenant_id)

    @app.get("/tasks/{task_id}/artifact")
    async def task_artifact(
        task_id: str, principal: Principal = Depends(current_principal)
    ) -> ArtifactView:
        """The signed manifest of one task and its verification status."""
        return await _call(state.tasks.artifact, task_id, principal.tenant_id)

    @app.get("/events/stream")
    async def events_stream(
        request: Request,
        since: int = 0,
        principal: Principal = Depends(current_principal),
    ) -> StreamingResponse:
        """The audit events of the tenant of the caller, as they happen."""
        return StreamingResponse(
            _sse(state, request, principal, since),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @app.get("/approvals/pending")
    async def pending_approvals(
        principal: Principal = Depends(admin_principal),
    ) -> list[ApprovalView]:
        """The approvals that wait for a decision."""
        return await _call(state.tasks.pending_approvals, principal.tenant_id)

    @app.post("/approvals/{approval_id}/decide")
    async def decide_approval(
        approval_id: str,
        payload: ApprovalDecisionRequest,
        request: Request,
        principal: Principal = Depends(verified_principal),
    ) -> ApprovalView:
        """Record the decision of an administrator on one approval."""
        if principal.role != ROLE_ADMIN:
            raise PermissionDeniedError("this action needs the role 'admin'")
        approval = await _call(state.tasks.approval, approval_id, principal.tenant_id)
        current = artifact_hash(approval.artifact)
        if current != payload.artifact_hash:
            state.access_log.record(
                user_id=principal.user_id,
                action="approval",
                target=approval_id,
                result="denied",
                tenant_id=principal.tenant_id,
                ip=_client_ip(request),
                correlation_id=principal.session_id,
                detail="the hash of the artifact does not match",
            )
            raise ConflictError(
                "the artifact changed since it was shown: the decision is refused"
            )
        approved = payload.decision == "approved"
        decided = state.approvals.decide(
            approval_id,
            approved=approved,
            decided_by=principal.user_id,
            note=payload.comment,
            artifact_hash=current,
        )
        state.event_log.append(
            tenant_id=principal.tenant_id,
            actor=principal.user_id,
            action="approval_decided",
            payload={
                "run_id": approval.run_id,
                "approval_id": approval_id,
                "decision": payload.decision,
                "comment": payload.comment,
                "artifact_hash": current,
                "correlation_id": principal.session_id,
            },
        )
        state.access_log.record(
            user_id=principal.user_id,
            action="approval",
            target=approval_id,
            result="success",
            tenant_id=principal.tenant_id,
            ip=_client_ip(request),
            correlation_id=principal.session_id,
            detail=f"{payload.decision} {current}",
        )
        if approved:
            await state.runs.resume(task_id=approval.run_id)
        return state.tasks.approval_view(decided)

    @app.get("/metrics")
    async def metrics(principal: Principal = Depends(current_principal)) -> MetricsView:
        """The counters of the tenant of the caller."""
        return await _call(state.tasks.metrics, principal.tenant_id)

    if config.web_dist is not None:
        console = WebConsole(config.web_dist)

        @app.get("/{spa_path:path}", include_in_schema=False)
        async def web_console(spa_path: str) -> Response:
            """The console: the files of the build, and the shell for the routes.

            This route is the last one: every route of the API is matched
            before it, and the answers of the API never come from here.
            """
            target = console.file_for(spa_path)
            if target is None:
                target = console.index
            if not target.is_file():
                raise NotFoundError(
                    "the console is not built: run the build of the web app"
                )
            return FileResponse(
                target,
                headers={
                    "Content-Security-Policy": SPA_CSP,
                    "Cache-Control": console.cache_control(target),
                },
            )

    return app


async def _sse(
    state: _Gateway,
    request: Request,
    principal: Principal,
    since: int,
) -> AsyncIterator[str]:
    """The events of the tenant of the caller, in the SSE format."""
    stream = state.stream.subscribe(
        principal.tenant_id,
        since_seq=since,
        idle_seconds=state.config.keep_alive_seconds,
    )
    try:
        async for event in stream:
            if await request.is_disconnected():
                break
            if event is None:
                yield ": keep-alive\n\n"
                continue
            yield f"event: {event.action}\ndata: {json.dumps(_event_payload(event))}\n\n"
    finally:
        await stream.aclose()
