"""The HTTP gateway of the engine.

The package holds the users, the sessions, the thin gateway itself and the
services it calls. It never talks to a provider and never holds a key.
"""

from __future__ import annotations

from oracle_hcm.api.auth import (
    COOKIE_NAME,
    CSRF_HEADER,
    LoginLimiter,
    Principal,
    Session,
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
    RateLimitedError,
)
from oracle_hcm.api.gateway import ApiConfig, build_api
from oracle_hcm.api.runs import RunManager
from oracle_hcm.api.stream import EventStream
from oracle_hcm.api.tasks import TaskService
from oracle_hcm.api.users import ROLE_ADMIN, ROLE_USER, UserRecord, UserStore

__all__ = [
    "COOKIE_NAME",
    "CSRF_HEADER",
    "ROLE_ADMIN",
    "ROLE_USER",
    "ApiConfig",
    "ApiError",
    "AuthenticationError",
    "ConflictError",
    "EventStream",
    "LoginLimiter",
    "NotFoundError",
    "PayloadTooLargeError",
    "PermissionDeniedError",
    "Principal",
    "RateLimitedError",
    "RunManager",
    "Session",
    "SessionStore",
    "TaskService",
    "TokenService",
    "UserRecord",
    "UserStore",
    "build_api",
]
