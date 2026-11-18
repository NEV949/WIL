"""Sessions, tokens and the protection of the login.

A session lives on the server; the browser only holds a short-lived JWT in
an httpOnly cookie. The session carries the CSRF token of the caller, which
the client has to send back in a header on every state-changing request: a
cross-site form cannot read it, so it cannot forge such a request.

A login that fails too often locks the account for a while, and an address
that tries too often is refused before the password is even checked.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

import jwt

from oracle_hcm.api.errors import AuthenticationError, RateLimitedError
from oracle_hcm.api.users import ROLE_ADMIN

__all__ = [
    "COOKIE_NAME",
    "CSRF_HEADER",
    "LoginLimiter",
    "LoginLockedError",
    "Principal",
    "Session",
    "SessionStore",
    "TokenService",
]

COOKIE_NAME = "oracle_hcm_session"
"""The name of the cookie that carries the JWT."""

CSRF_HEADER = "X-CSRF-Token"
"""The header that carries the CSRF token of the caller."""

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "oracle-hcm"


class LoginLockedError(RateLimitedError):
    """The account is locked after too many failed logins."""

    code = "account_locked"


@dataclass(frozen=True)
class Principal:
    """The authenticated caller."""

    user_id: str
    tenant_id: str
    role: str
    session_id: str

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN


@dataclass(frozen=True)
class Session:
    """One session of the gateway."""

    session_id: str
    user_id: str
    tenant_id: str
    role: str
    csrf_token: str
    created_at: float
    expires_at: float


class SessionStore:
    """The sessions of the gateway, in memory."""

    def __init__(self, *, ttl_seconds: int = 3600) -> None:
        self._ttl = ttl_seconds
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def create(self, *, user_id: str, tenant_id: str, role: str) -> Session:
        """Open a session for a user."""
        now = time.time()
        session = Session(
            session_id=secrets.token_urlsafe(24),
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + self._ttl,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        """The session, when it exists and is not over."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.expires_at <= time.time():
                del self._sessions[session_id]
                return None
            return session

    def touch(self, session_id: str) -> Session | None:
        """Extend the lifetime of an active session by ttl_seconds."""
        now = time.time()
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.expires_at <= now:
                del self._sessions[session_id]
                return None
            renewed = Session(
                session_id=session.session_id,
                user_id=session.user_id,
                tenant_id=session.tenant_id,
                role=session.role,
                csrf_token=session.csrf_token,
                created_at=session.created_at,
                expires_at=now + self._ttl,
            )
            self._sessions[session_id] = renewed
            return renewed

    def drop(self, session_id: str) -> None:
        """Close a session."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def purge_expired(self) -> int:
        """Drop the sessions that are over, and return how many were dropped."""
        now = time.time()
        with self._lock:
            expired = [key for key, session in self._sessions.items() if session.expires_at <= now]
            for key in expired:
                del self._sessions[key]
        return len(expired)


class TokenService:
    """Issues and checks the JWT of a session."""

    def __init__(self, secret: str, *, ttl_seconds: int = 3600) -> None:
        self._secret = secret
        self._ttl = ttl_seconds

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def issue(self, session: Session) -> str:
        """The token that carries the session."""
        now = int(time.time())
        payload = {
            "sub": session.user_id,
            "tid": session.tenant_id,
            "role": session.role,
            "sid": session.session_id,
            "iss": JWT_ISSUER,
            "iat": now,
            "exp": int(session.expires_at),
        }
        return jwt.encode(payload, self._secret, algorithm=JWT_ALGORITHM)

    def decode(self, token: str) -> dict[str, str]:
        """The claims of a token, when it is valid and not expired."""
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=[JWT_ALGORITHM],
                issuer=JWT_ISSUER,
                options={"require": ["exp", "iat", "sub", "sid"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError("the session token is not valid") from exc
        return {key: str(value) for key, value in claims.items()}


@dataclass
class _Failure:
    """The failed logins of one account."""

    moments: list[float] = field(default_factory=list)
    locked_until: float = 0.0


class LoginLimiter:
    """Rate limits the logins and locks an account that fails too often."""

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        window_seconds: int = 900,
        lockout_seconds: int = 900,
        max_attempts_per_ip: int = 30,
    ) -> None:
        self._max_attempts = max_attempts
        self._window = window_seconds
        self._lockout = lockout_seconds
        self._max_attempts_per_ip = max_attempts_per_ip
        self._failures: dict[str, _Failure] = {}
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, moments: list[float], now: float) -> list[float]:
        return [moment for moment in moments if moment > now - self._window]

    def check(self, *, user_id: str, ip: str | None) -> None:
        """Refuse a login that is locked or that comes from a busy address."""
        now = time.time()
        with self._lock:
            failure = self._failures.get(user_id)
            if failure is not None and failure.locked_until > now:
                retry = int(failure.locked_until - now)
                raise LoginLockedError(
                    f"the account is locked for another {retry} second(s)",
                    retry_after=retry,
                )
            attempts = self._prune(self._attempts.get(ip or "", []), now)
            self._attempts[ip or ""] = attempts
            if len(attempts) >= self._max_attempts_per_ip:
                retry = int(self._window - (now - attempts[0]))
                raise RateLimitedError(
                    f"too many login attempts from this address, retry in {retry} second(s)",
                    retry_after=max(retry, 1),
                )

    def record_attempt(self, *, ip: str | None) -> None:
        """Count one attempt of an address."""
        now = time.time()
        with self._lock:
            key = ip or ""
            attempts = self._prune(self._attempts.get(key, []), now)
            attempts.append(now)
            self._attempts[key] = attempts

    def record_failure(self, *, user_id: str) -> None:
        """Count a failed login, and lock the account when there are too many."""
        now = time.time()
        with self._lock:
            failure = self._failures.setdefault(user_id, _Failure())
            failure.moments = self._prune(failure.moments, now)
            failure.moments.append(now)
            if len(failure.moments) >= self._max_attempts:
                failure.locked_until = now + self._lockout
                failure.moments.clear()

    def record_success(self, *, user_id: str) -> None:
        """Forget the failed logins of an account."""
        with self._lock:
            self._failures.pop(user_id, None)

    def locked_until(self, user_id: str) -> float:
        """The moment the account is unlocked again."""
        with self._lock:
            failure = self._failures.get(user_id)
            return failure.locked_until if failure is not None else 0.0
