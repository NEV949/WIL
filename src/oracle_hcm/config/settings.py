"""Runtime settings.

Keys are read from the process environment only. There is no .env file
dependency: the engine starts and runs with no keys present, and a missing key
surfaces only when a model is actually invoked.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from oracle_hcm.config.providers import PROVIDER_ENV_VARS, Provider
from oracle_hcm.errors import MissingApiKeyError
from oracle_hcm.paths import web_dist

__all__ = ["Settings"]


def _int_env(source: Mapping[str, str], name: str, default: int) -> int:
    """Read an integer from the environment, keeping the default on garbage."""
    raw = source.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _bool_env(source: Mapping[str, str], name: str, default: bool) -> bool:
    """Read a boolean from the environment."""
    raw = source.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    """Immutable view of the environment-derived configuration."""

    api_keys: Mapping[str, str] = field(default_factory=dict, repr=False)
    jwt_secret: str | None = field(default=None, repr=False)
    jwt_ttl_seconds: int = 3600
    cors_origins: tuple[str, ...] = ()
    max_request_bytes: int = 65536
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    cookie_secure: bool = False
    login_max_attempts: int = 5
    login_window_seconds: int = 900
    login_lockout_seconds: int = 900
    login_max_attempts_per_ip: int = 30
    keep_alive_seconds: float = 15.0
    request_timeout_seconds: float = 90.0
    chain_timeout_seconds: float = 120.0
    security_repair_attempts: int = 3
    web_dist: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        keys: dict[str, str] = {}
        for provider, var in PROVIDER_ENV_VARS.items():
            value = source.get(var, "").strip()
            if value:
                keys[provider.value] = value
        jwt_secret = source.get("JWT_SECRET", "").strip()
        origins = tuple(
            origin.strip()
            for origin in source.get("ORACLE_HCM_CORS_ORIGINS", "").split(",")
            if origin.strip()
        )
        return cls(
            api_keys=keys,
            jwt_secret=jwt_secret or None,
            jwt_ttl_seconds=_int_env(source, "ORACLE_HCM_JWT_TTL_SECONDS", 3600),
            cors_origins=origins,
            max_request_bytes=_int_env(source, "ORACLE_HCM_MAX_REQUEST_BYTES", 65536),
            api_host=source.get("ORACLE_HCM_API_HOST", "").strip() or "127.0.0.1",
            api_port=_int_env(source, "ORACLE_HCM_API_PORT", 8000),
            cookie_secure=_bool_env(source, "ORACLE_HCM_COOKIE_SECURE", False),
            login_max_attempts=_int_env(source, "ORACLE_HCM_LOGIN_MAX_ATTEMPTS", 5),
            login_window_seconds=_int_env(source, "ORACLE_HCM_LOGIN_WINDOW_SECONDS", 900),
            login_lockout_seconds=_int_env(source, "ORACLE_HCM_LOGIN_LOCKOUT_SECONDS", 900),
            login_max_attempts_per_ip=_int_env(
                source, "ORACLE_HCM_LOGIN_MAX_ATTEMPTS_PER_IP", 30
            ),
            keep_alive_seconds=float(
                _int_env(source, "ORACLE_HCM_KEEP_ALIVE_SECONDS", 15)
            ),
            request_timeout_seconds=float(
                _int_env(source, "ORACLE_HCM_REQUEST_TIMEOUT_SECONDS", 90)
            ),
            chain_timeout_seconds=float(
                _int_env(source, "ORACLE_HCM_CHAIN_TIMEOUT_SECONDS", 120)
            ),
            security_repair_attempts=_int_env(
                source, "ORACLE_HCM_SECURITY_REPAIR_ATTEMPTS", 3
            ),
            web_dist=source.get("ORACLE_HCM_WEB_DIST", "").strip() or None,
        )

    def web_dist_path(self) -> Path | None:
        """The build of the console.

        The one of the environment when it is set, the one of the checkout
        when it exists. Without a build the gateway serves the API alone.
        """
        if self.web_dist:
            return Path(self.web_dist)
        candidate = web_dist()
        return candidate if candidate.is_dir() else None

    def api_key(self, provider: Provider) -> str | None:
        return self.api_keys.get(provider.value)

    def require_api_key(self, provider: Provider) -> str:
        key = self.api_key(provider)
        if not key:
            raise MissingApiKeyError(provider)
        return key
