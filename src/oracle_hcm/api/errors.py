"""Errors of the HTTP gateway.

Every error of the gateway carries the status code it maps to, so the
handlers never have to guess it.
"""

from __future__ import annotations

from oracle_hcm.errors import OracleHcmError

__all__ = [
    "ApiError",
    "AuthenticationError",
    "ConflictError",
    "NotFoundError",
    "PayloadTooLargeError",
    "PermissionDeniedError",
    "RateLimitedError",
]


class ApiError(OracleHcmError):
    """Base class of the errors of the gateway."""

    status_code = 400
    code = "bad_request"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class AuthenticationError(ApiError):
    """The caller is not authenticated, or its session is over."""

    status_code = 401
    code = "unauthenticated"


class PermissionDeniedError(ApiError):
    """The caller may not perform this action."""

    status_code = 403
    code = "forbidden"


class NotFoundError(ApiError):
    """The object does not exist, or belongs to another tenant."""

    status_code = 404
    code = "not_found"


class ConflictError(ApiError):
    """The object changed under the caller, or is not in the expected state."""

    status_code = 409
    code = "conflict"


class PayloadTooLargeError(ApiError):
    """The request body is larger than the gateway accepts."""

    status_code = 413
    code = "payload_too_large"


class RateLimitedError(ApiError):
    """Too many requests from this caller."""

    status_code = 429
    code = "rate_limited"

    def __init__(self, message: str, *, retry_after: int = 0) -> None:
        super().__init__(message)
        self.retry_after = retry_after
