"""Users of the gateway.

The users live in one JSON file, ``data/users.json``, which is part of the
ignored ``data`` directory: the file holds password hashes and never leaves
the host. A password is stored as an Argon2 hash; the plain password is only
ever read from the terminal, with ``getpass``, and is never logged, printed
or returned.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from pydantic import BaseModel, ConfigDict, Field

from oracle_hcm.paths import data_dir
from oracle_hcm.schemas.artifacts import utc_now_iso

__all__ = [
    "MIN_PASSWORD_LENGTH",
    "ROLE_ADMIN",
    "ROLE_USER",
    "UserExistsError",
    "UserRecord",
    "UserStore",
    "WeakPasswordError",
]

UserRole = Literal["admin", "user"]

ROLE_ADMIN: UserRole = "admin"
ROLE_USER: UserRole = "user"

MIN_PASSWORD_LENGTH = 12
"""The shortest password the gateway accepts."""

_DUMMY_HASH = (
    "$argon2id$v=19$m=8192,t=1,p=1$1aCfs/HCtdw+PvOnRGH0lA"
    "$o7P6eyL6S9wlDsLsrtjc7Wg2+jCWGSx+7UkMfhF+eh8"
)
"""A hash of a value nobody knows, used to keep the timing of a failed login constant."""


class UserExistsError(Exception):
    """The user is already known."""


class WeakPasswordError(Exception):
    """The password is too short to be accepted."""


class UserRecord(BaseModel):
    """One user of the gateway."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    role: UserRole
    tenant_id: str
    password_hash: str
    created_at: str
    disabled: bool = False


class _UserFile(BaseModel):
    """The shape of the file on disk."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    users: dict[str, UserRecord] = Field(default_factory=dict)


class UserStore:
    """The users of the gateway, on disk."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        hasher: PasswordHasher | None = None,
    ) -> None:
        self._path = path if path is not None else data_dir() / "users.json"
        self._hasher = hasher if hasher is not None else PasswordHasher()
        self._lock = threading.RLock()  # reentrant: create() saves while it holds the lock
        self._users: dict[str, UserRecord] = {}
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> None:
        if not self._path.is_file():
            return
        data = json.loads(self._path.read_text(encoding="utf-8"))
        self._users = _UserFile.model_validate(data).users

    def save(self) -> None:
        """Write the users to disk."""
        with self._lock:
            payload = _UserFile(version=1, users=dict(self._users))
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                payload.model_dump_json(indent=2),
                encoding="utf-8",
            )

    def create(
        self,
        *,
        user_id: str,
        password: str,
        role: UserRole = ROLE_ADMIN,
        tenant_id: str = "default",
    ) -> UserRecord:
        """Create a user and store the hash of its password."""
        if len(password) < MIN_PASSWORD_LENGTH:
            raise WeakPasswordError(
                f"the password must hold at least {MIN_PASSWORD_LENGTH} characters"
            )
        with self._lock:
            if user_id in self._users:
                raise UserExistsError(f"the user '{user_id}' already exists")
            record = UserRecord(
                user_id=user_id,
                role=role,
                tenant_id=tenant_id,
                password_hash=self._hasher.hash(password),
                created_at=utc_now_iso(),
            )
            self._users[user_id] = record
            self.save()
            return record

    def get(self, user_id: str) -> UserRecord | None:
        """The user of this id, if it exists."""
        return self._users.get(user_id)

    def list_users(self) -> list[UserRecord]:
        """Every user, ordered by id."""
        return [self._users[key] for key in sorted(self._users)]

    def authenticate(self, user_id: str, password: str) -> UserRecord | None:
        """The user of this id, when the password matches.

        The check runs against a hash of an unknown value when the user does
        not exist, so that a missing user and a wrong password take the same
        time.
        """
        record = self._users.get(user_id)
        candidate = record.password_hash if record is not None else _DUMMY_HASH
        try:
            verified = bool(self._hasher.verify(candidate, password))
        except (VerificationError, InvalidHashError):
            verified = False
        if record is None or not verified or record.disabled:
            return None
        return record
