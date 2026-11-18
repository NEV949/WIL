"""The static files of the console.

The console is a PWA built by Vite into a directory of plain files. The
gateway serves that directory from its root, so the page and the API share
one origin: the cookie of the session and the CSRF token work without any
cross-site dance.

The rules are narrow on purpose. Only the files of the build are served, a
path never leaves the directory of the build, and the answers of the API are
never served from here: the caller of the API always reaches the API.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = ["IMMUTABLE_CACHE", "NO_STORE_CACHE", "SPA_CSP", "WebConsole"]

SPA_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "manifest-src 'self'; "
    "worker-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)
"""The policy of the console.

There is no inline script and no inline style: everything the page needs comes
from a file of the build.
"""

IMMUTABLE_CACHE = "public, max-age=31536000, immutable"
"""The cache of the assets whose name carries a hash: they never change."""

NO_STORE_CACHE = "no-store"
"""The cache of the shell: the index must never be kept by a browser."""

HASHED_DIRECTORY = "assets"
"""The directory of the build that holds the hashed assets."""


@dataclass(frozen=True)
class WebConsole:
    """The build of the console."""

    root: Path

    @property
    def index(self) -> Path:
        """The shell of the console."""
        return self.root / "index.html"

    def file_for(self, url_path: str) -> Path | None:
        """The file of a request, when the build holds it.

        A path that points outside of the build is refused: it is never
        resolved to a file of the host.
        """
        relative = url_path.lstrip("/")
        if relative == "":
            return self.index if self.index.is_file() else None
        root = self._root()
        try:
            candidate = (root / relative).resolve()
        except (OSError, ValueError):
            return None
        if not candidate.is_relative_to(root):
            return None
        try:
            if not candidate.is_file():
                return None
        except (OSError, ValueError):
            return None
        return candidate

    def cache_control(self, target: Path) -> str:
        """The cache of a file: the hashed assets are kept, the shell is not."""
        try:
            relative = target.relative_to(self._root())
        except ValueError:
            return NO_STORE_CACHE
        if relative.parts and relative.parts[0] == HASHED_DIRECTORY:
            return IMMUTABLE_CACHE
        return NO_STORE_CACHE

    def _root(self) -> Path:
        try:
            return self.root.resolve()
        except (OSError, ValueError):
            return self.root
