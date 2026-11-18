"""The HTTP wrapper of a deployed artifact.

The wrapper is copied into the image of the artifact. It serves the artifact
over HTTP, reports whether the artifact loads and exposes the functions of
the artifact. It never reads a key and never writes outside the temporary
directories of the container.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

WORKSPACE = "/app"
SERVICE_PORT = 8080

NAME = os.environ.get("ORACLE_SERVICE_NAME", "oracle-service")
VERSION = os.environ.get("ORACLE_SERVICE_VERSION", "")
ROOT_HASH = os.environ.get("ORACLE_ROOT_HASH", "")
FILES = [item for item in os.environ.get("ORACLE_SERVICE_FILES", "").split(",") if item]
MODULES = [item for item in os.environ.get("ORACLE_SERVICE_MODULES", "").split(",") if item]

sys.path.insert(0, WORKSPACE)

_LOADED: dict[str, Any] = {}
_ERRORS: list[str] = []


def _load() -> None:
    """Import every module of the artifact and keep the failures."""
    for name in MODULES:
        try:
            _LOADED[name] = importlib.import_module(name)
        except Exception:
            _ERRORS.append(f"{name}: {traceback.format_exc(limit=3)}")


class Handler(BaseHTTPRequestHandler):
    """The routes of the service."""

    server_version = "oracle-service/1.0"

    def log_message(self, format: str, *args: object) -> None:
        """The access log of the container carries the requests."""

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _health(self) -> None:
        healthy = not _ERRORS
        self._send(
            200 if healthy else 500,
            {
                "status": "ok" if healthy else "failed",
                "name": NAME,
                "version": VERSION,
                "root_hash": ROOT_HASH,
                "modules": sorted(_LOADED),
                "errors": _ERRORS,
            },
        )

    def _info(self) -> None:
        self._send(
            200,
            {
                "name": NAME,
                "version": VERSION,
                "root_hash": ROOT_HASH,
                "files": FILES,
                "modules": sorted(_LOADED),
            },
        )

    def _call(self, query: dict[str, list[str]]) -> None:
        module = query.get("module", [""])[0]
        function = query.get("function", [""])[0]
        if not module or not function:
            self._send(400, {"error": "the call needs a module and a function"})
            return
        target = _LOADED.get(module)
        if target is None:
            self._send(404, {"error": f"the module '{module}' is not part of the artifact"})
            return
        handler = getattr(target, function, None)
        if handler is None or function.startswith("_"):
            self._send(404, {"error": f"the function '{function}' is not part of the artifact"})
            return
        raw = query.get("args", ["[]"])[0]
        try:
            arguments = json.loads(raw)
        except json.JSONDecodeError:
            self._send(400, {"error": "the arguments are not a JSON list"})
            return
        if not isinstance(arguments, list):
            self._send(400, {"error": "the arguments are not a JSON list"})
            return
        try:
            result = handler(*arguments)
        except Exception:
            self._send(500, {"error": traceback.format_exc(limit=3)})
            return
        self._send(200, {"result": result})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/health":
            self._health()
            return
        if parsed.path == "/call":
            self._call(query)
            return
        self._info()


def main() -> int:
    """Serve the artifact until the container is stopped."""
    _load()
    server = ThreadingHTTPServer(("0.0.0.0", SERVICE_PORT), Handler)  # noqa: S104
    server.daemon_threads = True
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
