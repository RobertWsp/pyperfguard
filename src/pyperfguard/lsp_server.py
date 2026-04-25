"""Minimal stdio LSP server for pyperfguard — diagnostics only.

Implements the Language Server Protocol 3.17 subset required to publish
diagnostics on file open/change/save events.  Zero external dependencies.

Lifecycle handled:
    initialize             → respond with textDocumentSync:1 capabilities
    initialized            → no-op (notification)
    textDocument/didOpen   → analyze → textDocument/publishDiagnostics
    textDocument/didChange → analyze → textDocument/publishDiagnostics
    textDocument/didSave   → re-analyze from disk → publishDiagnostics
    textDocument/didClose  → clear diagnostics for that file
    shutdown               → respond null, set flag
    exit                   → sys.exit(0 if shutdown else 1)

All other requests receive a ``MethodNotFound`` error response so the
client does not hang waiting.  Notifications with no known handler are
silently ignored.

Usage::

    pyperfguard lsp          # invoked by the opencode LSP client

The server writes all log output to stderr so stdout remains clean for
LSP traffic.
"""

from __future__ import annotations

import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO
from urllib.parse import unquote, urlparse

if TYPE_CHECKING:
    from pyperfguard.core.config import Config
    from pyperfguard.core.registry import Registry

_log = logging.getLogger(__name__)

# LSP DiagnosticSeverity constants
_SEV_TO_LSP: dict[str, int] = {
    "error": 1,
    "warning": 2,
    "info": 3,
    "hint": 4,
}


def _uri_to_path(uri: str) -> Path:
    parsed = urlparse(uri)
    p = unquote(parsed.path)
    # Windows: /C:/foo → C:/foo
    if sys.platform == "win32" and p.startswith("/") and len(p) > 2 and p[2] == ":":
        p = p[1:]
    return Path(p)


def _read_message(stream: BinaryIO) -> dict[str, Any] | None:
    """Read one JSON-RPC message from the LSP stream.  Returns None on EOF."""
    headers: dict[str, str] = {}
    while True:
        raw = stream.readline()
        if not raw:
            return None
        line = raw.decode("utf-8").rstrip("\r\n")
        if not line:
            break
        key, _, value = line.partition(": ")
        headers[key] = value

    length = int(headers.get("Content-Length", "0"))
    if length == 0:
        return None

    body = b""
    while len(body) < length:
        chunk = stream.read(length - len(body))
        if not chunk:
            return None
        body += chunk

    return json.loads(body.decode("utf-8"))  # type: ignore[no-any-return]


def _write_message(stream: BinaryIO, msg: dict[str, Any]) -> None:
    body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    stream.write(header + body)
    if hasattr(stream, "flush"):
        stream.flush()


def _find_pyproject(start: Path) -> Path | None:
    for parent in (start, *start.parents):
        candidate = parent / "pyproject.toml"
        if candidate.exists():
            return candidate
    return None


class LspServer:
    """Single-threaded LSP server that emits pyperfguard diagnostics."""

    def __init__(self) -> None:
        self._registry: Registry | None = None
        self._config: Config | None = None
        self._shutdown = False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _ensure_init(self, workspace_root: Path | None = None) -> tuple[Registry, Config]:
        if self._registry is None:
            from pyperfguard.plugins import bootstrap

            self._registry = bootstrap()
        if self._config is None:
            from pyperfguard.core.config import Config

            pyproject = _find_pyproject(workspace_root) if workspace_root else None
            self._config = Config.load(path=pyproject)
        return self._registry, self._config

    def _analyze_content(
        self, uri: str, content: str, registry: Registry, config: Config
    ) -> list[dict[str, Any]]:
        """Write *content* to a temp file, run AstEngine, return LSP diagnostics."""
        from pyperfguard.ast_engine.runner import AstEngine

        real_path = _uri_to_path(uri)
        suffix = real_path.suffix or ".py"
        # Write next to the real file so relative package context is preserved.
        tmp_dir = real_path.parent if real_path.parent.is_dir() else Path(tempfile.gettempdir())

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=suffix,
                dir=tmp_dir,
                delete=False,
                encoding="utf-8",
            ) as fd_obj:
                fd_obj.write(content)
                tmp_path = Path(fd_obj.name)
        except OSError:
            # Fallback: system temp dir
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=suffix,
                delete=False,
                encoding="utf-8",
            ) as fd_obj:
                fd_obj.write(content)
                tmp_path = Path(fd_obj.name)

        try:
            engine = AstEngine(registry=registry, config=config)
            findings = engine.run([tmp_path])
        except Exception:
            _log.exception("analysis failed for %s", uri)
            return []
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass

        diagnostics: list[dict[str, Any]] = []
        for f in findings:
            start_line = max(0, f.location.start_line - 1)  # 1-indexed → 0-indexed
            start_char = f.location.start_col  # already 0-indexed
            end_line = max(0, (f.location.end_line or f.location.start_line) - 1)
            end_char = (
                f.location.end_col
                if f.location.end_col is not None
                else start_char + 1
            )
            diag: dict[str, Any] = {
                "range": {
                    "start": {"line": start_line, "character": start_char},
                    "end": {"line": end_line, "character": end_char},
                },
                "severity": _SEV_TO_LSP.get(f.severity.value, 2),
                "code": f.rule_id,
                "source": "pyperfguard",
                "message": f.compact_message(),
            }
            diagnostics.append(diag)

        return diagnostics

    def _publish(
        self,
        writer: BinaryIO,
        uri: str,
        diagnostics: list[dict[str, Any]],
    ) -> None:
        _write_message(
            writer,
            {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "diagnostics": diagnostics},
            },
        )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
    ) -> int:
        """Block until the client sends ``exit``.  Returns the exit code."""
        workspace_root: Path | None = None
        registry: Registry | None = None
        config: Config | None = None

        while True:
            try:
                msg = _read_message(reader)
            except Exception as exc:
                _log.debug("read error: %s", exc)
                break

            if msg is None:
                break

            method: str = msg.get("method", "")
            msg_id: Any = msg.get("id")
            params: dict[str, Any] = msg.get("params") or {}

            _log.debug("← %s id=%s", method, msg_id)

            # ---- Lifecycle -----------------------------------------------

            if method == "initialize":
                root_uri: str | None = params.get("rootUri") or params.get("rootPath")
                if root_uri and root_uri.startswith("file://"):
                    workspace_root = _uri_to_path(root_uri)

                registry, config = self._ensure_init(workspace_root)

                _write_message(
                    writer,
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "capabilities": {
                                # 1 = TextDocumentSyncKind.Full
                                "textDocumentSync": 1,
                            },
                            "serverInfo": {
                                "name": "pyperfguard",
                            },
                        },
                    },
                )

            elif method == "initialized":
                pass  # notification — no response

            elif method == "shutdown":
                self._shutdown = True
                _write_message(
                    writer,
                    {"jsonrpc": "2.0", "id": msg_id, "result": None},
                )

            elif method == "exit":
                return 0 if self._shutdown else 1

            # ---- Text document events ------------------------------------

            elif method == "textDocument/didOpen":
                td: dict[str, Any] = params.get("textDocument") or {}
                uri: str = td.get("uri", "")
                if uri.endswith((".py", ".pyi")) and registry is not None and config is not None:
                    diags = self._analyze_content(uri, td.get("text", ""), registry, config)
                    self._publish(writer, uri, diags)

            elif method == "textDocument/didChange":
                td = params.get("textDocument") or {}
                uri = td.get("uri", "")
                changes: list[dict[str, Any]] = params.get("contentChanges") or []
                if changes and uri.endswith((".py", ".pyi")) and registry is not None and config is not None:
                    # Full sync (textDocumentSync:1) — last entry is the full text
                    content: str = changes[-1].get("text", "")
                    diags = self._analyze_content(uri, content, registry, config)
                    self._publish(writer, uri, diags)

            elif method == "textDocument/didSave":
                # Re-analyze from disk; avoids round-trip temp file for saves
                td = params.get("textDocument") or {}
                uri = td.get("uri", "")
                if uri.endswith((".py", ".pyi")) and registry is not None and config is not None:
                    path_on_disk = _uri_to_path(uri)
                    try:
                        content = path_on_disk.read_text(encoding="utf-8")
                    except OSError:
                        continue
                    diags = self._analyze_content(uri, content, registry, config)
                    self._publish(writer, uri, diags)

            elif method == "textDocument/didClose":
                td = params.get("textDocument") or {}
                uri = td.get("uri", "")
                self._publish(writer, uri, [])  # clear diagnostics

            # ---- Unknown requests ----------------------------------------

            elif msg_id is not None:
                # Respond so the client does not hang
                _write_message(
                    writer,
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method not found: {method}",
                        },
                    },
                )

        return 0 if self._shutdown else 1


def main() -> None:
    logging.basicConfig(
        level=logging.WARNING,
        format="pyperfguard-lsp %(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    server = LspServer()
    code = server.run(sys.stdin.buffer, sys.stdout.buffer)
    sys.exit(code)


if __name__ == "__main__":  # pragma: no cover
    main()
