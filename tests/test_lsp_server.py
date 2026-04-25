"""Tests for the minimal LSP server (pyperfguard lsp)."""

from __future__ import annotations

import io
import json
import textwrap
from pathlib import Path

import pytest

from pyperfguard.lsp_server import LspServer, _read_message, _write_message


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_message(payload: dict) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    return header + body


def _read_all_messages(buf: io.BytesIO) -> list[dict]:
    buf.seek(0)
    msgs = []
    while True:
        msg = _read_message(buf)
        if msg is None:
            break
        msgs.append(msg)
    return msgs


def _run_sequence(messages: list[dict]) -> list[dict]:
    """Feed *messages* into LspServer and return all written responses."""
    in_data = b"".join(_make_message(m) for m in messages)
    reader = io.BytesIO(in_data)
    writer = io.BytesIO()
    server = LspServer()
    server.run(reader, writer)
    return _read_all_messages(writer)


# ---------------------------------------------------------------------------
# _read_message / _write_message round-trip
# ---------------------------------------------------------------------------


def test_round_trip_simple():
    payload = {"jsonrpc": "2.0", "method": "initialized", "params": {}}
    buf = io.BytesIO()
    _write_message(buf, payload)
    buf.seek(0)
    result = _read_message(buf)
    assert result == payload


def test_read_message_returns_none_on_eof():
    assert _read_message(io.BytesIO(b"")) is None


def test_write_includes_content_length_header():
    buf = io.BytesIO()
    _write_message(buf, {"a": 1})
    buf.seek(0)
    raw = buf.read().decode("utf-8")
    assert "Content-Length:" in raw
    # Header must end with blank line before body
    assert "\r\n\r\n" in raw


# ---------------------------------------------------------------------------
# initialize handshake
# ---------------------------------------------------------------------------


def test_initialize_returns_capabilities():
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    init_resp = next(r for r in responses if r.get("id") == 1)
    assert "capabilities" in init_resp["result"]
    assert init_resp["result"]["capabilities"]["textDocumentSync"] == 1


def test_initialize_serverinfo():
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    init_resp = next(r for r in responses if r.get("id") == 1)
    assert init_resp["result"]["serverInfo"]["name"] == "pyperfguard"


# ---------------------------------------------------------------------------
# shutdown + exit lifecycle
# ---------------------------------------------------------------------------


def test_shutdown_responds_null():
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "shutdown"},
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    shutdown_resp = next(r for r in responses if r.get("id") == 2)
    assert shutdown_resp["result"] is None


def test_exit_without_shutdown_returns_1():
    in_data = _make_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    in_data += _make_message({"jsonrpc": "2.0", "method": "exit"})
    reader = io.BytesIO(in_data)
    writer = io.BytesIO()
    server = LspServer()
    code = server.run(reader, writer)
    assert code == 1


def test_exit_after_shutdown_returns_0():
    in_data = (
        _make_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        + _make_message({"jsonrpc": "2.0", "id": 2, "method": "shutdown"})
        + _make_message({"jsonrpc": "2.0", "method": "exit"})
    )
    reader = io.BytesIO(in_data)
    writer = io.BytesIO()
    server = LspServer()
    code = server.run(reader, writer)
    assert code == 0


# ---------------------------------------------------------------------------
# textDocument/didOpen — diagnostic publishing
# ---------------------------------------------------------------------------


def _make_did_open(uri: str, content: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": content}
        },
    }


def _make_did_change(uri: str, content: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": uri, "version": 2},
            "contentChanges": [{"text": content}],
        },
    }


def test_did_open_clean_file_publishes_empty_diagnostics(tmp_path: Path):
    clean = tmp_path / "clean.py"
    uri = clean.as_uri()
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            _make_did_open(uri, "x = 1\n"),
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    diag_notifs = [r for r in responses if r.get("method") == "textDocument/publishDiagnostics"]
    assert len(diag_notifs) == 1
    assert diag_notifs[0]["params"]["uri"] == uri
    assert diag_notifs[0]["params"]["diagnostics"] == []


def test_did_open_mutable_default_publishes_pkn001(tmp_path: Path):
    uri = (tmp_path / "bad.py").as_uri()
    code = textwrap.dedent("""\
        def f(x=[]):
            pass
    """)
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            _make_did_open(uri, code),
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    diag_notifs = [r for r in responses if r.get("method") == "textDocument/publishDiagnostics"]
    diags = diag_notifs[0]["params"]["diagnostics"]
    assert any(d["code"] == "PKN001" for d in diags)


def test_did_open_diagnostic_severity_is_lsp_integer(tmp_path: Path):
    uri = (tmp_path / "bad.py").as_uri()
    code = "def f(x=[]):\n    pass\n"
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            _make_did_open(uri, code),
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    diag_notifs = [r for r in responses if r.get("method") == "textDocument/publishDiagnostics"]
    for d in diag_notifs[0]["params"]["diagnostics"]:
        assert isinstance(d["severity"], int)
        assert 1 <= d["severity"] <= 4


def test_did_open_diagnostic_range_is_0indexed(tmp_path: Path):
    uri = (tmp_path / "bad.py").as_uri()
    # PKN001 on line 1 → LSP line 0
    code = "def f(x=[]):\n    pass\n"
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            _make_did_open(uri, code),
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    diag_notifs = [r for r in responses if r.get("method") == "textDocument/publishDiagnostics"]
    pkn001 = next(d for d in diag_notifs[0]["params"]["diagnostics"] if d["code"] == "PKN001")
    assert pkn001["range"]["start"]["line"] == 0  # 1-indexed → 0-indexed


def test_did_open_non_python_file_no_diagnostics():
    uri = "file:///some/file.js"
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            _make_did_open(uri, "const x = 1;"),
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    diag_notifs = [r for r in responses if r.get("method") == "textDocument/publishDiagnostics"]
    assert diag_notifs == []


# ---------------------------------------------------------------------------
# textDocument/didChange
# ---------------------------------------------------------------------------


def test_did_change_updates_diagnostics(tmp_path: Path):
    uri = (tmp_path / "evolving.py").as_uri()
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            _make_did_open(uri, "x = 1\n"),  # clean
            _make_did_change(uri, "def f(x=[]):\n    pass\n"),  # introduces PKN001
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    diag_notifs = [r for r in responses if r.get("method") == "textDocument/publishDiagnostics"]
    assert len(diag_notifs) == 2
    # First publish: clean
    assert diag_notifs[0]["params"]["diagnostics"] == []
    # Second publish: PKN001 present
    codes = {d["code"] for d in diag_notifs[1]["params"]["diagnostics"]}
    assert "PKN001" in codes


# ---------------------------------------------------------------------------
# textDocument/didClose — clear diagnostics
# ---------------------------------------------------------------------------


def test_did_close_publishes_empty_diagnostics(tmp_path: Path):
    uri = (tmp_path / "bad.py").as_uri()
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            _make_did_open(uri, "def f(x=[]):\n    pass\n"),
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didClose",
                "params": {"textDocument": {"uri": uri}},
            },
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    diag_notifs = [r for r in responses if r.get("method") == "textDocument/publishDiagnostics"]
    # Last publish must be empty (close clears diagnostics)
    assert diag_notifs[-1]["params"]["diagnostics"] == []
    assert diag_notifs[-1]["params"]["uri"] == uri


# ---------------------------------------------------------------------------
# Unknown request → MethodNotFound error
# ---------------------------------------------------------------------------


def test_unknown_request_returns_method_not_found():
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 99, "method": "textDocument/hover", "params": {}},
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    error_resp = next((r for r in responses if r.get("id") == 99), None)
    assert error_resp is not None
    assert "error" in error_resp
    assert error_resp["error"]["code"] == -32601


def test_unknown_notification_is_silently_ignored():
    # Should not raise or produce an error response
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "$/unknownNotification"},
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    # Only initialize response present; no error
    ids = [r.get("id") for r in responses]
    assert 1 in ids
    assert all("error" not in r for r in responses)


# ---------------------------------------------------------------------------
# initialized notification (no response expected)
# ---------------------------------------------------------------------------


def test_initialized_notification_has_no_response():
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "initialized", "params": {}},
            {"jsonrpc": "2.0", "method": "exit"},
        ]
    )
    # Only the initialize response (id=1); no extra messages for initialized
    ids = [r.get("id") for r in responses if "id" in r]
    assert ids == [1]
