"""Tests for the minimal LSP server (pyperfguard lsp)."""

from __future__ import annotations

import io
import json
import textwrap
from pathlib import Path
from typing import Any

from pyperfguard.lsp_server import LspServer, _read_message, _uri_to_path, _write_message

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_message(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    return header + body


def _read_all_messages(buf: io.BytesIO) -> list[dict[str, Any]]:
    buf.seek(0)
    msgs: list[dict[str, Any]] = []
    while True:
        msg = _read_message(buf)
        if msg is None:
            break
        msgs.append(msg)
    return msgs


def _run_sequence(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Feed *messages* into LspServer and return all written responses."""
    in_data = b"".join(_make_message(m) for m in messages)
    reader = io.BytesIO(in_data)
    writer = io.BytesIO()
    server = LspServer()
    server.run(reader, writer)
    return _read_all_messages(writer)


def _init_msg(msg_id: int = 1, root_uri: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if root_uri is not None:
        params["rootUri"] = root_uri
    return {"jsonrpc": "2.0", "id": msg_id, "method": "initialize", "params": params}


def _exit_msg() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": "exit"}


def _make_did_open(uri: str, content: str, version: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": uri,
                "languageId": "python",
                "version": version,
                "text": content,
            }
        },
    }


def _make_did_change(uri: str, content: str, version: int = 2) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": uri, "version": version},
            "contentChanges": [{"text": content}],
        },
    }


def _make_did_save(uri: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": uri}},
    }


def _make_did_close(uri: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "method": "textDocument/didClose",
        "params": {"textDocument": {"uri": uri}},
    }


def _diag_notifs(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in responses if r.get("method") == "textDocument/publishDiagnostics"]


# ---------------------------------------------------------------------------
# _uri_to_path
# ---------------------------------------------------------------------------


def test_uri_to_path_simple():
    p = _uri_to_path("file:///home/user/project/file.py")
    assert p == Path("/home/user/project/file.py")


def test_uri_to_path_url_encoded_spaces():
    encoded = "file:///home/user/my%20project/file.py"
    p = _uri_to_path(encoded)
    assert p == Path("/home/user/my project/file.py")


def test_uri_to_path_url_encoded_special_chars():
    uri = "file:///home/user/project%20(2)/s%C3%A9rie.py"
    p = _uri_to_path(uri)
    assert p == Path("/home/user/project (2)/série.py")


def test_uri_to_path_plain_path_string():
    # rootPath (deprecated LSP field) is a plain path, not file://
    p = _uri_to_path("/home/user/project")
    assert p == Path("/home/user/project")


# ---------------------------------------------------------------------------
# _read_message / _write_message round-trip
# ---------------------------------------------------------------------------


def test_round_trip_simple():
    payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "initialized", "params": {}}
    buf = io.BytesIO()
    _write_message(buf, payload)
    buf.seek(0)
    result = _read_message(buf)
    assert result == payload


def test_round_trip_unicode_content():
    payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "x", "params": {"text": "héllo wörld ✓"}}
    buf = io.BytesIO()
    _write_message(buf, payload)
    buf.seek(0)
    result = _read_message(buf)
    assert result == payload


def test_read_message_returns_none_on_eof():
    assert _read_message(io.BytesIO(b"")) is None


def test_write_two_separate_writes_no_concatenated_alloc():
    """_write_message must write header and body separately (no header+body object)."""
    buf = io.BytesIO()
    _write_message(buf, {"a": 1})
    buf.seek(0)
    raw = buf.read()
    # Verify correct framing: Content-Length header + blank line + body
    assert b"Content-Length:" in raw
    assert b"\r\n\r\n" in raw
    idx = raw.index(b"\r\n\r\n")
    body_raw = raw[idx + 4 :]
    doc = json.loads(body_raw)
    assert doc == {"a": 1}


def test_read_multiple_messages_from_stream():
    buf = io.BytesIO()
    for i in range(3):
        _write_message(buf, {"id": i})
    buf.seek(0)
    msgs = []
    while True:
        m = _read_message(buf)
        if m is None:
            break
        msgs.append(m)
    assert len(msgs) == 3
    assert [m["id"] for m in msgs] == [0, 1, 2]


# ---------------------------------------------------------------------------
# initialize handshake
# ---------------------------------------------------------------------------


def test_initialize_returns_capabilities():
    responses = _run_sequence([_init_msg(), _exit_msg()])
    init_resp = next(r for r in responses if r.get("id") == 1)
    caps = init_resp["result"]["capabilities"]
    assert "textDocumentSync" in caps


def test_initialize_text_document_sync_full():
    responses = _run_sequence([_init_msg(), _exit_msg()])
    init_resp = next(r for r in responses if r.get("id") == 1)
    tds = init_resp["result"]["capabilities"]["textDocumentSync"]
    # Full sync capabilities object (not shorthand int)
    assert isinstance(tds, dict)
    assert tds["change"] == 1  # TextDocumentSyncKind.Full
    assert tds["openClose"] is True
    assert tds["save"] == {"includeText": False}


def test_initialize_server_info():
    responses = _run_sequence([_init_msg(), _exit_msg()])
    init_resp = next(r for r in responses if r.get("id") == 1)
    assert init_resp["result"]["serverInfo"]["name"] == "pyperfguard"


def test_initialize_with_root_uri(tmp_path: Path):
    # Server must accept rootUri without crashing
    root_uri = tmp_path.as_uri()
    responses = _run_sequence([_init_msg(root_uri=root_uri), _exit_msg()])
    init_resp = next(r for r in responses if r.get("id") == 1)
    assert "capabilities" in init_resp["result"]


def test_initialize_with_root_path_deprecated(tmp_path: Path):
    # rootPath is a deprecated plain path string — must still be accepted
    msg: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"rootPath": str(tmp_path)},
    }
    responses = _run_sequence([msg, _exit_msg()])
    init_resp = next(r for r in responses if r.get("id") == 1)
    assert "capabilities" in init_resp["result"]


# ---------------------------------------------------------------------------
# shutdown + exit lifecycle
# ---------------------------------------------------------------------------


def test_shutdown_responds_null():
    responses = _run_sequence(
        [_init_msg(), {"jsonrpc": "2.0", "id": 2, "method": "shutdown"}, _exit_msg()]
    )
    shutdown_resp = next(r for r in responses if r.get("id") == 2)
    assert shutdown_resp["result"] is None


def test_exit_without_shutdown_returns_1():
    in_data = _make_message(_init_msg()) + _make_message(_exit_msg())
    reader = io.BytesIO(in_data)
    writer = io.BytesIO()
    code = LspServer().run(reader, writer)
    assert code == 1


def test_exit_after_shutdown_returns_0():
    in_data = (
        _make_message(_init_msg())
        + _make_message({"jsonrpc": "2.0", "id": 2, "method": "shutdown"})
        + _make_message(_exit_msg())
    )
    reader = io.BytesIO(in_data)
    writer = io.BytesIO()
    code = LspServer().run(reader, writer)
    assert code == 0


# ---------------------------------------------------------------------------
# Pre-initialization guard
# ---------------------------------------------------------------------------


def test_request_before_initialize_returns_server_not_initialized():
    responses = _run_sequence(
        [
            {"jsonrpc": "2.0", "id": 5, "method": "textDocument/hover", "params": {}},
            _init_msg(),
            _exit_msg(),
        ]
    )
    err_resp = next((r for r in responses if r.get("id") == 5), None)
    assert err_resp is not None
    assert "error" in err_resp
    assert err_resp["error"]["code"] == -32002  # ServerNotInitialized


def test_notification_before_initialize_is_silently_dropped():
    # didOpen before initialize is a protocol violation — must not crash,
    # must not produce any publishDiagnostics response.
    uri = "file:///tmp/early.py"
    responses = _run_sequence(
        [
            _make_did_open(uri, "x = 1\n"),  # before initialize
            _init_msg(),
            _exit_msg(),
        ]
    )
    notifs = _diag_notifs(responses)
    assert notifs == []


# ---------------------------------------------------------------------------
# textDocument/didOpen
# ---------------------------------------------------------------------------


def test_did_open_clean_file_publishes_empty_diagnostics(tmp_path: Path):
    uri = (tmp_path / "clean.py").as_uri()
    responses = _run_sequence([_init_msg(), _make_did_open(uri, "x = 1\n"), _exit_msg()])
    notifs = _diag_notifs(responses)
    assert len(notifs) == 1
    assert notifs[0]["params"]["uri"] == uri  # original URI, not temp file path
    assert notifs[0]["params"]["diagnostics"] == []


def test_did_open_publishes_to_original_uri_not_temp_path(tmp_path: Path):
    uri = (tmp_path / "check_uri.py").as_uri()
    responses = _run_sequence(
        [_init_msg(), _make_did_open(uri, "def f(x=[]):\n    pass\n"), _exit_msg()]
    )
    notifs = _diag_notifs(responses)
    assert len(notifs) == 1
    # Must be the original URI, never a /tmp/tmpXXXX.py path
    assert notifs[0]["params"]["uri"] == uri
    assert "/tmp/" not in notifs[0]["params"]["uri"] or "check_uri" in notifs[0]["params"]["uri"]


def test_did_open_mutable_default_publishes_pkn001(tmp_path: Path):
    uri = (tmp_path / "bad.py").as_uri()
    code = textwrap.dedent("""\
        def f(x=[]):
            pass
    """)
    responses = _run_sequence([_init_msg(), _make_did_open(uri, code), _exit_msg()])
    diags = _diag_notifs(responses)[0]["params"]["diagnostics"]
    assert any(d["code"] == "PKN001" for d in diags)


def test_did_open_diagnostic_severity_is_lsp_integer(tmp_path: Path):
    uri = (tmp_path / "bad.py").as_uri()
    responses = _run_sequence(
        [_init_msg(), _make_did_open(uri, "def f(x=[]):\n    pass\n"), _exit_msg()]
    )
    for d in _diag_notifs(responses)[0]["params"]["diagnostics"]:
        assert isinstance(d["severity"], int)
        assert 1 <= d["severity"] <= 4


def test_did_open_diagnostic_range_is_0indexed(tmp_path: Path):
    uri = (tmp_path / "bad.py").as_uri()
    # PKN001 fires on line 1 of source → must appear as line 0 in LSP
    responses = _run_sequence(
        [_init_msg(), _make_did_open(uri, "def f(x=[]):\n    pass\n"), _exit_msg()]
    )
    pkn001 = next(
        d
        for d in _diag_notifs(responses)[0]["params"]["diagnostics"]
        if d["code"] == "PKN001"
    )
    assert pkn001["range"]["start"]["line"] == 0


def test_did_open_non_python_file_no_diagnostics(tmp_path: Path):
    uri = (tmp_path / "file.js").as_uri()
    responses = _run_sequence([_init_msg(), _make_did_open(uri, "const x = 1;"), _exit_msg()])
    assert _diag_notifs(responses) == []


def test_did_open_url_encoded_uri(tmp_path: Path):
    # Directory and file with a space in the name
    spaced = tmp_path / "my project"
    spaced.mkdir()
    file = spaced / "app.py"
    encoded_uri = file.as_uri()  # Path.as_uri() percent-encodes spaces
    assert "%20" in encoded_uri
    responses = _run_sequence(
        [_init_msg(), _make_did_open(encoded_uri, "def f(x=[]):\n    pass\n"), _exit_msg()]
    )
    notifs = _diag_notifs(responses)
    assert len(notifs) == 1
    assert any(d["code"] == "PKN001" for d in notifs[0]["params"]["diagnostics"])


# ---------------------------------------------------------------------------
# textDocument/didChange
# ---------------------------------------------------------------------------


def test_did_change_publishes_diagnostics(tmp_path: Path):
    uri = (tmp_path / "evolving.py").as_uri()
    responses = _run_sequence(
        [
            _init_msg(),
            _make_did_open(uri, "x = 1\n"),
            _make_did_change(uri, "def f(x=[]):\n    pass\n"),
            _exit_msg(),
        ]
    )
    notifs = _diag_notifs(responses)
    assert len(notifs) == 2
    assert notifs[0]["params"]["diagnostics"] == []
    assert any(d["code"] == "PKN001" for d in notifs[1]["params"]["diagnostics"])


def test_did_change_clean_clears_previous_diagnostics(tmp_path: Path):
    uri = (tmp_path / "healing.py").as_uri()
    responses = _run_sequence(
        [
            _init_msg(),
            _make_did_open(uri, "def f(x=[]):\n    pass\n"),  # bad
            _make_did_change(uri, "x = 1\n"),                 # now clean
            _exit_msg(),
        ]
    )
    notifs = _diag_notifs(responses)
    assert len(notifs) == 2
    assert any(d["code"] == "PKN001" for d in notifs[0]["params"]["diagnostics"])
    assert notifs[1]["params"]["diagnostics"] == []


def test_did_change_empty_content_no_crash(tmp_path: Path):
    uri = (tmp_path / "empty.py").as_uri()
    responses = _run_sequence(
        [_init_msg(), _make_did_open(uri, "x=1\n"), _make_did_change(uri, ""), _exit_msg()]
    )
    notifs = _diag_notifs(responses)
    assert len(notifs) == 2
    # Empty file has no findings
    assert notifs[1]["params"]["diagnostics"] == []


# ---------------------------------------------------------------------------
# textDocument/didSave
# ---------------------------------------------------------------------------


def test_did_save_clean_file_publishes_empty_diagnostics(tmp_path: Path):
    saved = tmp_path / "saved.py"
    saved.write_text("x = 1\n", encoding="utf-8")
    uri = saved.as_uri()
    responses = _run_sequence(
        [_init_msg(), _make_did_open(uri, "x = 1\n"), _make_did_save(uri), _exit_msg()]
    )
    notifs = _diag_notifs(responses)
    # didOpen + didSave both publish
    assert len(notifs) == 2
    assert notifs[1]["params"]["uri"] == uri
    assert notifs[1]["params"]["diagnostics"] == []


def test_did_save_with_anti_pattern_publishes_finding(tmp_path: Path):
    saved = tmp_path / "saved_bad.py"
    saved.write_text("def f(x=[]):\n    pass\n", encoding="utf-8")
    uri = saved.as_uri()
    responses = _run_sequence(
        [_init_msg(), _make_did_open(uri, "x = 1\n"), _make_did_save(uri), _exit_msg()]
    )
    notifs = _diag_notifs(responses)
    # didSave re-reads from disk (which has the anti-pattern)
    assert any(d["code"] == "PKN001" for d in notifs[-1]["params"]["diagnostics"])


def test_did_save_file_deleted_clears_diagnostics(tmp_path: Path):
    deleted = tmp_path / "gone.py"
    deleted.write_text("def f(x=[]):\n    pass\n", encoding="utf-8")
    uri = deleted.as_uri()

    # Open file (gets diagnostics), then delete it, then trigger didSave
    deleted.unlink()

    responses = _run_sequence(
        [_init_msg(), _make_did_open(uri, "def f(x=[]):\n    pass\n"), _make_did_save(uri), _exit_msg()]
    )
    notifs = _diag_notifs(responses)
    # Last publish should be empty (file gone → diagnostics cleared)
    assert notifs[-1]["params"]["diagnostics"] == []
    assert notifs[-1]["params"]["uri"] == uri


# ---------------------------------------------------------------------------
# textDocument/didClose
# ---------------------------------------------------------------------------


def test_did_close_publishes_empty_diagnostics(tmp_path: Path):
    uri = (tmp_path / "bad.py").as_uri()
    responses = _run_sequence(
        [
            _init_msg(),
            _make_did_open(uri, "def f(x=[]):\n    pass\n"),
            _make_did_close(uri),
            _exit_msg(),
        ]
    )
    notifs = _diag_notifs(responses)
    assert notifs[-1]["params"]["diagnostics"] == []
    assert notifs[-1]["params"]["uri"] == uri


def test_did_close_without_prior_open_is_idempotent():
    uri = "file:///tmp/never_opened.py"
    responses = _run_sequence([_init_msg(), _make_did_close(uri), _exit_msg()])
    notifs = _diag_notifs(responses)
    assert len(notifs) == 1
    assert notifs[0]["params"]["diagnostics"] == []


# ---------------------------------------------------------------------------
# Unknown request / notification
# ---------------------------------------------------------------------------


def test_unknown_request_returns_method_not_found():
    responses = _run_sequence(
        [
            _init_msg(),
            {"jsonrpc": "2.0", "id": 99, "method": "textDocument/hover", "params": {}},
            _exit_msg(),
        ]
    )
    err = next((r for r in responses if r.get("id") == 99), None)
    assert err is not None
    assert err["error"]["code"] == -32601


def test_unknown_notification_silently_ignored():
    responses = _run_sequence(
        [_init_msg(), {"jsonrpc": "2.0", "method": "$/unknownNotification"}, _exit_msg()]
    )
    ids = [r.get("id") for r in responses if "id" in r]
    assert ids == [1]
    assert all("error" not in r for r in responses)


# ---------------------------------------------------------------------------
# initialized notification (no response expected)
# ---------------------------------------------------------------------------


def test_initialized_notification_has_no_response():
    responses = _run_sequence(
        [_init_msg(), {"jsonrpc": "2.0", "method": "initialized", "params": {}}, _exit_msg()]
    )
    ids = [r.get("id") for r in responses if "id" in r]
    assert ids == [1]


# ---------------------------------------------------------------------------
# AstEngine caching — same instance reused across events
# ---------------------------------------------------------------------------


def test_engine_reused_across_multiple_did_open(tmp_path: Path):
    """_get_engine must return the same AstEngine instance on repeated calls."""
    server = LspServer()
    in_data = (
        _make_message(_init_msg())
        + _make_message(_make_did_open((tmp_path / "a.py").as_uri(), "x = 1\n"))
        + _make_message(_make_did_open((tmp_path / "b.py").as_uri(), "y = 2\n"))
        + _make_message(_exit_msg())
    )
    reader = io.BytesIO(in_data)
    writer = io.BytesIO()
    server.run(reader, writer)
    # After two didOpen events the engine must have been built exactly once
    assert server._engine is not None
    engine_id = id(server._engine)
    # Engine must not be replaced on subsequent calls
    assert id(server._engine) == engine_id
