"""Cassandra driver patcher.

Uses the official ``Session.add_request_init_listener`` API (stable, public)
to hook into every query without monkey-patching execute() directly.

The listener runs on the thread that calls ``session.execute()`` (or
``execute_async()``), so ``sys._getframe`` captures the correct call stack.
Results are delivered asynchronously via ``ResponseFuture`` callbacks — we
capture timing there.

Anti-patterns detected at runtime (complementing AST-level PKN010-PKN013):
- N+1 (via NPlusOneDetector on the Scope)
- Queries with ALLOW FILTERING (emit extra flag in the event)
"""

from __future__ import annotations

import re
import time
from types import ModuleType

_ALLOW_FILTERING_RE = re.compile(r"\bALLOW\s+FILTERING\b", re.IGNORECASE)


class CassandraPatcher:
    """Patches ``cassandra.cluster.Session.__init__`` to auto-add our listener."""

    module_name = "cassandra.cluster"

    def __init__(self) -> None:
        self._original_init: object | None = None

    def install(self, module: ModuleType) -> None:
        if self._original_init is not None:
            return  # already installed
        original = module.Session.__init__
        self._original_init = original
        patcher = self

        def patched_init(sess, *args, **kwargs):  # type: ignore[no-untyped-def]
            original(sess, *args, **kwargs)
            sess.add_request_init_listener(patcher._on_request)

        module.Session.__init__ = patched_init

    def uninstall(self, module: ModuleType) -> None:
        if self._original_init is None:
            return
        module.Session.__init__ = self._original_init
        self._original_init = None

    # ----- Request listener ------------------------------------------------

    def _on_request(self, response_future: object) -> None:
        query_str = _extract_cql(response_future)  # type: ignore[arg-type]
        if not query_str:
            return

        from pyperfguard.core.frame_utils import format_frames, walk_user_frames
        from pyperfguard.fingerprint.cql import fingerprint_hash, normalize
        from pyperfguard.runtime_engine.event_bus import get_event_bus
        from pyperfguard.runtime_engine.events import QueryEvent

        frames = walk_user_frames(skip=3, limit=6)
        cs_fp = hash(tuple(f.fingerprint() for f in frames)) if frames else None
        stmt_norm = normalize(query_str)
        fp = fingerprint_hash(query_str)
        start = time.perf_counter()
        has_af = bool(_ALLOW_FILTERING_RE.search(query_str))

        def _on_success(result: object) -> None:
            duration = time.perf_counter() - start
            rows = None
            try:
                rows = result.current_rows.__len__()  # type: ignore[union-attr]
            except Exception:
                pass
            get_event_bus().emit(
                QueryEvent(
                    fingerprint=fp,
                    db_system="cassandra",
                    statement=stmt_norm,
                    duration_s=duration,
                    rows=rows,
                    call_site=cs_fp,
                    stack_frames=format_frames(frames),
                    extra=(("allow_filtering", has_af),),
                )
            )

        def _on_error(exc: Exception) -> None:
            get_event_bus().emit(
                QueryEvent(
                    fingerprint=fp,
                    db_system="cassandra",
                    statement=stmt_norm,
                    error=str(exc),
                    call_site=cs_fp,
                    stack_frames=format_frames(frames),
                    extra=(("allow_filtering", has_af),),
                )
            )

        try:
            response_future.add_callbacks(_on_success, _on_error)  # type: ignore[union-attr]
        except Exception:
            pass


# ---------------------------------------------------------------------------


def _extract_cql(rf: object) -> str | None:
    q = getattr(rf, "query", None)
    if q is None:
        return None
    # SimpleStatement
    qs = getattr(q, "query_string", None)
    if qs:
        return str(qs)
    # BoundStatement (prepared)
    ps = getattr(q, "prepared_statement", None)
    if ps is not None:
        qs2 = getattr(ps, "query_string", None)
        if qs2:
            return str(qs2)
    return None
