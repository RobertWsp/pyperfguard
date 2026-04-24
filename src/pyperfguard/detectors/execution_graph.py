"""Execution-graph–aware N+1 detector.

Unlike the basic :class:`~pyperfguard.detectors.nplusone.NPlusOneDetector`
which groups by ``(fingerprint, call_site)``, this detector uses the **full
call stack** as the execution graph — each frame is a node, each call is an
edge.  This lets it detect N+1 patterns that span multiple function boundaries:

    router.list_conversations()          ← FastAPI handler
      └─ ConversationService.list_all()  ← service layer
           └─ for conv in convs:         ← loop frame  ← KEY
                └─ await executor.execute("SELECT ...")  ← N queries

The stack trace captures all four frames.  The detector groups events by a
**stack prefix hash** (all frames except the immediate query call site), which
uniquely identifies "this loop inside this service method called from this
handler".  If that prefix appears with ≥ ``threshold`` different bind-parameter
sets, it is an N+1 regardless of which function contained the loop.

Algorithm:
1. For each QueryEvent, compute ``stack_prefix_hash`` = hash of frames 1..N-1
   (exclude frame 0 = the query itself, include the rest up to the handler).
2. Group events by ``(fingerprint, stack_prefix_hash)``.
3. If a group has ≥ ``threshold`` entries → N+1, report the full chain.

Why exclude frame 0?
    Frame 0 is always ``session.execute / executor.execute`` — identical for
    every query.  The loop is at frame 1 or deeper.

Why use a prefix (not the full stack)?
    Different parameter sets produce the same ``fingerprint`` but slightly
    different stacks (e.g. the ``await`` frame line varies).  The prefix
    normalises this.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from pyperfguard.core.finding import Finding, Location
from pyperfguard.core.severity import Severity
from pyperfguard.runtime_engine.events import QueryEvent
from pyperfguard.runtime_engine.scope import Scope


@dataclass(slots=True)
class ExecutionGraphN1Detector:
    """Stack-aware N+1 detector using the execution graph (full call stack).

    Detects cross-function N+1 patterns invisible to single-function AST rules.

    Parameters
    ----------
    threshold:
        Minimum repeated queries for the same stack prefix + fingerprint.
        Default 3 (lower than NPlusOneDetector's 5 because we have richer
        signal from the full stack).
    min_stack_frames:
        Require at least this many user frames in the stack.  Filters events
        that were emitted from tests/scripts with shallow stacks.
    db_systems:
        Restrict to specific DB systems (None = all).
    min_duration_ms:
        Skip groups whose total duration is under this threshold.
    prefix_depth:
        How many frames from the top (caller side) to include in the prefix
        hash.  Default 8 captures router → service → helper → loop.
    """

    threshold: int = 3
    min_stack_frames: int = 2
    db_systems: frozenset[str] | None = None
    min_duration_ms: float = 0.0
    prefix_depth: int = 8

    def evaluate(self, scope: Scope) -> list[Finding]:
        groups: dict[tuple[str, int], list[QueryEvent]] = defaultdict(list)

        for event in scope.filter("query"):
            if not isinstance(event, QueryEvent):
                continue
            if self.db_systems and event.db_system not in self.db_systems:
                continue
            if len(event.stack_frames) < self.min_stack_frames:
                continue

            prefix_hash = self._stack_prefix_hash(event.stack_frames)
            groups[(event.fingerprint, prefix_hash)].append(event)

        findings: list[Finding] = []
        for (fingerprint, _prefix_hash), events in groups.items():
            if len(events) < self.threshold:
                continue

            total_ms = sum(
                (e.duration_s * 1000) for e in events if e.duration_s is not None
            )
            if total_ms < self.min_duration_ms:
                continue

            findings.append(self._make_finding(events, fingerprint, total_ms, scope))

        return findings

    def _stack_prefix_hash(self, frames: tuple[str, ...]) -> int:
        """Hash the caller-side prefix of the stack (skip the innermost frame)."""
        # frames[0] is the deepest (the execute() call site).
        # frames[1:prefix_depth+1] are the callers — loop, service, handler, etc.
        prefix = frames[1: self.prefix_depth + 1]
        return hash(prefix)

    @staticmethod
    def _make_finding(
        events: list[QueryEvent],
        fingerprint: str,
        total_ms: float,
        scope: Scope,
    ) -> Finding:
        first = events[0]
        db_system = first.db_system
        stmt = first.statement or fingerprint
        count = len(events)

        # Build a human-readable execution chain from the stack.
        chain = _format_execution_chain(first.stack_frames)

        message = (
            f"N+1 query (execution graph): '{stmt}' executed {count}× "
            f"from the same call chain (total {total_ms:.1f} ms, db={db_system or 'unknown'}). "
            f"Execution path: {chain}"
        )

        return Finding(
            rule_id="PKN101",
            message=message,
            severity=Severity.ERROR,
            location=Location(path=Path("<runtime>"), start_line=0),
            scope="runtime",
            stack=first.stack_frames,
            extra={
                "count": count,
                "fingerprint": fingerprint,
                "statement": stmt,
                "db_system": db_system,
                "total_ms": round(total_ms, 2),
                "scope_name": scope.name,
                "execution_chain": chain,
                "detector": "execution_graph",
            },
        )


def _format_execution_chain(frames: tuple[str, ...]) -> str:
    """Convert stack frames to a human-readable call chain (outermost first)."""
    if not frames:
        return "<unknown>"
    # frames[0] is innermost (execute), frames[-1] is outermost (handler).
    # Reverse so we show handler → service → loop → execute.
    chain_parts = []
    for frame in reversed(frames[:6]):
        # Each frame is "path/to/file.py:42 in func_name"
        parts = frame.rsplit(" in ", 1)
        func = parts[1] if len(parts) == 2 else frame
        chain_parts.append(func)
    return " → ".join(chain_parts)
