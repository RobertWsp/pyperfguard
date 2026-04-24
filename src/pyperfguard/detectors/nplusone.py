"""N+1 detector — Prosopite-style: group by (fingerprint, call_site) per scope.

The algorithm:
1. Collect all ``QueryEvent``s from the scope.
2. Group by ``(fingerprint, call_site)`` — "same query, same call site".
3. If a group has ≥ ``threshold`` entries the caller is executing the same
   query in a loop without batching → emit an ERROR Finding.

This deliberately avoids false positives: two identical queries originating
from *different* call sites are not N+1 (they may be legitimate reuse).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from pyperfguard.core.finding import Finding, Location
from pyperfguard.core.severity import Severity
from pyperfguard.runtime_engine.events import QueryEvent
from pyperfguard.runtime_engine.scope import Scope


@dataclass(slots=True)
class NPlusOneDetector:
    """Detects N+1 query patterns by analysing a completed :class:`Scope`.

    Parameters
    ----------
    threshold:
        Minimum number of identical (fingerprint, call_site) pairs before
        raising a finding. Default 5 — tune per project.
    db_systems:
        Restrict detection to specific DB systems. ``None`` means all.
    min_duration_ms:
        Only report if the total duration of the repeated queries exceeds
        this value (milliseconds). Avoids noise from trivially fast caches.
    """

    threshold: int = 5
    db_systems: frozenset[str] | None = None
    min_duration_ms: float = 0.0

    def evaluate(self, scope: Scope) -> Iterable[Finding]:
        """Analyse ``scope`` and yield zero or more Findings."""
        groups: dict[tuple[str, int | None], list[QueryEvent]] = defaultdict(list)

        for event in scope.filter("query"):
            if not isinstance(event, QueryEvent):
                continue
            if self.db_systems and event.db_system not in self.db_systems:
                continue
            groups[(event.fingerprint, event.call_site)].append(event)

        for (fingerprint, _call_site), events in groups.items():
            if len(events) < self.threshold:
                continue

            total_ms = sum(
                (e.duration_s * 1000) for e in events if e.duration_s is not None
            )
            if total_ms < self.min_duration_ms:
                continue

            db_system = events[0].db_system
            statement = events[0].statement or fingerprint

            # Pick stack frames from the first event that has them.
            stack: tuple[str, ...] = ()
            for e in events:
                if e.stack_frames:
                    stack = e.stack_frames
                    break

            yield Finding(
                rule_id="PKN100",
                message=(
                    f"N+1 query: '{statement}' executed {len(events)}× "
                    f"from the same call site "
                    f"(total {total_ms:.1f} ms, db={db_system or 'unknown'})."
                ),
                severity=Severity.ERROR,
                location=Location(path=Path("<runtime>"), start_line=0),
                scope="runtime",
                stack=stack,
                extra={
                    "count": len(events),
                    "fingerprint": fingerprint,
                    "statement": statement,
                    "db_system": db_system,
                    "total_ms": round(total_ms, 2),
                    "scope_name": scope.name,
                },
            )
