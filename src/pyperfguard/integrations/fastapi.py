"""FastAPI integration for pyperfguard — automatic N+1 and anti-pattern detection.

Zero-config setup::

    from pyperfguard.integrations.fastapi import PyperfguardMiddleware
    from pyperfguard.detectors.nplusone import NPlusOneDetector

    app = FastAPI()
    app.add_middleware(
        PyperfguardMiddleware,
        detectors=[NPlusOneDetector(threshold=3)],
        on_findings=lambda findings, request: logger.warning(
            "pyperfguard.findings",
            path=str(request.url),
            count=len(findings),
            findings=[f.as_dict() for f in findings],
        ),
    )

Each HTTP request automatically creates a :class:`~pyperfguard.runtime_engine.scope.Scope`
bound to the asyncio context via ``contextvars``. All DB patchers (Cassandra, SQL,
Mongo) emit :class:`~pyperfguard.runtime_engine.events.QueryEvent` into that scope.
At the end of the request the registered detectors evaluate the scope and call
``on_findings`` with any problems found.

The middleware is designed for production use:
- Scope is bound via PEP 567 ``ContextVar`` — no shared state between concurrent requests.
- ``on_findings`` is called in the request context so you can add request metadata.
- Overhead is negligible: a single ``ContextVar.set`` per request.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from typing import Any

from pyperfguard.core.finding import Finding
from pyperfguard.runtime_engine.scope import Scope, reset_scope, set_scope

logger = logging.getLogger(__name__)

# Type aliases (avoid importing starlette/fastapi at module level so the module
# can be imported even when starlette is not installed).
_Request = Any
_Receive = Any
_Send = Any
_Scope = Any  # ASGI scope dict


class PyperfguardMiddleware:
    """ASGI middleware that wraps each request in a pyperfguard Scope.

    Parameters
    ----------
    app:
        The ASGI application to wrap.
    detectors:
        Detectors with an ``evaluate(scope) -> Iterable[Finding]`` method.
        Evaluated after each request.
    on_findings:
        Async or sync callable invoked when detectors emit findings.
        Receives ``(findings: list[Finding], request_info: dict)``.
        Defaults to a ``logging.warning`` call.
    exclude_paths:
        URL path prefixes to skip (e.g. ``["/health", "/metrics"]``).
    threshold:
        Shortcut: if ``detectors`` is empty and a value is given, a default
        :class:`~pyperfguard.detectors.nplusone.NPlusOneDetector` is created
        with this threshold.
    """

    def __init__(
        self,
        app: Any,
        detectors: Sequence[Any] | None = None,
        on_findings: Callable[..., Any] | None = None,
        exclude_paths: Sequence[str] = ("/health", "/metrics", "/docs", "/openapi.json", "/redoc"),
        threshold: int = 3,
    ) -> None:
        self.app = app
        self.exclude_paths = tuple(exclude_paths)
        self.on_findings = on_findings or _default_on_findings

        if detectors:
            self.detectors = list(detectors)
        else:
            from pyperfguard.detectors.nplusone import NPlusOneDetector

            self.detectors = [NPlusOneDetector(threshold=threshold)]

    async def __call__(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if any(path.startswith(ex) for ex in self.exclude_paths):
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET")
        pyguard_scope = Scope(name=f"{method} {path}")
        token = set_scope(pyguard_scope)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_scope(token)
            await self._evaluate(pyguard_scope, method, path, scope)

    async def _evaluate(
        self,
        pyguard_scope: Scope,
        method: str,
        path: str,
        asgi_scope: _Scope,
    ) -> None:
        findings: list[Finding] = []
        for detector in self.detectors:
            try:
                findings.extend(detector.evaluate(pyguard_scope))
            except Exception as exc:
                logger.debug("pyperfguard: detector error: %s", exc)

        if not findings:
            return

        request_info = {
            "method": method,
            "path": path,
            "query_count": pyguard_scope.event_count(),
        }
        try:
            result = self.on_findings(findings, request_info)
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:
            logger.debug("pyperfguard: on_findings error: %s", exc)


def _default_on_findings(findings: list[Finding], request_info: dict[str, Any]) -> None:
    logger.warning(
        "pyperfguard N+1 detected: %d finding(s) on %s %s",
        len(findings),
        request_info.get("method", "?"),
        request_info.get("path", "?"),
    )
    for f in findings:
        logger.warning("  [%s] %s", f.rule_id, f.message)
        for frame in f.stack[:3]:
            logger.warning("    at %s", frame)
