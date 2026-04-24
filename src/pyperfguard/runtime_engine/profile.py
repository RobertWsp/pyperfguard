"""Public ``profile()`` and ``async_profile()`` context managers — explicit scope openers.

Sync usage::

    from pyperfguard import profile

    with profile(name="import_users") as session:
        run_business_logic()

    for f in session.findings:
        print(f)

Async usage (FastAPI handlers, async services)::

    from pyperfguard import async_profile
    from pyperfguard.detectors.nplusone import NPlusOneDetector

    async def my_handler():
        async with async_profile("list_contacts", detectors=[NPlusOneDetector()]) as session:
            contacts = await service.list_all()
        for f in session.findings:
            logger.warning("finding", rule=f.rule_id, msg=f.message)
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from types import TracebackType

from pyperfguard.core.finding import Finding
from pyperfguard.runtime_engine.scope import Scope, reset_scope, set_scope


@dataclass(slots=True)
class ProfileSession:
    """Container returned by :func:`profile`. Holds the scope and findings."""

    scope: Scope
    findings: list[Finding] = field(default_factory=list)
    _token: object | None = None
    _detectors: list[object] = field(default_factory=list)

    def __enter__(self) -> ProfileSession:
        self._token = set_scope(self.scope)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            for detector in self._detectors:
                fn = getattr(detector, "evaluate", None)
                if callable(fn):
                    self.findings.extend(fn(self.scope))
        finally:
            if self._token is not None:
                reset_scope(self._token)  # type: ignore[arg-type]
                self._token = None

    async def __aenter__(self) -> ProfileSession:
        self._token = set_scope(self.scope)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        # Identical logic to __exit__ but usable in async contexts.
        self.__exit__(exc_type, exc, tb)

    def add_detector(self, detector: object) -> None:
        """Attach a detector exposing ``evaluate(scope) -> Iterable[Finding]``."""
        self._detectors.append(detector)


def profile(name: str = "anonymous", detectors: Iterable[object] | None = None) -> ProfileSession:
    """Sync context manager. Works with ``with profile(...) as s:``."""
    session = ProfileSession(scope=Scope(name=name))
    for d in detectors or ():
        session.add_detector(d)
    return session


def async_profile(
    name: str = "anonymous",
    detectors: Iterable[object] | None = None,
) -> ProfileSession:
    """Async context manager. Works with ``async with async_profile(...) as s:``."""
    return profile(name=name, detectors=detectors)
