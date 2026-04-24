"""RuntimeEngine — orchestrates patcher installation and detector wiring.

Usage (programmatic)::

    from pyperfguard.runtime_engine.engine import RuntimeEngine
    from pyperfguard.core.config import Config
    from pyperfguard.plugins import bootstrap

    cfg = Config.load()
    reg = bootstrap()
    engine = RuntimeEngine(config=cfg, registry=reg)
    engine.start()
    # ... run app ...
    engine.stop()

Usage (bootstrap/zero-conf)::

    PYPERFGUARD_ENABLED=1 pyperfguard-bootstrap install
    # Then add -E PYPERFGUARD_ENABLED=1 to your run command.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pyperfguard.core.config import Config
from pyperfguard.core.registry import Registry
from pyperfguard.runtime_engine.import_hook import PyperfMetaPathFinder, install_finder


@dataclass(slots=True)
class RuntimeEngine:
    """Coordinates patcher discovery and import-hook installation."""

    config: Config
    registry: Registry
    _finder: PyperfMetaPathFinder | None = field(default=None, init=False, repr=False)

    def start(self) -> None:
        """Install the MetaPathFinder and register all configured patchers."""
        self._finder = install_finder()

        allowed: set[str] | None = (
            set(self.config.runtime.patchers) if self.config.runtime.patchers else None
        )
        for name, patcher in self.registry.patchers().items():
            if allowed is None or name in allowed:
                self._finder.register(patcher)

    def stop(self) -> None:
        """Uninstall all patchers (but leave the finder in sys.meta_path)."""
        if self._finder is None:
            return
        for name in list(self._finder._patchers):
            self._finder.unregister(name)

    def is_running(self) -> bool:
        return self._finder is not None and bool(self._finder._patchers)
