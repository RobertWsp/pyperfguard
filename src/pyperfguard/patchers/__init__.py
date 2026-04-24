"""Driver patchers — each patches one library at import time via the MetaPathFinder.

Each patcher implements the ``Patcher`` protocol:
- ``module_name: str`` — the importable name that triggers patching
- ``install(module)`` — wrap driver entry points
- ``uninstall(module)`` — reverse install (idempotent)

Patchers emit :class:`pyperfguard.runtime_engine.events.QueryEvent` into the
:class:`pyperfguard.runtime_engine.event_bus.EventBus` so detectors can
consume them independently of how the data was captured.
"""

from pyperfguard.patchers.cassandra_driver import CassandraPatcher
from pyperfguard.patchers.dbapi import DBAPIPatcher, wrap_connect
from pyperfguard.patchers.pymongo import PyMongoPatcher
from pyperfguard.patchers.sqlalchemy import SQLAlchemyPatcher

__all__ = [
    "CassandraPatcher",
    "DBAPIPatcher",
    "PyMongoPatcher",
    "SQLAlchemyPatcher",
    "wrap_connect",
]
