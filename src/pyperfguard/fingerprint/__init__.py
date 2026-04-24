"""Query fingerprinting — normalize queries from different DB systems to
a canonical form so N+1 detection can group 'same query, different args'
into a single pattern.

All normalizers are pure-Python (no external dependencies). Optional
high-precision backends (pglast for PostgreSQL) can be layered on top.
"""

from pyperfguard.fingerprint.cql import fingerprint_hash as cql_hash
from pyperfguard.fingerprint.cql import normalize as cql_normalize
from pyperfguard.fingerprint.mongo import fingerprint_hash as mongo_hash
from pyperfguard.fingerprint.mongo import normalize as mongo_normalize
from pyperfguard.fingerprint.sql import fingerprint_hash as sql_hash
from pyperfguard.fingerprint.sql import normalize as sql_normalize

__all__ = [
    "cql_hash",
    "cql_normalize",
    "mongo_hash",
    "mongo_normalize",
    "sql_hash",
    "sql_normalize",
]
