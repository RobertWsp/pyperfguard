"""CQL (Cassandra Query Language) fingerprinting.

CQL is syntactically close to SQL but has Cassandra-specific literal types:
- UUID literals  (e.g. 550e8400-e29b-41d4-a716-446655440000)
- Blob literals  (0x...)
- Collection literals ({}, [], ())
- USING TTL / TIMESTAMP clauses

Prepared statements already use ``?`` placeholders, so their
``prepared_statement.query_string`` is already fingerprint-ready; we still
run it through this function for consistent casing/spacing.
"""

from __future__ import annotations

import hashlib
import re

_TRANSFORMS: list[tuple[re.Pattern[str], str]] = [
    # UUID literals
    (
        re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            re.IGNORECASE,
        ),
        "?",
    ),
    # Blob literals
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "?"),
    # String literals (CQL uses '' for escaping inside strings)
    (re.compile(r"'(?:[^']|'')*'"), "?"),
    # Numeric literals
    (re.compile(r"\b\d+\.?\d*\b"), "?"),
    # Collapse IN (?, ?, …) to IN (?)
    (re.compile(r"\bIN\s*\(\s*\?(?:\s*,\s*\?)*\s*\)", re.IGNORECASE), "IN (?)"),
    # USING TTL/TIMESTAMP <value> → normalize value away
    (re.compile(r"\bUSING\s+(TTL|TIMESTAMP)\s+\d+\b", re.IGNORECASE), r"USING \1 ?"),
    # Normalize whitespace
    (re.compile(r"\s+"), " "),
]


def normalize(cql: str) -> str:
    """Return the normalized CQL string in uppercase."""
    q = cql.strip().rstrip(";")
    for pat, rep in _TRANSFORMS:
        q = pat.sub(rep, q)
    return q.strip().upper()


def fingerprint_hash(cql: str) -> str:
    """Return a 16-hex-char stable hash of the normalized CQL."""
    return hashlib.sha1(normalize(cql).encode()).hexdigest()[:16]
