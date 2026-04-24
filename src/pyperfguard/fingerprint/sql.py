"""SQL query fingerprinting.

Reduces a SQL statement to a canonical form by stripping literal values
and collapsing IN-list cardinality — so ``SELECT * FROM t WHERE id = 1``
and ``SELECT * FROM t WHERE id = 99`` share the same fingerprint.

No external dependencies: pure regex. For PostgreSQL-specific precision,
callers can optionally use ``pglast`` on top of this.
"""

from __future__ import annotations

import hashlib
import re

# Order matters: apply in sequence.
_TRANSFORMS: list[tuple[re.Pattern[str], str]] = [
    # Strip inline comments (/* ... */)
    (re.compile(r"/\*.*?\*/", re.DOTALL), " "),
    # Strip line comments (-- ...)
    (re.compile(r"--[^\n]*"), " "),
    # E-string literals  E'...'
    (re.compile(r"\bE'(?:[^'\\]|\\.)*'", re.IGNORECASE), "?"),
    # Single-quoted strings (handle '' escaping inside)
    (re.compile(r"'(?:[^'\\]|\\.)*(?:''[^'\\]|\\.)*'"), "?"),
    # Double-quoted strings (MySQL, SQLite identifiers — keep content but quote)
    # Note: we skip these because double-quotes are identifiers in standard SQL
    # Hex literals (PostgreSQL bytea, MySQL blobs)
    (re.compile(r"\b0x[0-9a-fA-F]+\b", re.IGNORECASE), "?"),
    # Numeric literals: integers, decimals, scientific notation
    (re.compile(r"\b\d+\.?\d*(?:[eE][+-]?\d+)?\b"), "?"),
    # PostgreSQL positional params ($1, $2 …) → already placeholders
    (re.compile(r"\$\d+"), "?"),
    # Collapse IN (?, ?, ...) to IN (?) regardless of list length
    (re.compile(r"\bIN\s*\(\s*\?(?:\s*,\s*\?)*\s*\)", re.IGNORECASE), "IN (?)"),
    # Normalize whitespace
    (re.compile(r"\s+"), " "),
]


def normalize(sql: str) -> str:
    """Return the normalized (literal-stripped) SQL string in uppercase."""
    q = sql.strip().rstrip(";")
    for pat, rep in _TRANSFORMS:
        q = pat.sub(rep, q)
    return q.strip().upper()


def fingerprint_hash(sql: str) -> str:
    """Return a 16-hex-char stable hash of the normalized SQL."""
    return hashlib.sha1(normalize(sql).encode()).hexdigest()[:16]
