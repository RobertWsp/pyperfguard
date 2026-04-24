"""MongoDB command fingerprinting.

MongoDB commands are Python dicts (or BSON documents). We produce a canonical
string by keeping the key structure but replacing every value with its
Python type name. This means:

  {find: "users", filter: {_id: ObjectId("abc")}, limit: 10}
  ↓ normalize ↓
  {filter:{_id:?},find:?,limit:?}

Keys are sorted alphabetically so {a:1, b:2} and {b:2, a:1} get the same hash.
"""

from __future__ import annotations

import hashlib
from typing import Any


def normalize(command: Any, *, depth: int = 0) -> str:  # noqa: ANN401
    """Recursively normalize ``command`` to a canonical string."""
    if depth > 10:
        return "?"
    if isinstance(command, dict):
        parts = [
            f"{k}:{normalize(v, depth=depth + 1)}"
            for k, v in sorted(command.items(), key=lambda x: str(x[0]))
        ]
        return "{" + ",".join(parts) + "}"
    if isinstance(command, (list, tuple)):
        return "[?]" if command else "[]"
    return "?"


def fingerprint_hash(command: Any) -> str:  # noqa: ANN401
    """Return a 16-hex-char stable hash of the normalized command."""
    return hashlib.sha1(normalize(command).encode()).hexdigest()[:16]
