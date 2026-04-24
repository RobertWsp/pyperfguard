"""
Well-written production-quality async service — should produce ZERO findings.

Demonstrates correct patterns for all rules:
- asyncio.gather instead of await-in-for-loop
- re.compile at module level, not inside loops
- datetime.now() outside loops
- copy.deepcopy outside loops
- import of heavy modules at top level
- proper typed except clauses
- immutable function defaults (None sentinels)
- asyncio.sleep instead of time.sleep
"""
from __future__ import annotations

import asyncio
import copy
import json
import re
from datetime import datetime
from typing import Any

try:
    import pandas as pd                                   # optional dependency guard
    _HAS_PANDAS = True
except ImportError:
    _HAS_PANDAS = False

# ---------------------------------------------------------------------------
# Module-level compiled patterns
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[a-z]{2,}$", re.IGNORECASE)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

# ---------------------------------------------------------------------------
# Async coroutines using asyncio.gather — no await-in-for-loop
# ---------------------------------------------------------------------------


async def fetch_user(user_id: int) -> dict:
    await asyncio.sleep(0)
    return {"id": user_id, "name": f"User {user_id}"}


async def send_notification(user_id: int, message: str) -> bool:
    await asyncio.sleep(0)
    return True


async def notify_users_concurrent(user_ids: list[int], message: str) -> list[dict]:
    """Send notifications concurrently with asyncio.gather — no serialization."""
    results = await asyncio.gather(
        *[send_notification(uid, message) for uid in user_ids]
    )
    return [{"user_id": uid, "sent": ok} for uid, ok in zip(user_ids, results)]


async def load_profiles_concurrent(user_ids: list[int]) -> list[dict]:
    """Fetch all user profiles in a single gather call."""
    profiles = await asyncio.gather(*[fetch_user(uid) for uid in user_ids])
    return list(profiles)


# ---------------------------------------------------------------------------
# Correct function defaults — None sentinel, not mutable containers
# ---------------------------------------------------------------------------


def build_filter_params(
    status: str = "published",
    tags: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build ORM filter parameters safely."""
    params: dict[str, Any] = {"status": status}
    if tags:
        params["tags__in"] = tags
    if extra:
        params.update(extra)
    return params


def paginate(page: int = 1, per_page: int = 20) -> dict[str, int]:
    return {"offset": (page - 1) * per_page, "limit": per_page}


# ---------------------------------------------------------------------------
# Proper exception handling — typed except clauses
# ---------------------------------------------------------------------------


def parse_json_body(raw: bytes) -> dict[str, Any]:
    """Parse JSON request body with explicit exception types."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Malformed request body: {exc}") from exc


def load_config(path: str) -> dict[str, Any]:
    """Load a JSON config file, raising clear errors on failure."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid config at {path}: {exc}") from exc


# ---------------------------------------------------------------------------
# String building with join — not concatenation in loop
# ---------------------------------------------------------------------------


def render_tag_cloud(tags: list[Any]) -> str:
    """Render tag cloud using join — no concatenation loop."""
    return " ".join(
        f'<a href="/tags/{tag.slug}/" class="tag">{tag.name}</a>'
        for tag in tags
    )


def build_csv_export(posts: list[dict]) -> str:
    """Export posts as CSV using join — memory efficient."""
    header = "id,title,author,created_at"
    rows = [
        f'{p["id"]},"{p["title"]}",{p["author_id"]},{p["created_at"]}'
        for p in posts
    ]
    return "\n".join([header, *rows])


# ---------------------------------------------------------------------------
# deepcopy and datetime.now() called once, outside loops
# ---------------------------------------------------------------------------

_BASE_TEMPLATE: dict = {
    "version": 2,
    "source": "pipeline",
    "tags": [],
    "metadata": {"processed": False},
}


def enrich_records(records: list[dict], source_tag: str) -> list[dict]:
    """Enrich records from a single deepcopy baseline — not per-iteration."""
    base = copy.deepcopy(_BASE_TEMPLATE)
    processed_at = datetime.now().isoformat()
    enriched = []
    for record in records:
        item = dict(base)
        item["tags"] = [source_tag]
        item["processed_at"] = processed_at
        item.update(record)
        enriched.append(item)
    return enriched


# ---------------------------------------------------------------------------
# Validation using module-level compiled patterns
# ---------------------------------------------------------------------------


def validate_emails(addresses: list[str]) -> list[str]:
    """Filter valid email addresses — regex compiled at module level."""
    return [addr for addr in addresses if _EMAIL_RE.match(addr)]


def validate_uuids(ids: list[str]) -> list[str]:
    """Filter well-formed UUIDs — pattern compiled once."""
    return [uid for uid in ids if _UUID_RE.match(uid)]


# ---------------------------------------------------------------------------
# list() used for mutation-during-iteration (legitimate PKN015 case)
# is NOT present here — we iterate generators directly
# ---------------------------------------------------------------------------


def active_sessions(sessions: dict[str, Any]) -> list[tuple[str, Any]]:
    """Iterate sessions safely without list() wrapping."""
    return [(k, v) for k, v in sessions.items() if v.get("active")]
