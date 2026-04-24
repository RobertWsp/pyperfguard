"""
Async API handlers for a notification service.

Anti-patterns present:
- PKN008: await inside a regular for loop (serializes async work)
- PKN009: time.sleep() and requests.get() inside async def
"""
from __future__ import annotations

import time
import requests
from typing import Any


# ---------------------------------------------------------------------------
# Simulated async stubs
# ---------------------------------------------------------------------------

async def fetch_user(user_id: int) -> dict:
    return {"id": user_id, "name": f"User {user_id}"}


async def send_notification(user_id: int, message: str) -> bool:
    return True


async def fetch_device_tokens(user_id: int) -> list[str]:
    return [f"token_{user_id}_0", f"token_{user_id}_1"]


async def push_to_device(token: str, payload: dict) -> dict:
    return {"token": token, "status": "delivered"}


# ---------------------------------------------------------------------------
# PKN008 — await inside a regular for loop
# ---------------------------------------------------------------------------

async def notify_users_serial(user_ids: list[int], message: str) -> list[dict]:
    """Send notifications to all users — serialized due to await in for loop."""
    results = []
    for uid in user_ids:
        user = await fetch_user(uid)                      # PKN008: await in for loop
        ok = await send_notification(uid, message)        # PKN008: await in for loop
        results.append({"user": user["name"], "sent": ok})
    return results


async def collect_device_tokens(user_ids: list[int]) -> dict[int, list[str]]:
    """Aggregate device tokens for push delivery — N sequential awaits."""
    token_map: dict[int, list[str]] = {}
    for uid in user_ids:
        tokens = await fetch_device_tokens(uid)           # PKN008: await in for loop
        token_map[uid] = tokens
    return token_map


async def fan_out_push(user_ids: list[int], payload: dict) -> list[dict]:
    """Send push notifications to each user's devices — sequential fan-out."""
    all_results = []
    for uid in user_ids:
        tokens = await fetch_device_tokens(uid)           # PKN008: await in for loop
        for token in tokens:
            result = await push_to_device(token, payload) # PKN008: await in for loop
            all_results.append(result)
    return all_results


# ---------------------------------------------------------------------------
# PKN009 — blocking calls in async def
# ---------------------------------------------------------------------------

async def health_probe(service_url: str) -> dict[str, Any]:
    """Probe an external service — uses blocking requests in async context."""
    time.sleep(0.01)                                      # PKN009: blocks event loop
    resp = requests.get(f"{service_url}/health")          # PKN009: blocking HTTP
    return {
        "url": service_url,
        "status": resp.status_code,
        "latency_ms": resp.elapsed.total_seconds() * 1000,
    }


async def enrich_event(event: dict) -> dict:
    """Call external enrichment API — synchronous HTTP in async handler."""
    resp = requests.post(                                  # PKN009: blocking HTTP
        "https://enrichment.internal/api/v1/enrich",
        json={"event_id": event.get("id"), "payload": event},
        timeout=5,
    )
    enriched = resp.json() if resp.ok else {}
    return {**event, **enriched}


async def rate_limited_sender(messages: list[dict]) -> list[bool]:
    """Send messages with a rate limit — uses blocking sleep."""
    results = []
    for msg in messages:
        ok = await send_notification(msg["user_id"], msg["text"])
        results.append(ok)
        time.sleep(0.1)                                   # PKN009: blocks event loop
    return results
