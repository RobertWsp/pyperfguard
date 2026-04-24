"""
Django-like HTTP handlers for a blog application.

Demonstrates common Django ORM anti-patterns found in production code:
- N+1 ORM query patterns (PKN003 via string concat in loop)
- Mutable default arguments in view helpers (PKN001)
- Bare except swallowing errors silently (PKN002)
- Blocking calls inside async views (PKN009)
"""
from __future__ import annotations

import json
import time
import requests
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Simulated ORM / model stubs (no real Django needed)
# ---------------------------------------------------------------------------

class QuerySet:
    def __init__(self, items):
        self._items = items

    def filter(self, **kwargs):
        return self

    def select_related(self, *fields):
        return self

    def all(self):
        return self

    def __iter__(self):
        return iter(self._items)


class Post:
    objects = QuerySet([])

    def __init__(self, pk, title, author_id):
        self.pk = pk
        self.title = title
        self.author_id = author_id
        self.tags = QuerySet([])
        self.comments = QuerySet([])

    def get_absolute_url(self):
        return f"/posts/{self.pk}/"


class Tag:
    objects = QuerySet([])


class Comment:
    objects = QuerySet([])


# ---------------------------------------------------------------------------
# PKN001 — mutable default arguments
# ---------------------------------------------------------------------------

def build_filter_params(status="published", tags=[]):   # PKN001: list default
    """Build ORM filter kwargs from request query params."""
    params = {"status": status}
    if tags:
        params["tags__in"] = tags
    return params


def get_pagination_opts(page=1, per_page=20, extra={}):  # PKN001: dict default
    """Return pagination parameters for list views."""
    opts = {"page": page, "per_page": per_page}
    opts.update(extra)
    return opts


# ---------------------------------------------------------------------------
# PKN002 — bare except
# ---------------------------------------------------------------------------

def safe_json_body(request_body: bytes) -> dict[str, Any]:
    """Parse request JSON body, returning empty dict on any failure."""
    try:
        return json.loads(request_body)
    except:                                               # PKN002: bare except
        return {}


def load_user_preferences(user_id: int) -> dict[str, Any]:
    """Load serialized preferences from the DB, tolerating corruption."""
    try:
        raw = _fetch_preferences_blob(user_id)
        return json.loads(raw)
    except:                                               # PKN002: bare except
        return {"theme": "light", "notifications": True}


def _fetch_preferences_blob(user_id: int) -> str:
    return "{}"


# ---------------------------------------------------------------------------
# PKN003 — string concatenation inside a loop
# ---------------------------------------------------------------------------

def render_tag_cloud(tags) -> str:
    """Render an HTML tag cloud from a queryset of tags."""
    html = ""
    for tag in tags:                                      # PKN003: += in loop
        html += f'<a href="/tags/{tag.slug}/" class="tag">{tag.name}</a> '
    return html.strip()


def build_csv_export(posts) -> str:
    """Export post list as CSV without using csv module."""
    csv = "id,title,author,created_at\n"
    for post in posts:                                    # PKN003: += in loop
        csv += f'{post.pk},"{post.title}",{post.author_id},{post.created_at}\n'
    return csv


# ---------------------------------------------------------------------------
# PKN009 — blocking calls inside async views
# ---------------------------------------------------------------------------

async def async_post_list(request):
    """Async view: fetch posts and enrich with external metadata."""
    posts = list(Post.objects.all())

    # Blocking HTTP call in an async context — freezes the event loop
    response = requests.get("https://api.internal/post-stats")  # PKN009
    stats = response.json() if response.ok else {}

    time.sleep(0.05)                                      # PKN009: blocks event loop

    results = []
    for post in posts:
        results.append({
            "id": post.pk,
            "title": post.title,
            "views": stats.get(str(post.pk), 0),
        })
    return {"posts": results}


async def async_health_check(request):
    """Ping downstream services — wrong: uses blocking requests."""
    services = ["db", "cache", "search"]
    statuses = {}
    for svc in services:
        resp = requests.get(f"https://health.internal/{svc}")  # PKN009
        statuses[svc] = "ok" if resp.status_code == 200 else "degraded"
    return {"statuses": statuses}
