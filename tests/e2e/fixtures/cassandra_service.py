"""
Cassandra microservice for a user activity tracking system.

Anti-patterns present:
- PKN010: allow_filtering in CQL queries
- PKN011: session.prepare() called inside a loop
- PKN012: IN clause with %s parameter binding
- PKN013: batch.add() called inside a loop
"""

from __future__ import annotations

from uuid import UUID

# ---------------------------------------------------------------------------
# Simulated cassandra-driver stubs
# ---------------------------------------------------------------------------


class Session:
    def execute(self, query, params=None):
        return []

    def prepare(self, query: str):
        return PreparedStatement(query)


class PreparedStatement:
    def __init__(self, query: str):
        self.query_string = query


class BatchStatement:
    def add(self, stmt, params=None):
        pass


class BatchType:
    UNLOGGED = "UNLOGGED"
    LOGGED = "LOGGED"


# ---------------------------------------------------------------------------
# PKN010 — ALLOW FILTERING
# ---------------------------------------------------------------------------


class ActivityRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_country_and_status(self, country: str, status: str) -> list[dict]:
        """Find active users by country — ALLOW FILTERING because country is not PK."""
        rows = self._session.execute(
            "SELECT user_id, country, status, last_seen "
            "FROM user_activity "
            "WHERE country = %s AND status = %s ALLOW FILTERING",  # PKN010
            (country, status),
        )
        return [dict(r) for r in rows]

    def find_inactive_since(self, cutoff_ts: int) -> list[dict]:
        """Find inactive users — forces full partition scan."""
        rows = self._session.execute(
            f"SELECT user_id, last_seen FROM user_activity "
            f"WHERE last_seen < {cutoff_ts} ALLOW FILTERING"  # PKN010 (f-string)
        )
        return [dict(r) for r in rows]

    def search_by_email_domain(self, domain: str) -> list[dict]:
        """Search users by email domain without a secondary index."""
        cql = (
            "SELECT user_id, email FROM users "
            "WHERE email LIKE %s ALLOW FILTERING"  # PKN010
        )
        return list(self._session.execute(cql, (f"%@{domain}",)))


# ---------------------------------------------------------------------------
# PKN011 — session.prepare() inside a loop
# ---------------------------------------------------------------------------


class EventIngester:
    def __init__(self, session: Session) -> None:
        self._session = session

    def ingest_batch(self, events: list[dict]) -> None:
        """Ingest events one-by-one, preparing the same statement each time."""
        for event in events:
            stmt = self._session.prepare(  # PKN011: prepare in loop
                "INSERT INTO events (id, user_id, event_type, ts) "
                "VALUES (uuid(), ?, ?, toTimestamp(now()))"
            )
            self._session.execute(stmt, (event["user_id"], event["type"]))

    def update_counters(self, user_ids: list[UUID], delta: int) -> None:
        """Increment activity counters — prepares the statement per user."""
        for uid in user_ids:
            prepared = self._session.prepare(  # PKN011: prepare in loop
                "UPDATE activity_counters SET event_count = event_count + ? WHERE user_id = ?"
            )
            self._session.execute(prepared, (delta, uid))


# ---------------------------------------------------------------------------
# PKN012 — IN query with %s / ? binding
# ---------------------------------------------------------------------------


class UserLoader:
    def __init__(self, session: Session) -> None:
        self._session = session

    def load_many(self, user_ids: list[UUID]) -> list[dict]:
        """Load multiple users with IN — causes coordinator scatter-gather."""
        rows = self._session.execute(
            "SELECT user_id, email, created_at FROM users WHERE user_id IN %s",  # PKN012
            (tuple(user_ids),),
        )
        return [dict(r) for r in rows]

    def get_events_for_users(self, user_ids: list[UUID], event_type: str) -> list[dict]:
        """Multi-partition IN query on partition key."""
        rows = self._session.execute(
            "SELECT * FROM events WHERE user_id IN %s AND event_type = %s",  # PKN012
            (tuple(user_ids), event_type),
        )
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# PKN013 — batch.add() inside a loop
# ---------------------------------------------------------------------------


class BulkWriter:
    def __init__(self, session: Session) -> None:
        self._session = session

    def write_profile_updates(self, updates: list[dict]) -> None:
        """Apply profile updates via an UNLOGGED batch — multi-partition anti-pattern."""
        update_stmt = PreparedStatement(
            "UPDATE user_profiles SET display_name = ?, avatar_url = ? WHERE user_id = ?"
        )
        batch = BatchStatement()
        for update in updates:  # PKN013: batch.add in loop
            batch.add(
                update_stmt,
                (
                    update["display_name"],
                    update["avatar_url"],
                    update["user_id"],
                ),
            )
        self._session.execute(batch)

    def archive_events(self, events: list[dict]) -> None:
        """Move events to archive table using a batch — coordinator bottleneck."""
        insert_stmt = PreparedStatement(
            "INSERT INTO events_archive (user_id, event_id, payload, archived_at) "
            "VALUES (?, ?, ?, toTimestamp(now()))"
        )
        batch = BatchStatement()
        for ev in events:  # PKN013: batch.add in loop
            batch.add(insert_stmt, (ev["user_id"], ev["id"], str(ev["payload"])))
        self._session.execute(batch)
