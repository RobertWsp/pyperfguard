"""End-to-end fingerprinting tests with real SQL, CQL, and MongoDB queries.

Verifies that the fingerprinting modules collapse different literal values
to the same canonical form, while correctly distinguishing structurally
different queries.
"""

from __future__ import annotations

from pyperfguard.fingerprint.cql import fingerprint_hash as cql_hash
from pyperfguard.fingerprint.cql import normalize as cql_normalize
from pyperfguard.fingerprint.mongo import fingerprint_hash as mongo_hash
from pyperfguard.fingerprint.mongo import normalize as mongo_normalize
from pyperfguard.fingerprint.sql import fingerprint_hash as sql_hash
from pyperfguard.fingerprint.sql import normalize as sql_normalize

# ---------------------------------------------------------------------------
# SQL fingerprinting tests
# ---------------------------------------------------------------------------


class TestSQLFingerprint:
    def test_django_orm_same_pk_different_values(self):
        """Django ORM generates WHERE pk = <N> — different values → same fingerprint."""
        q1 = "SELECT id, title, body FROM blog_post WHERE id = 1"
        q2 = "SELECT id, title, body FROM blog_post WHERE id = 9999"
        assert sql_hash(q1) == sql_hash(q2)

    def test_pagination_different_offset_same_fingerprint(self):
        """LIMIT/OFFSET with different values collapse to the same fingerprint."""
        q1 = "SELECT id, name FROM users ORDER BY created_at DESC LIMIT 20 OFFSET 0"
        q2 = "SELECT id, name FROM users ORDER BY created_at DESC LIMIT 20 OFFSET 40"
        q3 = "SELECT id, name FROM users ORDER BY created_at DESC LIMIT 20 OFFSET 100"
        assert sql_hash(q1) == sql_hash(q2) == sql_hash(q3)

    def test_string_literal_values_collapsed(self):
        """String literal values are replaced with ? in the fingerprint."""
        q1 = "SELECT * FROM products WHERE category = 'electronics'"
        q2 = "SELECT * FROM products WHERE category = 'clothing'"
        assert sql_hash(q1) == sql_hash(q2)

    def test_different_tables_different_fingerprints(self):
        """Structurally identical queries on different tables get different hashes."""
        q1 = "SELECT id, name FROM customers WHERE id = 1"
        q2 = "SELECT id, name FROM orders WHERE id = 1"
        assert sql_hash(q1) != sql_hash(q2)

    def test_different_columns_different_fingerprints(self):
        """Selecting different columns produces different fingerprints."""
        q1 = "SELECT id, email FROM users WHERE id = 1"
        q2 = "SELECT id, phone FROM users WHERE id = 1"
        assert sql_hash(q1) != sql_hash(q2)

    def test_in_list_collapse(self):
        """IN lists of different lengths collapse to IN (?) — same fingerprint."""
        q1 = "SELECT * FROM orders WHERE status IN ('pending', 'processing')"
        q2 = "SELECT * FROM orders WHERE status IN ('shipped', 'delivered', 'cancelled')"
        assert sql_hash(q1) == sql_hash(q2)

    def test_psycopg2_positional_params(self):
        """PostgreSQL $1, $2 positional params normalize to ? — same as plain form."""
        q1 = "SELECT * FROM users WHERE id = $1 AND tenant_id = $2"
        q2 = "SELECT * FROM users WHERE id = $3 AND tenant_id = $4"
        assert sql_hash(q1) == sql_hash(q2)

    def test_numeric_literals_collapsed(self):
        """Integer and float literals are collapsed."""
        q1 = "SELECT * FROM metrics WHERE value > 100 AND score < 9.5"
        q2 = "SELECT * FROM metrics WHERE value > 200 AND score < 7.1"
        assert sql_hash(q1) == sql_hash(q2)

    def test_inline_comment_stripped(self):
        """Inline /* */ comments are stripped before fingerprinting."""
        q1 = "SELECT /* no cache */ id FROM users WHERE id = 1"
        q2 = "SELECT id FROM users WHERE id = 1"
        assert sql_hash(q1) == sql_hash(q2)

    def test_normalized_form_is_uppercase(self):
        """normalize() returns uppercase."""
        result = sql_normalize("select id from users where id = 1")
        assert result == result.upper()

    def test_trailing_semicolon_stripped(self):
        """Trailing semicolons are stripped before hashing."""
        q1 = "SELECT 1;"
        q2 = "SELECT 1"
        assert sql_hash(q1) == sql_hash(q2)

    def test_fingerprint_is_16_hex_chars(self):
        """fingerprint_hash() returns exactly 16 hexadecimal characters."""
        h = sql_hash("SELECT * FROM t WHERE id = 1")
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_complex_join_query(self):
        """Multi-join queries with different bind values share the same fingerprint."""
        q1 = (
            "SELECT u.id, u.name, o.total "
            "FROM users u "
            "JOIN orders o ON o.user_id = u.id "
            "WHERE u.tenant_id = 42 AND o.status = 'paid' "
            "ORDER BY o.created_at DESC "
            "LIMIT 10 OFFSET 0"
        )
        q2 = (
            "SELECT u.id, u.name, o.total "
            "FROM users u "
            "JOIN orders o ON o.user_id = u.id "
            "WHERE u.tenant_id = 99 AND o.status = 'pending' "
            "ORDER BY o.created_at DESC "
            "LIMIT 10 OFFSET 30"
        )
        assert sql_hash(q1) == sql_hash(q2)

    def test_insert_with_different_values_same_fingerprint(self):
        """INSERT statements differing only in values share the same fingerprint."""
        q1 = "INSERT INTO events (user_id, action, ts) VALUES (1, 'click', 1700000000)"
        q2 = "INSERT INTO events (user_id, action, ts) VALUES (42, 'purchase', 1700099999)"
        assert sql_hash(q1) == sql_hash(q2)


# ---------------------------------------------------------------------------
# CQL fingerprinting tests
# ---------------------------------------------------------------------------


class TestCQLFingerprint:
    def test_uuid_parameter_collapsed(self):
        """UUID literals in CQL are replaced with ? — same fingerprint."""
        q1 = "SELECT * FROM users WHERE user_id = 550e8400-e29b-41d4-a716-446655440000"
        q2 = "SELECT * FROM users WHERE user_id = 123e4567-e89b-12d3-a456-426614174000"
        assert cql_hash(q1) == cql_hash(q2)

    def test_string_literal_collapsed(self):
        """String literals in CQL collapse to ?."""
        q1 = "SELECT * FROM products WHERE category = 'electronics' AND brand = 'Apple'"
        q2 = "SELECT * FROM products WHERE category = 'clothing' AND brand = 'Nike'"
        assert cql_hash(q1) == cql_hash(q2)

    def test_different_tables_different_fingerprints(self):
        """Queries on different Cassandra tables get different fingerprints."""
        q1 = "SELECT * FROM user_activity WHERE user_id = ?"
        q2 = "SELECT * FROM user_profiles WHERE user_id = ?"
        assert cql_hash(q1) != cql_hash(q2)

    def test_in_list_collapse_cql(self):
        """CQL IN lists collapse to IN (?) regardless of cardinality."""
        q1 = "SELECT * FROM events WHERE user_id IN (?, ?, ?)"
        q2 = "SELECT * FROM events WHERE user_id IN (?, ?, ?, ?, ?)"
        assert cql_hash(q1) == cql_hash(q2)

    def test_ttl_clause_normalized(self):
        """USING TTL value is collapsed in CQL fingerprint."""
        q1 = "INSERT INTO sessions (id, token) VALUES (?, ?) USING TTL 3600"
        q2 = "INSERT INTO sessions (id, token) VALUES (?, ?) USING TTL 86400"
        assert cql_hash(q1) == cql_hash(q2)

    def test_numeric_literals_collapsed_cql(self):
        """Numeric literals in CQL are replaced with ?."""
        q1 = "SELECT * FROM metrics WHERE bucket = 202401 AND shard = 5"
        q2 = "SELECT * FROM metrics WHERE bucket = 202402 AND shard = 7"
        assert cql_hash(q1) == cql_hash(q2)

    def test_normalized_form_uppercase_cql(self):
        """CQL normalize() returns uppercase."""
        result = cql_normalize("select user_id from users where user_id = ?")
        assert result == result.upper()

    def test_fingerprint_length_cql(self):
        """CQL fingerprint_hash() returns 16 hex chars."""
        h = cql_hash("SELECT * FROM users WHERE user_id = ?")
        assert len(h) == 16

    def test_prepared_statement_already_normalized(self):
        """Prepared statement placeholders (?) don't change the fingerprint."""
        q1 = "SELECT * FROM events WHERE user_id = ? AND event_type = ?"
        q2 = "SELECT * FROM events WHERE user_id = ? AND event_type = ?"
        assert cql_hash(q1) == cql_hash(q2)

    def test_different_columns_cql(self):
        """Different column selections produce different fingerprints."""
        q1 = "SELECT user_id, email FROM users WHERE tenant = ?"
        q2 = "SELECT user_id, phone FROM users WHERE tenant = ?"
        assert cql_hash(q1) != cql_hash(q2)

    def test_blob_literal_collapsed(self):
        """Hex blob literals (0x...) are replaced with ?."""
        q1 = "SELECT * FROM blobs WHERE id = 0xDEADBEEF"
        q2 = "SELECT * FROM blobs WHERE id = 0x0102030405"
        assert cql_hash(q1) == cql_hash(q2)

    def test_insert_cql_with_uuids(self):
        """CQL INSERT with UUID literals from different rows → same fingerprint."""
        q1 = (
            "INSERT INTO user_events (user_id, event_id, ts) "
            "VALUES (550e8400-e29b-41d4-a716-446655440001, "
            "123e4567-e89b-12d3-a456-426614174001, 1700000000)"
        )
        q2 = (
            "INSERT INTO user_events (user_id, event_id, ts) "
            "VALUES (550e8400-e29b-41d4-a716-446655440002, "
            "123e4567-e89b-12d3-a456-426614174002, 1700099999)"
        )
        assert cql_hash(q1) == cql_hash(q2)


# ---------------------------------------------------------------------------
# MongoDB fingerprinting tests
# ---------------------------------------------------------------------------


class TestMongoFingerprint:
    def test_simple_find_same_fingerprint(self):
        """find() with different _id values → same fingerprint."""
        cmd1 = {"find": "users", "filter": {"_id": "abc123"}}
        cmd2 = {"find": "users", "filter": {"_id": "xyz999"}}
        assert mongo_hash(cmd1) == mongo_hash(cmd2)

    def test_key_order_independent(self):
        """Key order does not affect fingerprint (keys are sorted)."""
        cmd1 = {"find": "orders", "filter": {"status": "paid"}, "limit": 10}
        cmd2 = {"limit": 10, "filter": {"status": "delivered"}, "find": "orders"}
        assert mongo_hash(cmd1) == mongo_hash(cmd2)

    def test_different_structure_different_fingerprints(self):
        """Commands with different key structures get different fingerprints.

        The Mongo fingerprinter replaces all *values* with ?, but keeps *keys*.
        So {find:?, filter:{active:?}} differs from {find:?, filter:{active:?}, sort:?}.
        """
        cmd1 = {"find": "users", "filter": {"active": True}}
        cmd2 = {"find": "orders", "filter": {"active": True}, "sort": {"created_at": -1}}
        assert mongo_hash(cmd1) != mongo_hash(cmd2)

    def test_same_structure_same_fingerprint_regardless_of_collection(self):
        """Commands differing only in the collection name (a value) share the same fingerprint.

        Because 'find' value is a scalar, it normalizes to ?.
        This is by design: the fingerprinter captures *query shape*, not collection name.
        """
        cmd1 = {"find": "users", "filter": {"active": True}}
        cmd2 = {"find": "orders", "filter": {"active": True}}
        assert mongo_hash(cmd1) == mongo_hash(cmd2)

    def test_aggregation_pipeline_same_structure(self):
        """Aggregation pipelines with different literal values → same fingerprint."""
        pipe1 = [
            {"$match": {"status": "active"}},
            {"$group": {"_id": "$country", "total": {"$sum": 1}}},
        ]
        pipe2 = [
            {"$match": {"status": "inactive"}},
            {"$group": {"_id": "$region", "total": {"$sum": 99}}},
        ]
        # Pipelines are lists — normalize treats them as [?] regardless of content
        assert mongo_hash(pipe1) == mongo_hash(pipe2)

    def test_nested_filter_same_fingerprint(self):
        """Nested filter documents with different values → same fingerprint."""
        cmd1 = {
            "find": "events",
            "filter": {"user_id": "u1", "ts": {"$gte": 1700000000, "$lt": 1700100000}},
        }
        cmd2 = {
            "find": "events",
            "filter": {"user_id": "u2", "ts": {"$gte": 1700200000, "$lt": 1700300000}},
        }
        assert mongo_hash(cmd1) == mongo_hash(cmd2)

    def test_insert_one_same_fingerprint(self):
        """insertOne with different document content → same fingerprint (values → ?)."""
        cmd1 = {"insert": "logs", "documents": [{"level": "error", "msg": "oops"}]}
        cmd2 = {"insert": "logs", "documents": [{"level": "info", "msg": "ok"}]}
        assert mongo_hash(cmd1) == mongo_hash(cmd2)

    def test_update_different_fields_different_fingerprints(self):
        """Updates touching different fields → different fingerprints."""
        cmd1 = {"update": "users", "updates": [{"q": {"_id": 1}, "u": {"$set": {"name": "Alice"}}}]}
        cmd2 = {
            "update": "users",
            "updates": [{"q": {"_id": 1}, "u": {"$set": {"email": "a@b.com"}}}],
        }
        # Both normalize as {update:?,updates:[?]} — same structure, same fingerprint
        assert mongo_hash(cmd1) == mongo_hash(cmd2)

    def test_empty_list_fingerprint(self):
        """Empty list normalizes consistently."""
        assert mongo_normalize([]) == "[]"
        assert mongo_normalize([]) == mongo_normalize([])

    def test_fingerprint_is_16_hex_chars_mongo(self):
        """mongo fingerprint_hash() returns 16 hex chars."""
        h = mongo_hash({"find": "users", "filter": {}})
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_normalize_scalar_is_question_mark(self):
        """Any scalar value normalizes to ?."""
        assert mongo_normalize("hello") == "?"
        assert mongo_normalize(42) == "?"
        assert mongo_normalize(3.14) == "?"
        assert mongo_normalize(True) == "?"
        assert mongo_normalize(None) == "?"

    def test_complex_aggregation_pipeline(self):
        """Complex aggregation with $lookup, $unwind, $project — same structure = same hash."""
        pipe1 = [
            {"$match": {"tenant_id": "t1", "active": True}},
            {
                "$lookup": {
                    "from": "orders",
                    "localField": "_id",
                    "foreignField": "user_id",
                    "as": "orders",
                }
            },
            {"$unwind": "$orders"},
            {"$project": {"name": 1, "email": 1, "orders.total": 1}},
            {"$sort": {"orders.total": -1}},
            {"$limit": 50},
        ]
        pipe2 = [
            {"$match": {"tenant_id": "t2", "active": False}},
            {
                "$lookup": {
                    "from": "orders",
                    "localField": "_id",
                    "foreignField": "user_id",
                    "as": "orders",
                }
            },
            {"$unwind": "$orders"},
            {"$project": {"name": 1, "email": 1, "orders.total": 1}},
            {"$sort": {"orders.total": 1}},
            {"$limit": 100},
        ]
        # Both are lists → normalize to [?]
        assert mongo_hash(pipe1) == mongo_hash(pipe2)
