from __future__ import annotations

from pyperfguard.fingerprint.cql import fingerprint_hash, normalize


def test_normalize_strips_uuid():
    n = normalize("SELECT * FROM users WHERE id = 550e8400-e29b-41d4-a716-446655440000")
    assert "550e8400" not in n
    assert "?" in n


def test_normalize_strips_string_literals():
    n = normalize("INSERT INTO t (name) VALUES ('alice')")
    assert "alice" not in n


def test_normalize_strips_numbers():
    n = normalize("SELECT * FROM t WHERE age = 25")
    assert "25" not in n


def test_same_values_different_uuids_same_hash():
    h1 = fingerprint_hash("SELECT * FROM t WHERE id = 550e8400-e29b-41d4-a716-446655440000")
    h2 = fingerprint_hash("SELECT * FROM t WHERE id = 6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    assert h1 == h2


def test_in_list_collapsed():
    h1 = fingerprint_hash("SELECT * FROM t WHERE id IN (?)")
    h2 = fingerprint_hash("SELECT * FROM t WHERE id IN (?, ?, ?)")
    assert h1 == h2


def test_using_ttl_normalized():
    h1 = fingerprint_hash("INSERT INTO t (id) VALUES (?) USING TTL 3600")
    h2 = fingerprint_hash("INSERT INTO t (id) VALUES (?) USING TTL 86400")
    assert h1 == h2


def test_using_timestamp_normalized():
    h1 = fingerprint_hash("INSERT INTO t (id) VALUES (?) USING TIMESTAMP 1000000")
    h2 = fingerprint_hash("INSERT INTO t (id) VALUES (?) USING TIMESTAMP 9999999")
    assert h1 == h2


def test_hash_is_16_hex_chars():
    h = fingerprint_hash("SELECT * FROM t WHERE id = ?")
    assert len(h) == 16
    assert all(c in "0123456789abcdef" for c in h)
