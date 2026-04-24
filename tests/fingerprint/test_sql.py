from __future__ import annotations

from pyperfguard.fingerprint.sql import fingerprint_hash, normalize


def test_normalize_strips_string_literals():
    assert normalize("SELECT * FROM t WHERE name = 'alice'") == "SELECT * FROM T WHERE NAME = ?"


def test_normalize_strips_numeric_literals():
    assert normalize("SELECT * FROM t WHERE id = 42") == "SELECT * FROM T WHERE ID = ?"


def test_same_query_different_values_same_hash():
    h1 = fingerprint_hash("SELECT * FROM t WHERE id = 1")
    h2 = fingerprint_hash("SELECT * FROM t WHERE id = 99")
    assert h1 == h2


def test_different_queries_different_hash():
    h1 = fingerprint_hash("SELECT * FROM users WHERE id = 1")
    h2 = fingerprint_hash("SELECT * FROM posts WHERE id = 1")
    assert h1 != h2


def test_in_list_collapsed():
    h1 = fingerprint_hash("SELECT * FROM t WHERE id IN (1)")
    h2 = fingerprint_hash("SELECT * FROM t WHERE id IN (1, 2, 3, 4, 5)")
    assert h1 == h2


def test_strips_inline_comments():
    n = normalize("SELECT /* comment */ * FROM t")
    assert "comment" not in n


def test_strips_line_comments():
    n = normalize("SELECT * FROM t -- trailing comment")
    assert "trailing" not in n


def test_postgres_positional_params_normalized():
    h1 = fingerprint_hash("SELECT * FROM t WHERE a = $1 AND b = $2")
    h2 = fingerprint_hash("SELECT * FROM t WHERE a = $99 AND b = $100")
    assert h1 == h2


def test_trailing_semicolon_stripped():
    h1 = fingerprint_hash("SELECT 1;")
    h2 = fingerprint_hash("SELECT 1")
    assert h1 == h2


def test_hash_is_16_hex_chars():
    h = fingerprint_hash("SELECT 1")
    assert len(h) == 16
    assert all(c in "0123456789abcdef" for c in h)


def test_hex_literal_stripped():
    n = normalize("SELECT * FROM t WHERE blob = 0xDEADBEEF")
    assert "0xDEADBEEF" not in n
    assert "?" in n
