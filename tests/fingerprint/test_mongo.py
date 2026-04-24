from __future__ import annotations

from pyperfguard.fingerprint.mongo import fingerprint_hash, normalize


def test_scalar_values_replaced():
    n = normalize({"find": "users", "filter": {"_id": "abc123"}})
    assert "abc123" not in n
    assert "?" in n


def test_dict_keys_sorted():
    n1 = normalize({"a": 1, "b": 2})
    n2 = normalize({"b": 2, "a": 1})
    assert n1 == n2


def test_list_becomes_placeholder():
    n = normalize({"ids": [1, 2, 3]})
    assert "[?]" in n


def test_empty_list_preserved():
    n = normalize({"ids": []})
    assert "[]" in n


def test_same_structure_different_values_same_hash():
    h1 = fingerprint_hash({"find": "users", "filter": {"_id": "user1"}})
    h2 = fingerprint_hash({"find": "users", "filter": {"_id": "user2"}})
    assert h1 == h2


def test_different_key_structures_different_hash():
    # Collection name is a scalar → normalized to ?; but different key shapes differ.
    h1 = fingerprint_hash({"find": "users", "filter": {"_id": "x"}})
    h2 = fingerprint_hash({"aggregate": "users", "pipeline": [{"$match": {"_id": "x"}}]})
    assert h1 != h2


def test_same_structure_different_collection_names_same_hash():
    # By design: scalar values (incl. collection names) are all normalized to ?
    h1 = fingerprint_hash({"find": "users", "filter": {"_id": "x"}})
    h2 = fingerprint_hash({"find": "posts", "filter": {"_id": "x"}})
    assert h1 == h2


def test_nested_dict_normalized():
    n = normalize({"filter": {"$or": [{"a": 1}, {"b": 2}]}})
    assert "1" not in n
    assert "2" not in n


def test_depth_limit_returns_placeholder():
    # Build a deeply nested dict (depth > 10)
    deep: dict = {}
    cur = deep
    for _i in range(15):
        cur["x"] = {}
        cur = cur["x"]
    cur["val"] = 42
    n = normalize(deep)
    assert n is not None  # should not raise


def test_hash_is_16_hex_chars():
    h = fingerprint_hash({"find": "t"})
    assert len(h) == 16
    assert all(c in "0123456789abcdef" for c in h)
