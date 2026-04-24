"""Tests for Cassandra-specific rules: PKN011, PKN012, PKN013."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.cassandra_batch_loop import CassandraBatchLoopRule
from pyperfguard.rules.cassandra_in_query import CassandraInQueryRule
from pyperfguard.rules.cassandra_prepare_loop import CassandraPrepareLoopRule


def _run(src: str, *rules) -> list:
    reg = Registry()
    for rule in rules:
        reg.register_rule(rule)
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


# ── PKN011: cassandra-prepare-in-loop ────────────────────────────────────────

class TestCassandraPrepareLoop:
    def test_prepare_inside_loop_flagged(self):
        src = (
            "for uid in user_ids:\n"
            "    stmt = session.prepare('SELECT * FROM users WHERE id = ?')\n"
            "    session.execute(stmt, [uid])\n"
        )
        findings = _run(src, CassandraPrepareLoopRule())
        assert len(findings) == 1
        assert findings[0].rule_id == "PKN011"

    def test_prepare_outside_loop_not_flagged(self):
        src = "stmt = session.prepare('SELECT * FROM users WHERE id = ?')\n"
        findings = _run(src, CassandraPrepareLoopRule())
        assert findings == []

    def test_other_method_in_loop_not_flagged(self):
        src = "for uid in ids:\n    session.execute(stmt, [uid])\n"
        findings = _run(src, CassandraPrepareLoopRule())
        assert findings == []

    def test_prepare_in_while_loop_flagged(self):
        src = "while items:\n    stmt = session.prepare('SELECT 1')\n    items.pop()\n"
        findings = _run(src, CassandraPrepareLoopRule())
        assert len(findings) == 1


# ── PKN012: cassandra-in-multi-partition ─────────────────────────────────────

class TestCassandraInQuery:
    def test_in_with_percent_s_flagged(self):
        src = "session.execute('SELECT * FROM users WHERE id IN %s', [tuple(ids)])\n"
        findings = _run(src, CassandraInQueryRule())
        assert len(findings) == 1
        assert findings[0].rule_id == "PKN012"

    def test_in_with_question_mark_flagged(self):
        src = "session.execute('SELECT * FROM t WHERE id IN (?)', [ids])\n"
        findings = _run(src, CassandraInQueryRule())
        assert len(findings) == 1

    def test_in_with_named_param_flagged(self):
        src = "session.execute('SELECT * FROM t WHERE id IN %(ids)s', params)\n"
        findings = _run(src, CassandraInQueryRule())
        assert len(findings) == 1

    def test_string_without_in_not_flagged(self):
        src = "session.execute('SELECT * FROM t WHERE id = ?', [uid])\n"
        findings = _run(src, CassandraInQueryRule())
        assert findings == []

    def test_in_without_param_not_flagged(self):
        src = "session.execute(\"SELECT * FROM t WHERE status IN ('active', 'pending')\")\n"
        findings = _run(src, CassandraInQueryRule())
        assert findings == []

    def test_in_case_insensitive(self):
        src = "session.execute('select * from t where id in %s', [ids])\n"
        findings = _run(src, CassandraInQueryRule())
        assert len(findings) == 1

    def test_log_format_string_not_flagged(self):
        # Regression: Flask/stdlib log format strings like "%(levelname)s in %(module)s"
        # used to match the IN+placeholder pattern. Must not be flagged.
        src = "logging.basicConfig(format='%(levelname)s in %(module)s: %(message)s')\n"
        findings = _run(src, CassandraInQueryRule())
        assert findings == []

    def test_log_format_with_in_keyword_not_flagged(self):
        # Another log-format false positive: "Error in %(name)s"
        src = "logger.setFormatter(logging.Formatter('Error in %(name)s'))\n"
        findings = _run(src, CassandraInQueryRule())
        assert findings == []

    def test_docstring_with_in_not_flagged(self):
        # Docstring containing "IN %s" description must not be flagged.
        src = '"""Execute IN %s query — not real SQL."""\n'
        findings = _run(src, CassandraInQueryRule())
        assert findings == []

    def test_rst_role_in_docstring_not_flagged(self):
        # Regression: Flask docstrings with RST :role:` syntax like "in :file:`..."
        # matched the IN :[name] pattern via backtracking. Must not be flagged.
        src = '"""Example in :file:`__init__.py` or from :func:`open_resource`."""\n'
        findings = _run(src, CassandraInQueryRule())
        assert findings == []

    def test_rst_func_role_not_flagged(self):
        # Another RST role: "loaded in :func:`sorted` order"
        src = '"""Keys are loaded in :func:`sorted` order from config."""\n'
        findings = _run(src, CassandraInQueryRule())
        assert findings == []

    def test_function_docstring_with_cql_example_not_flagged(self):
        # Regression: cassandra/query.py docstrings contain CQL IN examples.
        # Must not be flagged — they are documentation, not live queries.
        src = (
            "def execute_in(ids):\n"
            "    '''\n"
            "    Execute SELECT * FROM users WHERE id IN %s.\n"
            "    Pass a tuple of ids as the parameter.\n"
            "    '''\n"
            "    session.execute('SELECT * FROM users WHERE id IN %s', [tuple(ids)])\n"
        )
        findings = _run(src, CassandraInQueryRule())
        # The docstring constant should NOT be flagged; the live query SHOULD be.
        assert len(findings) == 1
        assert findings[0].rule_id == "PKN012"

    def test_non_first_string_in_function_flagged(self):
        # A string that is NOT the docstring (not the first statement) IS flagged.
        src = (
            "def f():\n"
            "    x = 1\n"
            "    session.execute('SELECT * FROM t WHERE id IN %s', ids)\n"
        )
        findings = _run(src, CassandraInQueryRule())
        assert len(findings) == 1

    def test_class_docstring_not_flagged(self):
        # Class docstring with CQL example — must not be flagged.
        src = (
            "class Repo:\n"
            "    '''\n"
            "    SELECT * FROM t WHERE pk IN %s — use execute_concurrent instead.\n"
            "    '''\n"
            "    pass\n"
        )
        findings = _run(src, CassandraInQueryRule())
        assert findings == []

    def test_module_level_informal_docstring_not_flagged(self):
        # Regression: cassandra/query.py has a module-level string after ValueSequence
        # assignment that documents CQL IN usage. Must not be flagged.
        src = (
            "ValueSequence = encoder.ValueSequence\n"
            '"""\n'
            "A wrapper class for CQL list values.\n"
            "Example: SELECT * FROM users WHERE user_id IN %s\n"
            '"""\n'
        )
        findings = _run(src, CassandraInQueryRule())
        assert findings == []

    def test_single_sql_keyword_not_flagged(self):
        # Regression: English prose with one SQL word (table/into/from) and an
        # incidental IN+%s pattern. Requires 2 DISTINCT SQL keywords.
        for s in [
            "Could not find object %s in %s.\nPlease move into the main module.",
            "Could not find manager %s in %s.\nPlease inherit from managers.",
            "The row in table '%s' with primary key '%s' has invalid: %s in %s.",
        ]:
            findings = _run(f"x = {repr(s)}", CassandraInQueryRule())
            # These are string assignments (ast.Assign), not standalone expressions,
            # so they bypass the module-level docstring exclusion.
            # They should NOT be flagged because they have only 1 SQL keyword.
            assert findings == [], f"Should not flag: {repr(s[:60])}"

    def test_two_sql_keywords_flagged(self):
        # A string with SELECT+FROM (2 keywords) and IN %s → flagged correctly.
        src = "q = 'SELECT id FROM t WHERE id IN %s'\n"
        findings = _run(src, CassandraInQueryRule())
        assert len(findings) == 1


# ── PKN013: cassandra-batch-in-loop ──────────────────────────────────────────

class TestCassandraBatchLoop:
    def test_batch_add_in_loop_flagged(self):
        src = (
            "batch = BatchStatement()\n"
            "for row in rows:\n"
            "    batch.add(insert_stmt, (row.id, row.data))\n"
        )
        findings = _run(src, CassandraBatchLoopRule())
        assert len(findings) == 1
        assert findings[0].rule_id == "PKN013"

    def test_batch_add_outside_loop_not_flagged(self):
        src = "batch.add(stmt, params)\n"
        findings = _run(src, CassandraBatchLoopRule())
        assert findings == []

    def test_other_add_method_not_flagged(self):
        src = "for item in items:\n    my_list.add(item)\n"
        findings = _run(src, CassandraBatchLoopRule())
        assert findings == []

    def test_receiver_with_batch_in_name_flagged(self):
        src = "for row in rows:\n    write_batch.add(stmt, params)\n"
        findings = _run(src, CassandraBatchLoopRule())
        assert len(findings) == 1

    def test_receiver_without_batch_not_flagged(self):
        src = "for row in rows:\n    collection.add(row)\n"
        findings = _run(src, CassandraBatchLoopRule())
        assert findings == []

    def test_unlogged_batch_flagged_as_warning(self):
        # UNLOGGED batches in loops → WARNING severity (strict anti-pattern).
        src = (
            "batch = BatchStatement(batch_type=BatchType.UNLOGGED)\n"
            "for row in rows:\n"
            "    batch.add(insert_stmt, (row.id,))\n"
        )
        findings = _run(src, CassandraBatchLoopRule())
        assert len(findings) == 1
        from pyperfguard.core.severity import Severity
        assert findings[0].severity == Severity.WARNING

    def test_logged_batch_flagged_as_info(self):
        # LOGGED batches in loops → INFO severity (may be intentional for atomicity).
        src = (
            "batch = BatchStatement(batch_type=BatchType.LOGGED)\n"
            "for row in rows:\n"
            "    batch.add(insert_stmt, (row.id,))\n"
        )
        findings = _run(src, CassandraBatchLoopRule())
        assert len(findings) == 1
        from pyperfguard.core.severity import Severity
        assert findings[0].severity == Severity.INFO

    def test_logged_batch_positional_arg_flagged_as_info(self):
        # LOGGED via positional: BatchStatement(BatchType.LOGGED)
        src = (
            "batch = BatchStatement(BatchType.LOGGED)\n"
            "for row in rows:\n"
            "    batch.add(insert_stmt, (row.id,))\n"
        )
        findings = _run(src, CassandraBatchLoopRule())
        assert len(findings) == 1
        from pyperfguard.core.severity import Severity
        assert findings[0].severity == Severity.INFO

    def test_unknown_batch_type_flagged_as_warning(self):
        # No BatchStatement creation found → default WARNING.
        src = (
            "for row in rows:\n"
            "    batch.add(insert_stmt, (row.id,))\n"
        )
        findings = _run(src, CassandraBatchLoopRule())
        assert len(findings) == 1
        from pyperfguard.core.severity import Severity
        assert findings[0].severity == Severity.WARNING
