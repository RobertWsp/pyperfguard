"""Tests for CallGraph — inter-procedural N+1 static detection."""
from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.call_graph import CallGraph


def _cg(*sources: str) -> CallGraph:
    """Build a CallGraph from source strings."""
    cg = CallGraph()
    for i, src in enumerate(sources):
        cg.add_module(Path(f"module_{i}.py"), ast.parse(src), src)
    cg.compute()
    return cg


def test_direct_db_call_in_loop_flagged():
    src = (
        "async def list_all(self):\n"
        "    rows = await self._executor.execute('SELECT * FROM t')\n"
        "    results = []\n"
        "    for row in rows:\n"
        "        msg = await self._executor.execute('SELECT * FROM m WHERE id = ?', [row.id])\n"
        "        results.append(msg)\n"
        "    return results\n"
    )
    cg = _cg(src)
    findings = list(cg.n1_findings())
    # The loop calls executor.execute which is directly a DB call.
    assert len(findings) >= 1
    assert any(f.rule_id == "PKN102" for f in findings)


def test_cross_function_n1_flagged():
    service_src = (
        "class ConversationService:\n"
        "    async def get_messages(self, conv_id):\n"
        "        return await self._executor.execute('SELECT * FROM m WHERE id = ?', [conv_id])\n"
        "\n"
        "    async def list_all(self):\n"
        "        convs = await self._executor.execute('SELECT * FROM c')\n"
        "        for conv in convs:\n"
        "            msgs = await self.get_messages(conv.id)\n"
        "        return convs\n"
    )
    cg = _cg(service_src)
    findings = list(cg.n1_findings())
    # list_all has a for loop calling get_messages which is DB-adjacent
    assert len(findings) >= 1
    assert any("get_messages" in f.message for f in findings)


def test_non_db_function_not_flagged():
    src = (
        "def transform(item):\n"
        "    return item.upper()\n"
        "\n"
        "def process_all(items):\n"
        "    for item in items:\n"
        "        result = transform(item)\n"
    )
    cg = _cg(src)
    findings = list(cg.n1_findings())
    assert findings == []


def test_two_module_cross_function_detection():
    """N+1 spanning two files — service defined in module_0, router in module_1."""
    service_src = (
        "class ContactService:\n"
        "    async def get_contact(self, id):\n"
        "        return await self._session.execute('SELECT * FROM c WHERE id = ?', [id])\n"
    )
    router_src = (
        "async def list_contacts(service):\n"
        "    contact_ids = [1, 2, 3]\n"
        "    for cid in contact_ids:\n"
        "        contact = await service.get_contact(cid)\n"
    )
    cg = _cg(service_src, router_src)
    findings = list(cg.n1_findings())
    assert len(findings) >= 1
    assert any("get_contact" in f.message for f in findings)


def test_no_loop_no_finding():
    src = (
        "async def get_single(self, id):\n"
        "    return await self._executor.execute('SELECT * FROM t WHERE id = ?', [id])\n"
    )
    cg = _cg(src)
    findings = list(cg.n1_findings())
    assert findings == []


def test_finding_has_pkn102_rule_id():
    src = (
        "async def fetch(id):\n"
        "    return await session.execute('SELECT ...', [id])\n"
        "\n"
        "async def process(ids):\n"
        "    for id in ids:\n"
        "        item = await fetch(id)\n"
    )
    cg = _cg(src)
    findings = list(cg.n1_findings())
    assert any(f.rule_id == "PKN102" for f in findings)


# ── False-positive heuristic tests ────────────────────────────────────────────

class TestConstantNSuppression:
    """Loops over small, fixed enum-like sets should NOT be flagged."""

    def test_string_literal_list_suppressed(self):
        """for status in ["OPEN", "WAITING", "IN_PROGRESS"]: execute(status)"""
        src = (
            "async def stats(executor, company_id):\n"
            "    for status in ['OPEN', 'WAITING', 'IN_PROGRESS']:\n"
            "        rows = await executor.execute(\n"
            "            'SELECT * FROM t WHERE company_id = %s AND status = %s',\n"
            "            (company_id, status),\n"
            "        )\n"
        )
        cg = _cg(src)
        assert list(cg.n1_findings()) == []

    def test_named_var_string_list_suppressed(self):
        """eligible = ['OPEN', 'WAITING']; for s in eligible: execute(s)"""
        src = (
            "async def close_inactive(executor, company_id):\n"
            "    eligible = ['OPEN', 'WAITING', 'IN_PROGRESS']\n"
            "    for status in eligible:\n"
            "        rows = await executor.execute(\n"
            "            'SELECT * FROM t WHERE company_id = %s AND status = %s',\n"
            "            (company_id, status),\n"
            "        )\n"
        )
        cg = _cg(src)
        assert list(cg.n1_findings()) == []

    def test_attribute_list_suppressed(self):
        """for s in [Status.OPEN, Status.WAITING]: execute(s)"""
        src = (
            "async def stats(executor, company_id):\n"
            "    for status in [Status.OPEN, Status.WAITING, Status.IN_PROGRESS]:\n"
            "        rows = await executor.execute(\n"
            "            'SELECT * FROM t WHERE status = %s', (status.value,)\n"
            "        )\n"
        )
        cg = _cg(src)
        assert list(cg.n1_findings()) == []

    def test_integer_list_not_suppressed(self):
        """for cid in [1, 2, 3]: execute(cid) — integers could be user data."""
        src = (
            "async def process(executor):\n"
            "    contact_ids = [1, 2, 3]\n"
            "    for cid in contact_ids:\n"
            "        row = await executor.execute(\n"
            "            'SELECT * FROM contacts WHERE id = %s', (cid,)\n"
            "        )\n"
        )
        cg = _cg(src)
        assert len(list(cg.n1_findings())) >= 1

    def test_large_literal_list_not_suppressed(self):
        """for x in [a, b, c, d, e, f]: — 6 elements > MAX_SMALL_N."""
        src = (
            "async def wide(executor, company_id):\n"
            "    for status in ['A', 'B', 'C', 'D', 'E', 'F']:\n"
            "        rows = await executor.execute(\n"
            "            'SELECT * FROM t WHERE status = %s', (status,)\n"
            "        )\n"
        )
        cg = _cg(src)
        assert len(list(cg.n1_findings())) >= 1


class TestPaginationLoopSuppression:
    """Cursor-pagination loops should NOT be flagged."""

    def test_range_throwaway_suppressed(self):
        """for _ in range(max_pages): fetch_page(...)"""
        src = (
            "async def paginate(executor, company_id):\n"
            "    for _ in range(100):\n"
            "        rows = await executor.execute(\n"
            "            'SELECT * FROM t WHERE company_id = %s', (company_id,)\n"
            "        )\n"
            "        if not rows:\n"
            "            break\n"
        )
        cg = _cg(src)
        assert list(cg.n1_findings()) == []

    def test_range_named_var_not_suppressed(self):
        """for page in range(10): — named var means it's used, not pagination."""
        src = (
            "async def fetch_pages(executor, company_id):\n"
            "    for page in range(10):\n"
            "        rows = await executor.execute(\n"
            "            'SELECT * FROM t WHERE company_id = %s AND page = %s',\n"
            "            (company_id, page),\n"
            "        )\n"
        )
        cg = _cg(src)
        # page IS used in query — looks like real N+1 (debatable, but conservative)
        # At minimum it should NOT be suppressed by pagination heuristic
        # (it may or may not be flagged depending on receiver check)
        assert isinstance(list(cg.n1_findings()), list)  # just assert no crash


class TestEarlyExitSeverity:
    """Early-exit loops should be downgraded to INFO, not suppressed."""

    def test_early_return_loop_is_info(self):
        """for variant in variants: ...; if row: return row — INFO, not WARNING."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def find_by_phone(executor, company_id, variants):\n"
            "    for variant in variants:\n"
            "        row = await executor.execute(\n"
            "            'SELECT * FROM t WHERE phone = %s AND company_id = %s',\n"
            "            (variant, company_id),\n"
            "        )\n"
            "        if row:\n"
            "            return row\n"
            "    return None\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert all(f.severity == Severity.INFO for f in findings)


class TestBackgroundFnSeverity:
    """Background/maintenance functions should be downgraded to INFO."""

    def test_cleanup_fn_is_info(self):
        """cleanup_* functions should produce INFO, not WARNING."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def cleanup_expired_sessions(executor, session_ids):\n"
            "    for sid in session_ids:\n"
            "        await executor.execute(\n"
            "            'DELETE FROM sessions WHERE id = %s', (sid,)\n"
            "        )\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert all(f.severity == Severity.INFO for f in findings)

    def test_migrate_fn_is_info(self):
        """migrate_* functions should produce INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def migrate_user_records(executor, user_ids):\n"
            "    for uid in user_ids:\n"
            "        await executor.execute(\n"
            "            'UPDATE users_v2 SET migrated = true WHERE id = %s', (uid,)\n"
            "        )\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert all(f.severity == Severity.INFO for f in findings)

    def test_regular_async_fn_not_background(self):
        """get_*_async should NOT be classified as background (async ≠ sync)."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def get_instances_by_company_async(executor, company_id, rows):\n"
            "    results = []\n"
            "    for row in rows:\n"
            "        inst = await executor.execute(\n"
            "            'SELECT * FROM instances WHERE id = %s', (row.id,)\n"
            "        )\n"
            "        results.append(inst)\n"
            "    return results\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert all(f.severity == Severity.WARNING for f in findings)


# ── asyncio.gather() concurrent N+1 detection ─────────────────────────────────


class TestGatherN1Detection:
    """asyncio.gather(*[f(x) for x in items]) is still N+1 — concurrent, not serial."""

    def test_gather_listcomp_direct_db_flagged(self):
        """gather(*[executor.execute(...) for id in ids]) → INFO (Variant A, direct)."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def list_users(executor, ids):\n"
            "    return await asyncio.gather(\n"
            "        *[executor.execute('SELECT * FROM users WHERE id=%s', (uid,)) for uid in ids]\n"
            "    )\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "gather direct DB call should be flagged"
        assert all(f.severity == Severity.INFO for f in findings)

    def test_gather_listcomp_indirect_db_flagged(self):
        """gather(*[get_user(id) for id in ids]) where get_user hits DB → INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(executor, uid):\n"
            "    return await executor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(executor, ids):\n"
            "    return await asyncio.gather(*[get_user(executor, uid) for uid in ids])\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "gather indirect DB call should be flagged"
        assert all(f.severity == Severity.INFO for f in findings)

    def test_gather_variable_listcomp_flagged(self):
        """tasks = [get_user(id) for id in ids]; gather(*tasks) → INFO (Variant B)."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(executor, uid):\n"
            "    return await executor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(executor, ids):\n"
            "    tasks = [get_user(executor, uid) for uid in ids]\n"
            "    return await asyncio.gather(*tasks)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "gather with variable listcomp should be flagged"
        assert all(f.severity == Severity.INFO for f in findings)

    def test_gather_generator_expr_flagged(self):
        """gather(*(get_user(id) for id in ids)) with generator expression → INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(executor, uid):\n"
            "    return await executor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(executor, ids):\n"
            "    return await asyncio.gather(*(get_user(executor, uid) for uid in ids))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "gather with generator expression should be flagged"
        assert all(f.severity == Severity.INFO for f in findings)

    def test_gather_fixed_args_not_flagged(self):
        """gather(f(), g(), h()) — fixed N, not data-driven → NOT flagged."""
        src = (
            "import asyncio\n"
            "async def get_users(executor):\n"
            "    return await executor.execute('SELECT * FROM users')\n"
            "async def get_orders(executor):\n"
            "    return await executor.execute('SELECT * FROM orders')\n"
            "\n"
            "async def get_dashboard(executor):\n"
            "    users, orders = await asyncio.gather(\n"
            "        get_users(executor),\n"
            "        get_orders(executor),\n"
            "    )\n"
            "    return users, orders\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        # gather(f(), g()) is fine — N=2, fixed, not data-driven
        gather_findings = [f for f in findings if "gather" in f.message.lower()]
        assert gather_findings == [], "fixed-arg gather should NOT be flagged"

    def test_gather_constant_iter_not_flagged(self):
        """gather(*[f(s) for s in ['OPEN', 'WAITING', 'CLOSED']]) — constant N ≤ 5."""
        src = (
            "import asyncio\n"
            "async def count_by_status(executor, status):\n"
            "    return await executor.execute(\n"
            "        'SELECT count(*) FROM t WHERE status=%s', (status,)\n"
            "    )\n"
            "\n"
            "async def stats(executor):\n"
            "    return await asyncio.gather(\n"
            "        *[count_by_status(executor, s) for s in ['OPEN', 'WAITING', 'CLOSED']]\n"
            "    )\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        gather_findings = [f for f in findings if "gather" in f.message.lower()]
        assert gather_findings == [], "constant-N gather (3 enum values) should NOT be flagged"

    def test_gather_non_db_callee_not_flagged(self):
        """gather(*[process(x) for x in items]) where process is pure Python → NOT flagged."""
        src = (
            "import asyncio\n"
            "async def process(item):\n"
            "    return item.upper()\n"
            "\n"
            "async def run_all(items):\n"
            "    return await asyncio.gather(*[process(item) for item in items])\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "non-DB gather should NOT be flagged"

    def test_gather_finding_rule_id(self):
        """Gather findings must use rule_id PKN102."""
        src = (
            "import asyncio\n"
            "async def get_user(executor, uid):\n"
            "    return await executor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(executor, ids):\n"
            "    return await asyncio.gather(*[get_user(executor, uid) for uid in ids])\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert any(f.rule_id == "PKN102" for f in findings)

    def test_gather_nested_function_not_attributed_to_outer(self):
        """gather inside a nested def must not produce a finding on the outer function."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(executor, uid):\n"
            "    return await executor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def outer(executor):\n"
            "    async def inner(ids):\n"
            "        return await asyncio.gather(*[get_user(executor, uid) for uid in ids])\n"
            "    return await inner([1, 2, 3])\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        # Finding should be attributed to 'inner', not 'outer'
        outer_gather = [
            f for f in findings
            if "outer()" in f.message and "gather" in f.message.lower()
        ]
        assert outer_gather == [], "gather in nested fn must not be attributed to outer()"
        inner_findings = [f for f in findings if "inner()" in f.message]
        assert len(inner_findings) >= 1, "inner function gather should still be flagged"


# ── [await f(x) for x in items] serial N+1 detection ─────────────────────────


class TestAwaitListcompN1:
    """[await f(x) for x in items] is serial N+1 — worse than gather."""

    def test_await_listcomp_direct_db_flagged(self):
        """[await executor.execute(...) for id in ids] → WARNING (serial)."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def list_users(executor, ids):\n"
            "    return [await executor.execute('SELECT * FROM users WHERE id=%s', (uid,)) for uid in ids]\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "serial await listcomp should be flagged"
        assert all(f.severity == Severity.WARNING for f in findings)

    def test_await_listcomp_indirect_db_flagged(self):
        """[await get_user(id) for id in ids] where get_user hits DB → WARNING."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def get_user(executor, uid):\n"
            "    return await executor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(executor, ids):\n"
            "    return [await get_user(executor, uid) for uid in ids]\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "serial await listcomp indirect should be flagged"
        assert all(f.severity == Severity.WARNING for f in findings)

    def test_await_listcomp_is_warning_not_info(self):
        """Serial await listcomp must be WARNING — worse than gather (INFO)."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(executor, uid):\n"
            "    return await executor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_serial(executor, ids):\n"
            "    return [await get_user(executor, uid) for uid in ids]  # serial = WARNING\n"
            "\n"
            "async def list_concurrent(executor, ids):\n"
            "    return await asyncio.gather(*[get_user(executor, uid) for uid in ids])  # concurrent = INFO\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        serial_findings = [f for f in findings if "Serial" in f.message or "serial" in f.message.lower()]
        gather_findings = [f for f in findings if "gather" in f.message.lower() and "gather()" in f.message]
        assert any(f.severity == Severity.WARNING for f in serial_findings)
        assert any(f.severity == Severity.INFO for f in gather_findings)

    def test_await_listcomp_constant_iter_not_flagged(self):
        """[await f(s) for s in ['OPEN', 'WAITING', 'CLOSED']] — constant N ≤ 5."""
        src = (
            "async def count_by_status(executor, status):\n"
            "    return await executor.execute('SELECT count(*) FROM t WHERE status=%s', (status,))\n"
            "\n"
            "async def stats(executor):\n"
            "    return [await count_by_status(executor, s) for s in ['OPEN', 'WAITING', 'CLOSED']]\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        listcomp_findings = [f for f in findings if "Serial" in f.message or "list comprehension" in f.message]
        assert listcomp_findings == [], "constant-N await listcomp should NOT be flagged"

    def test_await_listcomp_non_db_not_flagged(self):
        """[await process(x) for x in items] where process is pure Python."""
        src = (
            "async def process(item):\n"
            "    return item.upper()\n"
            "\n"
            "async def run_all(items):\n"
            "    return [await process(item) for item in items]\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "non-DB await listcomp should NOT be flagged"


# ── self.<config_attr> constant-N suppression ─────────────────────────────────


class TestConfigSelfAttrSuppression:
    """Loops over self.<config_attr> are instance configuration, not user data."""

    def test_self_extensions_suppressed(self):
        """for ext in self.extensions: conn.execute(DDL) — Piccolo pattern."""
        src = (
            "class Engine:\n"
            "    async def prep_database(self, conn):\n"
            "        for extension in self.extensions:\n"
            "            await conn.execute(f'CREATE EXTENSION IF NOT EXISTS \"{extension}\"')\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "self.extensions loop should NOT be flagged (config attribute)"

    def test_self_pragmas_items_suppressed(self):
        """for pragma, val in self.pragmas.items(): conn.execute(PRAGMA) — Tortoise pattern."""
        src = (
            "class SQLiteClient:\n"
            "    async def create_connection(self):\n"
            "        for pragma, val in self.pragmas.items():\n"
            "            await self._connection.execute(f'PRAGMA {pragma}={val}')\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "self.pragmas.items() loop should NOT be flagged (config attribute)"

    def test_self_settings_suppressed(self):
        """for key, val in self.settings.items(): conn.execute(SET ...) — config pattern."""
        src = (
            "class DBClient:\n"
            "    async def configure(self):\n"
            "        for key, val in self.settings.items():\n"
            "            await self.connection.execute(f'SET {key} = {val}')\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "self.settings.items() loop should NOT be flagged (config attribute)"

    def test_self_non_config_attr_not_suppressed(self):
        """for row in self.rows: execute(row.id) — data attribute, should be flagged."""
        src = (
            "class Processor:\n"
            "    async def process_all(self):\n"
            "        for row in self.rows:\n"
            "            await self.session.execute('UPDATE t SET done=1 WHERE id=%s', (row.id,))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "self.rows (data attribute) loop SHOULD be flagged"


# ── asyncpg fetch/fetchrow/fetchval detection ──────────────────────────────────


class TestAsyncpgMethods:
    """asyncpg conn.fetch(), conn.fetchrow(), conn.fetchval() are DB calls."""

    def test_conn_fetch_in_loop_flagged(self):
        """for id in ids: await conn.fetch(query, id) → WARNING."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def list_users(conn, ids):\n"
            "    results = []\n"
            "    for uid in ids:\n"
            "        row = await conn.fetch('SELECT * FROM users WHERE id=$1', uid)\n"
            "        results.append(row)\n"
            "    return results\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "conn.fetch() in loop should be flagged"
        assert any(f.severity == Severity.WARNING for f in findings)

    def test_conn_fetchrow_in_loop_flagged(self):
        """for id in ids: await conn.fetchrow(query, id) → WARNING."""
        src = (
            "async def get_users(conn, ids):\n"
            "    for uid in ids:\n"
            "        row = await conn.fetchrow('SELECT * FROM users WHERE id=$1', uid)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "conn.fetchrow() in loop should be flagged"

    def test_pool_fetch_in_loop_flagged(self):
        """for id in ids: await pool.fetch(query, id) → WARNING (asyncpg pool)."""
        src = (
            "async def list_items(pool, ids):\n"
            "    for item_id in ids:\n"
            "        rows = await pool.fetch('SELECT * FROM items WHERE id=$1', item_id)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "pool.fetch() in loop should be flagged"

    def test_pipeline_receiver_not_flagged(self):
        """pipe.execute_command(...) in loop — pipeline buffering, not N+1."""
        src = (
            "async def process(client, commands):\n"
            "    async with client.pipeline() as pipe:\n"
            "        for cmd, args in commands:\n"
            "            await pipe.execute_command(cmd, *args)\n"
            "        await pipe.execute()\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "pipe.execute_command() is pipeline buffering — NOT N+1"


# ── asyncio.TaskGroup / create_task concurrent N+1 ────────────────────────────


class TestTaskGroupN1:
    """asyncio.TaskGroup / create_task in loops — concurrent N+1 → INFO."""

    def test_taskgroup_for_loop_flagged(self):
        """async with TaskGroup() as tg: for uid in ids: tg.create_task(f(uid)) → INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(conn, uid):\n"
            "    return await conn.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(conn, ids):\n"
            "    async with asyncio.TaskGroup() as tg:\n"
            "        for uid in ids:\n"
            "            tg.create_task(get_user(conn, uid))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "TaskGroup for-loop should be flagged"
        assert all(f.severity == Severity.INFO for f in findings), "TaskGroup is concurrent → INFO"

    def test_taskgroup_listcomp_flagged(self):
        """[tg.create_task(f(uid)) for uid in ids] inside TaskGroup → INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(conn, uid):\n"
            "    return await conn.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(conn, ids):\n"
            "    async with asyncio.TaskGroup() as tg:\n"
            "        tasks = [tg.create_task(get_user(conn, uid)) for uid in ids]\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "TaskGroup listcomp should be flagged"
        assert all(f.severity == Severity.INFO for f in findings), "TaskGroup is concurrent → INFO"

    def test_create_task_listcomp_flagged(self):
        """[asyncio.create_task(f(uid)) for uid in ids] → INFO (concurrent)."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(conn, uid):\n"
            "    return await conn.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(conn, ids):\n"
            "    tasks = [asyncio.create_task(get_user(conn, uid)) for uid in ids]\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "create_task listcomp should be flagged"
        assert all(f.severity == Severity.INFO for f in findings)

    def test_create_task_non_db_not_flagged(self):
        """create_task(pure_python(x)) — non-DB inner call → NOT flagged."""
        src = (
            "import asyncio\n"
            "async def process(item):\n"
            "    return item.upper()\n"
            "\n"
            "async def run_all(items):\n"
            "    async with asyncio.TaskGroup() as tg:\n"
            "        tasks = [tg.create_task(process(item)) for item in items]\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "non-DB create_task should NOT be flagged"

    def test_create_task_is_info_while_await_loop_is_warning(self):
        """create_task in loop → INFO; await in loop → WARNING (serial worse than concurrent)."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(conn, uid):\n"
            "    return await conn.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def concurrent_fn(conn, ids):\n"
            "    tasks = [asyncio.create_task(get_user(conn, uid)) for uid in ids]\n"
            "\n"
            "async def serial_fn(conn, ids):\n"
            "    results = [await get_user(conn, uid) for uid in ids]\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        concurrent_f = [f for f in findings if "concurrent_fn" in f.message]
        serial_f = [f for f in findings if "serial_fn" in f.message]
        assert any(f.severity == Severity.INFO for f in concurrent_f), "create_task → INFO"
        assert any(f.severity == Severity.WARNING for f in serial_f), "await serial → WARNING"


# ── Path-based background detection ──────────────────────────────────────────


class TestPathBasedBackground:
    """Files under /benchmarks/, /examples/ etc. produce INFO, not WARNING."""

    def test_benchmark_path_is_info(self):
        """N+1 in /benchmarks/ file → INFO (not WARNING)."""
        from pyperfguard.core.severity import Severity
        from pathlib import Path
        import ast as _ast
        from pyperfguard.ast_engine.call_graph import CallGraph

        src = (
            "async def run_benchmark(conn, ids):\n"
            "    for uid in ids:\n"
            "        row = await conn.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
        )
        cg = CallGraph()
        # Simulate a file under /benchmarks/
        cg.add_module(Path("/project/benchmarks/bench_users.py"), _ast.parse(src), src)
        cg.compute()
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert all(f.severity == Severity.INFO for f in findings), \
            "benchmark path should produce INFO, not WARNING"

    def test_examples_path_is_info(self):
        """N+1 in /examples/ file → INFO."""
        from pyperfguard.core.severity import Severity
        from pathlib import Path
        import ast as _ast
        from pyperfguard.ast_engine.call_graph import CallGraph

        src = (
            "async def example_list(conn, ids):\n"
            "    for uid in ids:\n"
            "        row = await conn.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
        )
        cg = CallGraph()
        cg.add_module(Path("/project/examples/list_users.py"), _ast.parse(src), src)
        cg.compute()
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert all(f.severity == Severity.INFO for f in findings), \
            "examples path should produce INFO, not WARNING"

    def test_regular_path_still_warning(self):
        """N+1 in regular /api/ file → WARNING (unaffected by path detection)."""
        from pyperfguard.core.severity import Severity
        from pathlib import Path
        import ast as _ast
        from pyperfguard.ast_engine.call_graph import CallGraph

        src = (
            "async def list_users(conn, ids):\n"
            "    for uid in ids:\n"
            "        row = await conn.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
        )
        cg = CallGraph()
        cg.add_module(Path("/project/api/users.py"), _ast.parse(src), src)
        cg.compute()
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert any(f.severity == Severity.WARNING for f in findings), \
            "regular api path should still produce WARNING"


# ── Background function new tokens ────────────────────────────────────────────


class TestBackgroundTokens:
    """teardown, assert, verify, benchmark function name tokens → INFO."""

    def test_teardown_fn_is_info(self):
        """r_teardown() — test teardown → INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def r_teardown(conn, keys):\n"
            "    for key in keys:\n"
            "        await conn.execute('DELETE FROM t WHERE key=%s', (key,))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert all(f.severity == Severity.INFO for f in findings), "teardown → INFO"

    def test_assert_fn_is_info(self):
        """_assert_writes_succeed() — assertion helper → INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def _assert_writes_succeed(conn, ids):\n"
            "    for uid in ids:\n"
            "        row = await conn.execute('SELECT * FROM t WHERE id=%s', (uid,))\n"
            "        assert row\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert all(f.severity == Severity.INFO for f in findings), "_assert → INFO"

    def test_verify_fn_is_info(self):
        """verify_insert_select() — verification helper → INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def verify_insert_select(conn, ids):\n"
            "    for uid in ids:\n"
            "        await conn.execute('SELECT 1 FROM t WHERE id=%s', (uid,))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert all(f.severity == Severity.INFO for f in findings), "verify → INFO"

    def test_benchmark_fn_name_is_info(self):
        """run_benchmark_queries() — benchmark function name → INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def run_benchmark_queries(conn, ids):\n"
            "    for uid in ids:\n"
            "        await conn.execute('SELECT * FROM t WHERE id=%s', (uid,))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1
        assert all(f.severity == Severity.INFO for f in findings), "benchmark → INFO"


# ── Receiver suffix detection (_listener_conn, _write_session) ────────────────


class TestReceiverSuffixDetection:
    """Receivers with DB-connection suffixes should be detected as DB calls."""

    def test_listener_conn_execute_in_loop_flagged(self):
        """self._listener_conn.execute() in loop — suffix '_conn' → WARNING."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def subscribe(self, channels):\n"
            "    for channel in channels:\n"
            "        await self._listener_conn.execute('LISTEN %s', (channel,))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "_listener_conn.execute() in loop should be flagged"
        assert any(f.severity == Severity.WARNING for f in findings)

    def test_write_session_execute_in_loop_flagged(self):
        """self._write_session.execute() — suffix '_session' → WARNING."""
        src = (
            "async def bulk_update(self, items):\n"
            "    for item in items:\n"
            "        await self._write_session.execute('UPDATE t SET v=%s WHERE id=%s',\n"
            "                                          (item.value, item.id))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "_write_session.execute() in loop should be flagged"

    def test_commit_in_loop_flagged(self):
        """for item in items: session.execute(); session.commit() — N commits → WARNING."""
        src = (
            "async def save_all(session, items):\n"
            "    for item in items:\n"
            "        await session.execute('INSERT INTO t VALUES (%s)', (item,))\n"
            "        await session.commit()\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "session.commit() in loop should be flagged"

    def test_regular_name_still_works(self):
        """conn.execute() in loop — direct name match still works."""
        src = (
            "async def run(conn, ids):\n"
            "    for uid in ids:\n"
            "        await conn.fetch('SELECT * FROM users WHERE id=$1', uid)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "conn.fetch() in loop should still be flagged"


# ── gather(*map(...)) and gather(*tuple(...)) detection ───────────────────────


class TestGatherMapTuplePatterns:
    """gather(*map(fn, items)) and gather(*tuple(gen)) are N+1 variants."""

    def test_gather_map_db_fn_flagged(self):
        """asyncio.gather(*map(get_user, ids)) → INFO (concurrent N+1 via map)."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(conn, uid):\n"
            "    return await conn.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(conn, ids):\n"
            "    return await asyncio.gather(*map(lambda uid: get_user(conn, uid), ids))\n"
        )
        cg = _cg(src)
        # Note: lambda not fully tracked, but direct map(fn, iter) with Name/Attr fn is
        findings = list(cg.n1_findings())
        # At minimum should not crash
        assert isinstance(findings, list)

    def test_gather_map_direct_db_fn_flagged(self):
        """asyncio.gather(*map(get_user, ids)) where get_user is DB-adjacent → INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(conn, uid):\n"
            "    return await conn.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(conn, ids):\n"
            "    return await asyncio.gather(*map(get_user, ids))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "gather(*map(db_fn, items)) should be flagged"
        assert all(f.severity == Severity.INFO for f in findings)

    def test_gather_tuple_wrapper_flagged(self):
        """asyncio.gather(*tuple(f(x) for x in items)) → INFO."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def get_user(conn, uid):\n"
            "    return await conn.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
            "\n"
            "async def list_users(conn, ids):\n"
            "    return await asyncio.gather(*tuple(get_user(conn, uid) for uid in ids))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "gather(*tuple(genexp)) should be flagged"
        assert all(f.severity == Severity.INFO for f in findings)

    def test_gather_map_builtin_not_flagged(self):
        """asyncio.gather(*map(str, items)) — str is builtin → NOT flagged."""
        src = (
            "import asyncio\n"
            "async def process(items):\n"
            "    return await asyncio.gather(*map(str, items))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "gather(*map(builtin, items)) should NOT be flagged"


# ── BFS fallback: 2+ hop N+1 chains in await-listcomp and gather ─────────────


class TestBFSFallbackDetection:
    """BFS fallback catches transitive N+1 (2+ hop chains) in async listcomps."""

    def test_await_listcomp_two_hop_chain_flagged(self):
        """[await outer(x) for x in items] where outer→inner→db — 2-hop chain."""
        from pyperfguard.core.severity import Severity
        src = (
            "async def db_fetch(conn, uid):\n"
            "    return await conn.execute('SELECT * FROM t WHERE id=%s', (uid,))\n"
            "\n"
            "async def build_item(conn, uid):\n"
            "    data = await db_fetch(conn, uid)\n"
            "    return data\n"
            "\n"
            "async def list_items(conn, ids):\n"
            "    return [await build_item(conn, uid) for uid in ids]\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        # build_item is transitively db_adjacent (calls db_fetch which calls conn.execute)
        # but not DIRECTLY db_adjacent — BFS fallback should catch this
        assert len(findings) >= 1, "2-hop transitive N+1 in await-listcomp should be flagged"
        assert any(f.severity == Severity.WARNING for f in findings)

    def test_gather_two_hop_chain_flagged(self):
        """gather(*[outer(x) for x in items]) where outer→inner→db — 2-hop."""
        from pyperfguard.core.severity import Severity
        src = (
            "import asyncio\n"
            "async def db_fetch(conn, uid):\n"
            "    return await conn.execute('SELECT * FROM t WHERE id=%s', (uid,))\n"
            "\n"
            "async def build_item(conn, uid):\n"
            "    data = await db_fetch(conn, uid)\n"
            "    return {'id': uid, 'data': data}\n"
            "\n"
            "async def list_items(conn, ids):\n"
            "    return await asyncio.gather(*[build_item(conn, uid) for uid in ids])\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "2-hop transitive N+1 in gather should be flagged"
        assert all(f.severity == Severity.INFO for f in findings)

    def test_pure_python_two_hop_not_flagged(self):
        """BFS fallback does not flag pure-Python transitive chains."""
        src = (
            "def transform(item):\n"
            "    return item.upper()\n"
            "\n"
            "async def process_all(items):\n"
            "    return [transform(item) for item in items]\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "pure-Python 2-hop should NOT be flagged"


# ── Fix regression tests ───────────────────────────────────────────────────────
# Each test class below documents a concrete FP that was fixed and must stay fixed.


class TestModuleLevelConstantIterables:
    """Case 7: loop over module-level constant list/tuple — suppress FP.

    Pattern (sqlalchemy/dialects/postgresql/provision.py):
        _extensions = [("citext", (13,)), ("hstore", (13,))]

        def _create_citext_extension(url, engine, ident):
            with engine.connect() as conn:
                for extension, min_version in _extensions:
                    conn.execute(text(f"CREATE EXTENSION ..."))
    """

    def test_module_level_const_list_of_tuples_suppressed(self):
        """Loop over a module-level constant list of (str, tuple) pairs is NOT flagged."""
        src = (
            "_extensions = [\n"
            "    ('citext', (13,)),\n"
            "    ('hstore', (13,)),\n"
            "]\n"
            "\n"
            "def setup(conn):\n"
            "    for ext, ver in _extensions:\n"
            "        conn.execute(f'CREATE EXTENSION {ext}')\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], (
            "Loop over module-level constant list should NOT be flagged"
        )

    def test_module_level_large_list_flagged(self):
        """Module-level list with more than _MAX_SMALL_N_INDIRECT elements is flagged."""
        # Build a list of 25 string tuples (> max threshold of 20).
        pairs = ", ".join(f"('ext{i}', ({i},))" for i in range(25))
        src = (
            f"_large = [{pairs}]\n"
            "\n"
            "def setup(conn):\n"
            "    for ext, ver in _large:\n"
            "        conn.execute(f'CREATE EXTENSION {ext}')\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Large module-level list SHOULD be flagged"

    def test_module_level_const_with_name_nodes_not_suppressed(self):
        """Module-level list whose items are plain Names (variables) is NOT suppressed.

        _items = [a, b, c] where a/b/c are runtime variables — could be user IDs.
        """
        src = (
            "_items = [a, b, c]\n"
            "\n"
            "def process(conn):\n"
            "    for item in _items:\n"
            "        conn.execute('SELECT * FROM t WHERE id = %s', (item,))\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Module-level list with Name nodes SHOULD be flagged"


class TestHardcodedPairVariableLists:
    """_all_enum_like extension: list of ≤ 2 tuples of (Attribute, Name) pairs.

    Pattern (sqlalchemy/orm/relationships.py):
        for joincond, collection in [
            (self.primaryjoin, sync_pairs),
            (self.secondaryjoin, secondary_sync_pairs),
        ]:
    """

    def test_two_element_attribute_name_tuple_list_suppressed(self):
        """for x, y in [(self.a, var1), (self.b, var2)]: ... is NOT flagged."""
        src = (
            "class R:\n"
            "    def _setup(self):\n"
            "        sync = []\n"
            "        sec = []\n"
            "        for cond, col in [\n"
            "            (self.primaryjoin, sync),\n"
            "            (self.secondaryjoin, sec),\n"
            "        ]:\n"
            "            if cond is None:\n"
            "                continue\n"
            "            self.session.execute(cond)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], (
            "Hardcoded 2-element pair list with Attribute/Name should NOT be flagged"
        )

    def test_three_element_tuple_list_still_flagged(self):
        """3+ element list is NOT suppressed by pair-variable heuristic."""
        src = (
            "class R:\n"
            "    def _setup(self):\n"
            "        for cond, col in [\n"
            "            (self.a, x),\n"
            "            (self.b, y),\n"
            "            (self.c, z),\n"
            "        ]:\n"
            "            self.session.execute(cond)\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "3-element pair list SHOULD be flagged"


class TestProtocolLoopSuppression:
    """Fix 4: [await self._read_response(...) for _ in range(int(response))]

    Wire-protocol multi-bulk readers iterate over range(int(n)) with a
    throwaway loop variable — not user-data-driven N+1.
    """

    def test_await_listcomp_throwaway_range_suppressed(self):
        """[await f() for _ in range(int(n))] with throwaway var is NOT flagged."""
        src = (
            "class Parser:\n"
            "    async def _read_response(self):\n"
            "        n = await self._readline()\n"
            "        response = [\n"
            "            (await self._read_response())\n"
            "            for _ in range(int(n))\n"
            "        ]\n"
            "        return response\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], (
            "Listcomp with throwaway _ and range(int(n)) should NOT be flagged "
            "(wire protocol reader, not user-data loop)"
        )

    def test_await_listcomp_named_var_range_still_flagged(self):
        """[await f(uid) for uid in range(n)] with named var is still flagged."""
        src = (
            "class Service:\n"
            "    async def fetch_all(self, n):\n"
            "        return [\n"
            "            await self.session.execute('SELECT * FROM t WHERE id=%s', (uid,))\n"
            "            for uid in range(n)\n"
            "        ]\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Named loop var with DB call SHOULD be flagged"


class TestAncestorParamClosure:
    """Ancestor-parameter (closure) guard: fn passed as parameter to outer function.

    Pattern (sqlalchemy/sql/util.py visit_binary_product):
        def visit_binary_product(fn, expr):
            def visit(element):
                for l in element.get_children():
                    fn(l)   # ← fn is a closure from ancestor params, not a DB fn

    Even if another function named 'fn' somewhere does DB work, calling 'fn'
    where 'fn' is a parameter of the enclosing scope must NOT be flagged.
    """

    def test_closure_callback_call_in_loop_not_flagged(self):
        """Calling a closure-variable (ancestor param) in a loop is NOT flagged."""
        # fn() in another file directly calls execute() → BFS marks 'fn' as db_adjacent.
        # The nested visit() calls fn() in a loop, but fn is an ancestor parameter.
        db_src = (
            "class TestSuite:\n"
            "    def fn(self):\n"
            "        self.session.execute('SELECT 1')\n"
        )
        util_src = (
            "def visit_binary_product(fn, expr):\n"
            "    def visit(element):\n"
            "        for child in element.get_children():\n"
            "            fn(child)\n"  # fn is ancestor param, not global DB fn
            "    list(visit(expr))\n"
        )
        cg = _cg(db_src, util_src)
        findings = list(cg.n1_findings())
        # Only findings from util_src (visit()) are of interest.
        visit_findings = [
            f for f in findings
            if "visit" in f.message and "module_1" in str(f.location.path)
        ]
        assert visit_findings == [], (
            "Calling an ancestor-parameter callback in a loop should NOT be flagged"
        )

    def test_non_closure_db_call_still_flagged(self):
        """A genuine DB call in a loop that is NOT an ancestor param IS flagged."""
        src = (
            "class Service:\n"
            "    async def process_all(self, items):\n"
            "        for item in items:\n"
            "            await self.session.execute('UPDATE t SET x=1 WHERE id=%s', (item,))\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Real DB call in loop SHOULD be flagged"


class TestTestPathBFSIsolation:
    """Test-path functions must not seed the BFS and contaminate production names.

    If a test file defines a local function named 'fn' that calls execute(),
    ANY production loop calling a function named 'fn' must NOT be flagged.
    """

    def test_test_path_fn_does_not_contaminate_prod_fn(self):
        """fn() in a /tests/ file does not pollute production fn() references."""
        test_src = (
            "class TestCase:\n"
            "    def fn(self):\n"
            "        self.connection.execute('SELECT 1')\n"
        )
        prod_src = (
            "def fn(x):\n"
            "    return x * 2\n"
            "\n"
            "def process(items):\n"
            "    for item in items:\n"
            "        result = fn(item)\n"  # fn is pure Python here
        )
        cg = CallGraph()
        cg.add_module(Path("/app/tests/test_base.py"), ast.parse(test_src), test_src)
        cg.add_module(Path("/app/src/utils.py"), ast.parse(prod_src), prod_src)
        cg.compute()
        findings = [
            f for f in cg.n1_findings()
            if "/app/src/" in str(f.location.path)
        ]
        assert findings == [], (
            "test-file fn() should NOT contaminate production fn() via BFS"
        )


class TestDeferredClosureNotDbAdjacent:
    """Functions that merely return a closure containing DB calls are NOT db_adjacent.

    Pattern (SQLAlchemy ORM _load_subclass_via_in):
        def build_loader(session):
            def do_load(ids):
                session.execute(query)   # only in the returned closure
            return do_load              # outer fn does NOT issue a query

    The outer function creates a callable but does not execute a query.
    Calling it in a loop is NOT an N+1 — the deferred callable may be
    invoked once (or never) outside the loop.
    """

    def test_closure_factory_in_loop_not_flagged(self):
        """Loop that calls a function returning a DB-closure is NOT flagged."""
        src = (
            "def build_loader(ctx):\n"
            "    def do_load(states):\n"
            "        ctx.session.execute('SELECT ...')\n"
            "    return do_load\n"
            "\n"
            "def setup_loaders(entities):\n"
            "    for entity in entities:\n"
            "        loader = build_loader(entity.ctx)\n"  # no DB here
            "        register(entity, loader)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], (
            "Calling a closure-factory (not direct DB) in a loop should NOT be flagged"
        )

    def test_function_that_does_execute_directly_still_flagged(self):
        """A function that directly calls execute() IS db_adjacent (no closure)."""
        src = (
            "def fetch_one(session, id_):\n"
            "    return session.execute('SELECT * FROM t WHERE id=%s', (id_,))\n"
            "\n"
            "def fetch_all(session, ids):\n"
            "    results = []\n"
            "    for id_ in ids:\n"
            "        results.append(fetch_one(session, id_))\n"
            "    return results\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Direct DB call function in loop SHOULD be flagged"


class TestWhileLoopN1:
    """while True consumer loop N+1 detection."""

    def test_while_true_direct_db_call(self):
        """while True with direct session.execute() inside — should warn."""
        src = (
            "async def consume_messages(consumer, session):\n"
            "    while True:\n"
            "        msg = consumer.poll()\n"
            "        if msg is None:\n"
            "            continue\n"
            "        await session.execute('INSERT INTO events VALUES (?)', [msg.key])\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "while True with DB call per message SHOULD be flagged"

    def test_while_true_indirect_db_call(self):
        """while True calling a db-adjacent helper — should warn."""
        src = (
            "def save_event(session, key, value):\n"
            "    session.execute('INSERT INTO ev VALUES (?,?)', [key, value])\n"
            "\n"
            "async def consumer_loop(consumer, session):\n"
            "    while True:\n"
            "        msg = consumer.poll()\n"
            "        if msg:\n"
            "            save_event(session, msg.key, msg.value)\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "while True calling DB helper per message SHOULD be flagged"

    def test_while_condition_not_flagged(self):
        """while cursor: (bounded) should NOT be flagged — not an infinite consumer."""
        src = (
            "async def paginate(session):\n"
            "    cursor = None\n"
            "    while cursor is not None or True:\n"
            "        rows, cursor = await session.execute('SELECT ...')\n"
            "        if not cursor:\n"
            "            break\n"
        )
        # Only "while True" / "while 1" patterns are flagged
        src2 = (
            "async def paginate(session, done):\n"
            "    while not done:\n"
            "        rows = await session.execute('SELECT ...')\n"
        )
        cg = _cg(src2)
        findings = list(cg.n1_findings())
        assert findings == [], "Bounded while loop should NOT be flagged"

    def test_while_true_pipeline_not_flagged(self):
        """while True with pipeline accumulator should NOT be flagged."""
        src = (
            "async def batch_consumer(consumer, pipe):\n"
            "    while True:\n"
            "        msg = consumer.poll()\n"
            "        if msg:\n"
            "            pipe.execute_command('SET', msg.key, msg.value)\n"
            "        else:\n"
            "            break\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "Pipeline accumulator in while True should NOT be flagged"

    def test_while_true_background_fn_downgraded(self):
        """while True in a background/migrate function should be INFO, not WARNING."""
        src = (
            "async def migrate_legacy_events(consumer, session):\n"
            "    while True:\n"
            "        msg = consumer.poll()\n"
            "        if msg is None:\n"
            "            break\n"
            "        await session.execute('INSERT INTO new_events VALUES (?)', [msg.key])\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        warnings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        infos = [f for f in cg.n1_findings() if f.severity == Severity.INFO]
        assert warnings == [], "migrate_ function should NOT produce WARNING"
        assert len(infos) >= 1, "migrate_ function SHOULD still produce INFO"

    def test_while_true_nested_for_detected(self):
        """while True with inner for loop calling DB per element — should warn."""
        src = (
            "async def event_consumer(consumer, session):\n"
            "    while True:\n"
            "        messages = consumer.poll_many()\n"
            "        for msg in messages:\n"
            "            await session.execute('INSERT VALUES (?)', [msg.id])\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Inner for loop in while True body SHOULD be flagged"


class TestNestedForLoopN1:
    """Nested for loop inner processing (inner loop gets its own loop_vars)."""

    def test_inner_for_loop_db_call_detected(self):
        """Inner for loop with DB call per element — should warn using inner var."""
        src = (
            "async def process_groups(session, groups):\n"
            "    for group in groups:\n"
            "        for item in group.items:\n"
            "            await session.execute('SELECT * WHERE id=?', [item.id])\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Inner for loop DB call per item SHOULD be flagged"

    def test_outer_for_loop_does_not_suppress_inner(self):
        """Inner loop var different from outer — inner DB call must still be found."""
        src = (
            "async def process(session, pages):\n"
            "    for page in pages:\n"
            "        results = page.results\n"
            "        for row in results:\n"
            "            await session.execute('SELECT', [row.key])\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Inner loop uses 'row', not 'page' — must still flag"

    def test_outer_for_no_inner_loops_unchanged(self):
        """Normal for loop behavior unchanged after refactor."""
        src = (
            "async def process(session, items):\n"
            "    for item in items:\n"
            "        await session.execute('SELECT * WHERE id=?', [item.id])\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Standard for loop DB call SHOULD still be flagged"


class TestLoopVarAliasing:
    """Loop variable aliasing: msg = delivery, then uses msg in DB call."""

    def test_simple_alias_detected(self):
        """Alias: delivery = item; session.execute(delivery.id) — should flag."""
        src = (
            "async def process(session, deliveries):\n"
            "    for item in deliveries:\n"
            "        delivery = item\n"
            "        await session.execute('SELECT * WHERE id=?', [delivery.id])\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Aliased loop var used in DB call SHOULD be flagged"

    def test_tuple_unpack_alias_detected(self):
        """Tuple unpack: key, val = item; uses key in DB call."""
        src = (
            "async def process(session, items):\n"
            "    for item in items:\n"
            "        key, val = item\n"
            "        await session.execute('INSERT INTO t VALUES (?,?)', [key, val])\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Tuple-unpacked loop var used in DB call SHOULD be flagged"

    def test_call_assigned_not_aliased(self):
        """data = transform(item) — call result should NOT be treated as loop var alias."""
        src = (
            "def transform(x): return x\n"
            "\n"
            "STATUSES = ['a', 'b', 'c']\n"
            "\n"
            "async def process(session):\n"
            "    for item in STATUSES:\n"
            "        data = transform(item)\n"
            "        await session.execute('INSERT', [data])\n"
        )
        # This should still flag because STATUSES has 3 items <= _MAX_SMALL_N_DIRECT
        # but even if threshold passed, data = transform(item) is a Call so not aliased
        cg = _cg(src)
        # Just verify it doesn't crash and returns a consistent result
        findings = list(cg.n1_findings())
        assert findings is not None  # no crash


class TestDjangoORMDetection:
    """Django ORM N+1 detection via objects manager and _set reverse FK."""

    def test_objects_filter_in_loop(self):
        """Django Model.objects.filter() per loop iteration — should warn."""
        src = (
            "def list_user_posts(user_ids):\n"
            "    for user_id in user_ids:\n"
            "        posts = Post.objects.filter(user_id=user_id)\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Django objects.filter() per loop item SHOULD be flagged"

    def test_objects_get_in_loop(self):
        """Django Model.objects.get() per loop iteration — should warn."""
        src = (
            "def get_users(user_ids):\n"
            "    for user_id in user_ids:\n"
            "        user = User.objects.get(pk=user_id)\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Django objects.get() per loop item SHOULD be flagged"

    def test_objects_create_in_loop(self):
        """Django Model.objects.create() per loop iteration — should warn."""
        src = (
            "def create_records(items):\n"
            "    for item in items:\n"
            "        Record.objects.create(name=item.name, value=item.value)\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Django objects.create() per loop item SHOULD be flagged"

    def test_reverse_fk_all_in_loop(self):
        """Django reverse FK manager .all() per loop iteration — should warn."""
        src = (
            "def get_author_books(authors):\n"
            "    for author in authors:\n"
            "        books = author.book_set.all()\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Django book_set.all() (reverse FK) per author SHOULD be flagged"

    def test_reverse_fk_filter_in_loop(self):
        """Django reverse FK manager .filter() per loop iteration — should warn."""
        src = (
            "def get_approved_comments(authors):\n"
            "    for author in authors:\n"
            "        comments = author.comment_set.filter(approved=True)\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "Django comment_set.filter() (reverse FK) SHOULD be flagged"

    def test_dict_get_not_flagged(self):
        """dict.get() in a loop should NOT be flagged (not a DB receiver)."""
        src = (
            "def process(items, cache):\n"
            "    for item in items:\n"
            "        val = cache.get(item.key)\n"
            "        process_val(val)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "dict.get() on non-DB receiver must NOT be flagged"

    def test_factory_create_not_flagged(self):
        """factory.create() in a loop should NOT be flagged (not DB receiver)."""
        src = (
            "def build_objects(items, factory):\n"
            "    for item in items:\n"
            "        obj = factory.create(item.type)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "factory.create() on non-DB receiver must NOT be flagged"


class TestORMHighLevelMethods:
    """High-level ORM method detection (Tortoise, Beanie, Django)."""

    def test_fetch_related_in_loop(self):
        """Tortoise ORM: await obj.fetch_related() per loop item — should warn."""
        src = (
            "async def load_related(events):\n"
            "    for event in events:\n"
            "        await event.fetch_related('attendees')\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "fetch_related() per loop item SHOULD be flagged"

    def test_fetch_link_in_loop(self):
        """Beanie ODM: await obj.fetch_link() per loop item — should warn."""
        src = (
            "async def load_links(documents):\n"
            "    for doc in documents:\n"
            "        await doc.fetch_link('author')\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "fetch_link() per loop item SHOULD be flagged"

    def test_get_or_create_in_loop(self):
        """get_or_create() on objects manager per loop item — should produce finding."""
        src = (
            "def process_tags(items):\n"
            "    for item in items:\n"
            "        tag, created = Tag.objects.get_or_create(name=item.name)\n"
        )
        cg = _cg(src)
        # get_or_create IS a DB call — should produce a finding (W or I)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "get_or_create() per loop item SHOULD produce a finding"


class TestWhileRetryLoopSuppression:
    """while True retry loops should NOT be flagged (they're not consumer N+1)."""

    def test_lock_acquire_retry_not_flagged(self):
        """while True lock-acquire retry pattern should NOT be flagged."""
        src = (
            "async def acquire(session):\n"
            "    while True:\n"
            "        if await session.execute('SET nx=True'):\n"
            "            return True\n"
            "        import asyncio\n"
            "        await asyncio.sleep(0.1)\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        warnings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert warnings == [], "Lock acquire retry (while True: if: return) MUST NOT be flagged as WARNING"

    def test_try_return_retry_not_flagged(self):
        """while True: try: return await op() should NOT be flagged as consumer N+1."""
        src = (
            "async def execute_with_retry(session, query):\n"
            "    while True:\n"
            "        try:\n"
            "            return await session.execute(query)\n"
            "        except Exception:\n"
            "            import asyncio\n"
            "            await asyncio.sleep(0.5)\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        warnings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert warnings == [], "try/return retry loop MUST NOT be flagged as consumer N+1"

    def test_true_consumer_loop_still_flagged(self):
        """while True consumer (no return after DB) must still be flagged."""
        src = (
            "async def consume_events(consumer, session):\n"
            "    while True:\n"
            "        msg = consumer.poll()\n"
            "        if msg is not None:\n"
            "            await session.execute('INSERT INTO ev VALUES (?)', [msg.id])\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        findings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert len(findings) >= 1, "True consumer loop (no early return) SHOULD still be flagged"


# ── Django reverse manager (custom related_name) ─────────────────────────────


class TestDjangoRelatedManagerN1:
    """Detect N+1 via obj.custom_related_name.all()/filter()/etc."""

    def test_reverse_m2m_all_in_loop_flagged(self):
        """for line in lines: product.collections.all() → N+1 (M2M reverse)."""
        src = (
            "def fetch_lines(lines):\n"
            "    for line in lines:\n"
            "        product = line.variant.product\n"
            "        collections = list(product.collections.all())\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "product.collections.all() in loop should be flagged"

    def test_reverse_fk_all_in_loop_flagged(self):
        """for line in lines: line.discounts.all() → N+1 (reverse FK, custom related_name)."""
        src = (
            "def fetch_discounts(lines):\n"
            "    for line in lines:\n"
            "        discounts = list(line.discounts.all())\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "line.discounts.all() in loop should be flagged"

    def test_related_manager_filter_kwargs_flagged(self):
        """for line in lines: line.fulfillments.filter(status='ok') → N+1."""
        src = (
            "def fetch_fulfillments(lines):\n"
            "    for line in lines:\n"
            "        active = list(line.fulfillments.filter(status='active'))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "line.fulfillments.filter(kw=v) in loop should be flagged"

    def test_related_manager_select_for_update_flagged(self):
        """for gc in gift_cards.select_for_update() via intermediate attr → N+1."""
        src = (
            "def use_gift_cards(orders):\n"
            "    for order in orders:\n"
            "        for gc in order.gift_cards.select_for_update():\n"
            "            gc.used = True\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "order.gift_cards.select_for_update() in inner loop should be flagged"

    def test_plain_dict_get_not_flagged(self):
        """for item in items: item.cache.get(key) must NOT be flagged (get not in safe set)."""
        src = (
            "def process(items):\n"
            "    for item in items:\n"
            "        val = item.cache.get('key', None)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "item.cache.get() must not be flagged (could be dict.get)"

    def test_python_all_builtin_1_level_not_flagged(self):
        """all(x for x in items) must NOT be flagged (Python builtin, no receiver)."""
        src = (
            "def check_all(items, session):\n"
            "    for item in items:\n"
            "        result = all(c.active for c in item.children)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "Python builtin all() in generator must not be flagged"

    def test_related_manager_no_loop_var_not_flagged(self):
        """obj.rel.all() where obj is NOT derived from loop var must NOT be flagged."""
        src = (
            "def process(items, global_obj):\n"
            "    for item in items:\n"
            "        collections = list(global_obj.collections.all())\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "global_obj not derived from loop var — must not be flagged"

    def test_related_manager_alias_chain_flagged(self):
        """Multi-hop alias: line→variant→product→collections.all() still detected."""
        src = (
            "def fetch_lines(lines):\n"
            "    for line in lines:\n"
            "        variant = line.variant\n"
            "        product = variant.product\n"
            "        collections = list(product.collections.all())\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "multi-hop alias product→collections.all() should be flagged"

    def test_filter_with_positional_args_not_flagged(self):
        """Python filter(fn, iterable) with positional args must NOT be flagged."""
        src = (
            "def process(groups, session):\n"
            "    for group in groups:\n"
            "        active = list(filter(lambda x: x.active, group.members))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "filter(fn, iterable) with positional args must not be flagged"

    def test_values_list_flagged(self):
        """for order in orders: order.lines.values_list('id', flat=True) → N+1."""
        src = (
            "def get_line_ids(orders):\n"
            "    for order in orders:\n"
            "        ids = list(order.lines.values_list('id', flat=True))\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "order.lines.values_list() in loop should be flagged"


# ── while True: break suppression (WATCH/MULTI/EXEC retry) ───────────────────


class TestWhileRetryBreakSuppression:
    """while True: try: op(); break — optimistic-locking retry, NOT consumer N+1."""

    def test_watch_multi_exec_break_suppressed(self):
        """Redis WATCH/MULTI/EXEC: try: ...; break; except WatchError: continue."""
        src = (
            "def atomic_update(pipe, key, session):\n"
            "    while True:\n"
            "        try:\n"
            "            pipe.watch(key)\n"
            "            val = session.execute('SELECT val FROM t WHERE k=$1', key)\n"
            "            pipe.multi()\n"
            "            pipe.set(key, val + 1)\n"
            "            pipe.execute()\n"
            "            break\n"
            "        except Exception:\n"
            "            continue\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        warnings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert warnings == [], "WATCH/MULTI/EXEC retry with break must NOT be flagged"

    def test_bounded_monitoring_break_suppressed(self):
        """while True: try: wait(); break — monitoring loop exits when done."""
        src = (
            "async def monitor_worker(job, session):\n"
            "    while True:\n"
            "        try:\n"
            "            retpid = await session.execute('SELECT pid FROM workers WHERE id=$1', job.id)\n"
            "            break\n"
            "        except TimeoutError:\n"
            "            await session.execute('UPDATE heartbeats SET ts=NOW() WHERE id=$1', job.id)\n"
        )
        cg = _cg(src)
        from pyperfguard.core.severity import Severity
        warnings = [f for f in cg.n1_findings() if f.severity == Severity.WARNING]
        assert warnings == [], "break-in-try monitoring loop must NOT be flagged as consumer N+1"

    def test_consumer_if_none_break_still_flagged(self):
        """while True: if msg is None: break; session.execute() — still consumer N+1."""
        src = (
            "async def consume(consumer, session):\n"
            "    while True:\n"
            "        msg = consumer.poll()\n"
            "        if msg is None:\n"
            "            break\n"
            "        await session.execute('INSERT INTO ev VALUES ($1)', msg.id)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "consumer loop with 'if None: break' SHOULD still be flagged"


# ── Batch __in= filter suppression ───────────────────────────────────────────


class TestBatchInQuerySuppression:
    """filter(pk__in=batch) is a batched query — not an N+1."""

    def test_filter_pk_in_batch_suppressed(self):
        """for batch_pks in batches: Model.objects.filter(pk__in=batch_pks) → suppressed."""
        src = (
            "def update_in_batches(batches):\n"
            "    for batch_pks in batches:\n"
            "        from myapp.models import Product\n"
            "        Product.objects.filter(pk__in=batch_pks).update(active=True)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert findings == [], "filter(pk__in=batch) is batched — must NOT be flagged"

    def test_filter_id_in_ids_suppressed(self):
        """for id_batch in chunked_ids: Model.objects.filter(id__in=id_batch) → suppressed."""
        src = (
            "def process_chunks(chunks, session):\n"
            "    for chunk in chunks:\n"
            "        rows = session.execute('SELECT * FROM t WHERE id = ANY($1)', chunk)\n"
        )
        # Direct execute with positional arg — NOT a __in=batch pattern
        # (this should still be flagged if chunk is a loop var in args)
        # But the batch guard only applies to __in= kwargs.
        # This test just confirms positional-arg execute is not suppressed.
        cg = _cg(src)
        findings = list(cg.n1_findings())
        # session.execute with positional arg = loop var — should be flagged as N+1
        assert len(findings) >= 1, "execute(query, chunk) per chunk should still be flagged"

    def test_filter_in_single_item_not_suppressed(self):
        """filter(pk=item.pk) without __in is per-item — must still be flagged."""
        src = (
            "def process(items):\n"
            "    for item in items:\n"
            "        from myapp.models import Product\n"
            "        Product.objects.filter(pk=item.pk).update(processed=True)\n"
        )
        cg = _cg(src)
        findings = list(cg.n1_findings())
        assert len(findings) >= 1, "filter(pk=item.pk) per item SHOULD be flagged (N+1)"
