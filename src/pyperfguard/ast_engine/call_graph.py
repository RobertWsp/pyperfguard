"""Inter-procedural call graph for cross-function N+1 static detection.

This module builds a call graph from a collection of Python AST modules and
uses it to find N+1 patterns that span function boundaries:

    # router.py
    @router.get("/conversations")
    async def list_conversations(service: ConversationServiceDep):
        return await service.list_all()   # no loop visible here

    # service.py
    class ConversationService:
        async def list_all(self):
            convs = await self._executor.execute("SELECT ...")
            for conv in convs:
                # N+1 here — only visible by following the call graph
                msgs = await self._executor.execute("SELECT ... WHERE id = ?", [conv.id])
            ...

The AST-level rule PKN008 (await_in_loop) already catches the loop+await
pattern *within* a single function. This module catches the case where the
loop is in the *caller* of a DB-accessing function.

Algorithm (3-pass):
1. **Collect**: Walk all modules, collect every function definition with its
   direct calls. Build ``fn_name → {called_fn_names}`` and
   ``fn_name → [loop_nodes_containing_calls]``.
2. **Mark DB functions**: A function is "DB-adjacent" if it directly calls a
   known DB access pattern (``executor.execute``, ``session.execute``, etc.)
   or calls another DB-adjacent function (transitive closure via BFS).
3. **Detect**: For every for-loop, check if any function call inside it is
   DB-adjacent. If so, emit a finding.

Limitations:
- Uses name-based call matching (no type inference). Will miss calls through
  aliased variables, dynamic dispatch, etc.
- `self.method()` calls are tracked by method name only (no class disambiguation).
- False positives possible when different classes have a method with the same
  name, one of which is DB-accessing.
"""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.severity import Severity

# Names that indicate a direct DB access call.
# IMPORTANT: Keep this list SPECIFIC — common names like "get", "set", "all",
# "first" cause massive false positives (dict.get, list operations, etc.).
_DB_CALL_PATTERNS: frozenset[str] = frozenset(
    {
        # Cassandra — very specific names
        "execute",         # session.execute() — requires receiver check
        "execute_async",   # session.execute_async()
        "prepare",         # session.prepare() — requires receiver check
        # SQLAlchemy — specific enough, always on a session/connection
        "scalar",
        "scalars",
        "fetchall",
        "fetchone",
        # PyMongo — specific, unlikely to collide
        "find_one",
        "insert_one",
        "insert_many",
        "update_one",
        "update_many",
        "delete_one",
        "delete_many",
        "bulk_write",
        # Redis — only pipeline is specific enough (get/set are too generic)
        "pipeline",
        "execute_command",
    }
)

# Receiver names / attribute chains that strongly indicate DB access.
# "cache" is intentionally excluded: a local dict named ``cache`` (common in
# helpers like ``_build_src_cache``) would be a false positive, and real cache
# clients are reached through more specific names like ``redis``, ``_redis``.
_DB_RECEIVER_HINTS: frozenset[str] = frozenset(
    {
        "executor",
        "session",
        "_executor",
        "_session",
        "db",
        "_db",
        "conn",
        "connection",
        "_connection",
        "redis",
        "_redis",
        "pool",        # asyncpg pool.fetch() / pool.execute()
        "_pool",
        # Django ORM: Model.objects.filter() — "objects" is the Manager attribute
        "objects",
    }
)

# Variable-name suffixes that indicate a DB receiver object.
# Catches patterns like ``_listener_conn``, ``_write_conn``,
# ``_query_connection``, ``_read_session``, ``_async_db`` — all naming
# conventions used in production code that are not covered by the exact-match
# set above.
_DB_RECEIVER_SUFFIXES: tuple[str, ...] = (
    "_conn", "_connection", "_session", "_executor", "_db", "_cursor",
)


def _is_db_receiver(name: str) -> bool:
    """True when the receiver name indicates a database-connection object.

    Checks both the exact ``_DB_RECEIVER_HINTS`` set and common naming
    suffixes so that patterns like ``self._listener_conn.execute()`` or
    ``self._write_session.scalar()`` are correctly recognised as DB calls.

    Also detects Django reverse FK managers (``comment_set``, ``author_set``)
    which end in ``_set`` per Django's naming convention.
    """
    if name in _DB_RECEIVER_HINTS:
        return True
    if name.endswith("_set") and len(name) > 4:
        return True
    return any(
        name.endswith(suffix) and len(name) > len(suffix)
        for suffix in _DB_RECEIVER_SUFFIXES
    )

# ── False-positive suppression heuristics ────────────────────────────────────

# Constant-N thresholds — applied differently for direct vs indirect DB calls.
#
# DIRECT calls (executor.execute inside the loop): we apply a SMALL threshold.
# A loop over ["OPEN", "WAITING", "CLOSED"] (3 items) is clearly enum-driven and
# safe to suppress.  But 6+ literals is large enough that we want to flag it.
#
# INDIRECT calls (loop calls a helper that itself does DB work): we apply a
# LARGER threshold because schema-init loops like ``ensure_columns()`` can iterate
# over 10–15 column definitions, all string constants, and are never user-driven.
_MAX_SMALL_N_DIRECT: int = 5
_MAX_SMALL_N_INDIRECT: int = 20

# Function name fragments (lowercased) that indicate background / maintenance
# operations.  These are expected to iterate over data row-by-row and are
# downgraded from WARNING to INFO, because their impact on end-user latency is
# typically zero (they run as offline jobs, not in the request path).
_BACKGROUND_FN_FRAGMENTS: frozenset[str] = frozenset(
    {
        "cleanup", "clean_up",
        "backfill", "back_fill",
        "migrate", "migration",
        "repair", "fix",
        "sync", "synchronize",
        "purge", "prune",
        "rebuild", "reindex",
        "reconcile",
        "archive",
        "batch",
        "reprocess",
        "populate",
        # Schema / DDL setup — runs at startup, never in the request path
        "ensure",       # ensure_columns, ensure_table — schema drift correction
        "schema",       # schema-related management functions
        "tables",       # create_tables, _init_tables, drop_tables — DDL management
        "drop",         # drop_views, drop_tables — DDL teardown
        "truncate",     # truncate_tables, truncate_all_models — DDL/test cleanup
        "invalidate",   # cache_invalidate_pattern — N Redis DELETEs is expected
        "provision",    # infrastructure provisioning
        "bootstrap",    # one-shot startup initialisation
        "seed",         # data seeding
        # Intentional bulk / batch operations — N I/Os by design, not accidental
        "bulk",         # bulk_create, bulk_update, bulk_import — batch semantics
        "many",         # execute_many, save_many, insert_many — batch semantics
        # Test, fixture, and assertion helpers — never in production request path
        "test",         # test_* / *_test functions in test suites
        "testing",      # _prep_testing_database, testing_* helpers
        "fixture",      # load_fixtures, setup_fixture — test data setup
        "teardown",     # test teardown helpers (r_teardown, teardown_db, ...)
        "assert",       # _assert_writes_succeed — test assertion helpers
        "verify",       # verify_insert_select, verify_schema — test verification
        "benchmark",    # benchmark_* / run_benchmark — perf measurement, not prod
        # Distributed system routing — per-shard/slot ops are protocol-required
        "shard",        # ssubscribe / per-shard routing — not user-data-driven
        "slot",         # _split_command_across_slots — cluster topology routing
        "nonatomic",    # mset_nonatomic — intentionally non-transactional multi-key
        "partition",    # _partition_keys_by_slot — key→slot partitioning
        "across",       # _split_command_across_slots — slot-partitioned fan-out
        # Startup / connection setup — runs once per process, not per request
        "bake",         # _bake() — GINO bakes prepared queries at connection time
        "mixin",        # _init_mixin() — connection/dialect initialisation mixin
        "check",        # check_connection() — health checks, validation on open
        "serve",        # serve() — startup server functions (CLI entrypoints)
        # Cluster / topology management — background infrastructure work
        "maintenance",  # handle_oss_maintenance_notification — cluster topology
        "reconnect",    # mark_for_reconnect — connection pool management
        "handoff",      # record_connection_handoff — cluster failover
        # Bulk / streaming data operations — intentional N I/Os, not accidental
        "chunk",        # insert_chunk(), process_chunk() — batch I/O by design
        "dump",         # iterdump(), export_dump() — serialisation to file/stream
        "refresh",      # _refresh_schemas(), refresh_cache() — background resync
        "convert",      # _convert_multi() — data type conversion (offline)
        "transform",    # transform() DDL table rebuild — SQLite/schema migration
        "analyze",      # analyze_column(), _analyze() — stats collection
        "export",       # export_archived_records() — data export operations
    }
)

# File-path fragments that indicate benchmark, example, or doctest code.
# When a finding's source file is under one of these paths, it is downgraded
# to INFO — the code is not production request-path code, so actual end-user
# latency impact is zero.
_BACKGROUND_PATH_FRAGMENTS: frozenset[str] = frozenset(
    {
        "/benchmarks/", "/benchmark/", "/bench/",
        "/examples/", "/example/",
        "/doctests/", "/doctest/",
        "/demos/", "/demo/",
        "/perf/", "/performance/", "/profiling/",
        "/load_test/", "/load_tests/",
        # Test directories — never production request-path code
        "/tests/", "/test/", "/testing/",
        # Common test config / support files
        "conftest.py",
        # Standalone example / demo / sample files (e.g. example_core.py)
        "example_", "demo_", "sample_",
        # Django database migrations — one-time data operations, not request-path
        "/migrations/",
    }
)

# Python built-in callable names that are *always* pure-Python when called as a
# bare function (``ast.Name`` node — no receiver).  These names are commonly
# shadowed by domain-specific methods in libraries (e.g. Redis has its own
# ``range()``, ``list()``, ``type()``, ``get()`` commands that call
# ``execute_command()``).  When the BFS marks those library functions as
# DB-adjacent, any use of the *actual* Python built-in with the same name in a
# loop would be a false positive.
#
# Guard: we only suppress when the call site is ``ast.Name`` (bare call, no
# receiver).  ``self.type()``, ``obj.get()``, etc. still go through the normal
# path so real method calls are not silenced.
_BUILTIN_BARE_CALL_NAMES: frozenset[str] = frozenset(
    {
        # type system / identity
        "type", "isinstance", "issubclass", "id", "hash",
        # containers
        "list", "dict", "set", "frozenset", "tuple",
        "range", "enumerate", "zip", "reversed", "sorted",
        "filter", "map", "iter", "next",
        # Boolean tests — "all" / "any" are Python builtins, never DB calls.
        # They must be guarded here because ORM libraries (Cassandra cqlengine,
        # Django) define Model.all() / Model.any() methods that call execute().
        # BFS propagates db_adjacent to the name "all", so bare all(generator)
        # in a loop would otherwise be falsely flagged as an indirect N+1.
        "all", "any",
        # arithmetic / numeric
        "len", "abs", "round", "min", "max", "sum", "pow",
        "int", "float", "bool", "str", "bytes", "bytearray",
        # I/O helpers — not DB
        "print", "repr", "vars", "dir",
        # conversion
        "ord", "chr", "hex", "oct", "bin",
    }
)

# Python built-in / stdlib method names that are NEVER database operations.
#
# When these appear as callees in an indirect check and the receiver does NOT
# look like a service or DB object, we suppress the finding.  This prevents
# false positives caused by name collisions between common Python method names
# (dict.get, set.update, list.add) and user-defined service methods that happen
# to share the same name and are DB-adjacent.
_PURE_PYTHON_METHODS: frozenset[str] = frozenset(
    {
        # dict / mapping
        "get", "set", "setdefault", "pop", "popitem", "update", "clear",
        "copy", "items", "keys", "values",
        # list
        "append", "extend", "insert", "remove", "reverse", "sort",
        "count", "index",
        # set
        "add", "discard", "issubset", "issuperset", "union",
        "intersection", "difference",
        # string
        "encode", "decode", "strip", "lstrip", "rstrip", "split", "rsplit",
        "join", "format", "replace", "startswith", "endswith",
        "upper", "lower", "isoformat", "fromisoformat",
        # Pydantic / dataclass serialisation — never network I/O
        "model_dump", "model_validate",
        # logging — never DB
        "warning", "info", "debug", "error", "critical", "warn", "log",
    }
)

# Receiver name substrings (lowercase) that indicate a service / repository.
# When the receiver contains one of these patterns we do NOT suppress a finding
# even if the callee is in _PURE_PYTHON_METHODS (e.g. service.update() is a
# real DB write, not a dict.update()).
_SERVICE_RECEIVER_PATTERNS: frozenset[str] = frozenset(
    {
        "service", "svc", "repo", "repository", "manager", "store",
        "client", "dao", "gateway", "adapter", "backend", "registry",
        "handler", "provider",
    }
)

# Receiver variable names that indicate a pipeline / batch accumulator.
# Calls on these objects buffer commands and execute them in a single round-
# trip outside the loop (Redis pipeline, Cassandra BatchStatement, etc.).
# Any method called on them is safe to suppress — the real I/O is the single
# execute() outside the loop.
_PIPELINE_RECEIVERS: frozenset[str] = frozenset(
    {
        "pipe", "pipeline",
        "batch", "batch_stmt",
        "tx", "multi", "transaction",
    }
)

# Instance attribute names that indicate per-class configuration rather than
# user-data collections.  Loops over ``self.<attr>`` or
# ``self.<attr>.items()`` with these names are provably not data-driven and
# must not be flagged as N+1.
#
# Examples:
#   for ext in self.extensions: conn.execute(CREATE EXTENSION ...)  ← Piccolo
#   for pragma, val in self.pragmas.items(): conn.execute(PRAGMA)   ← Tortoise
_CONFIG_SELF_ATTRS: frozenset[str] = frozenset(
    {
        "extensions", "pragmas", "settings", "config",
        "options", "params", "defaults",
        "backends", "plugins", "middleware", "middlewares",
        "handlers", "validators", "converters", "processors",
        "interceptors", "listeners", "hooks", "filters",
        "columns", "indexes", "constraints", "fields",
        "serializers", "deserializers", "encoders", "decoders",
        "ddl", "ddl_statements", "statements",  # DDL schema management
        # ORM mapper / schema attributes — loops over these iterate over
        # the *class hierarchy* or *table schema*, not user-data rows.
        # SQLAlchemy: base_mapper._sorted_tables, mapper._pks_by_table, etc.
        "tables", "sorted_tables", "mappers", "mapper",
        "bases", "subclasses", "hierarchy",
    }
)


@dataclass(slots=True)
class _FunctionInfo:
    name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    module_path: Path
    direct_calls: set[str] = field(default_factory=set)
    is_db_adjacent: bool = False
    # Parameter names inherited from lexically enclosing (ancestor) functions.
    # When a nested function calls a name that is a parameter of an outer
    # function, the call targets a caller-supplied callback — not a DB function.
    # Suppressing these prevents false positives from BFS name pollution where
    # a parameter name like ``fn`` or ``callback`` gets marked as db_adjacent
    # because another unrelated function with the same name does DB work.
    ancestor_params: frozenset[str] = field(default_factory=frozenset)


def _called_names(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return the set of function/method names directly called in ``fn_node``."""
    names: set[str] = set()
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
                # Also track receiver.method for DB hints.
                if isinstance(func.value, ast.Name):
                    names.add(f"{func.value.id}.{func.attr}")
                elif isinstance(func.value, ast.Attribute) and isinstance(
                    func.value.value, ast.Name
                ):
                    # self._executor.execute etc.
                    names.add(f"{func.value.value.id}.{func.value.attr}.{func.attr}")
    return names


# Methods that are DB-specific ONLY when the receiver is a known DB object.
# "exec"       — SQLModel's session.exec() (Python built-in exec() is bare, not a method).
# "fetch"      — asyncpg conn.fetch() / pool.fetch().
# "fetchrow"   — asyncpg conn.fetchrow().
# "fetchval"   — asyncpg conn.fetchval().
# "commit"     — session.commit() / conn.commit() in a loop = N transactions instead of 1.
# Django ORM methods: always require "objects" manager or "_set" reverse-FK receiver.
# "filter"     — QuerySet.filter() is a query; bare filter() is a Python builtin (guarded).
# "exclude"    — QuerySet.exclude(); no Python builtin, but guard on receiver anyway.
# "all"        — QuerySet.all(); bare all() is Python builtin (guarded by _BUILTIN_BARE_CALL_NAMES).
# "count"      — QuerySet.count() issues COUNT(*); list.count(x) has different signature.
# "values"     — QuerySet.values(); dict.values() has no args; receiver disambiguates.
# "values_list"— Django-specific; needs receiver to guard against list comprehension FPs.
# "delete"     — QuerySet.delete() / reversed-FK manager.delete() = N DELETE queries.
# "get"        — QuerySet.get() / Model.objects.get() = SELECT per call; dict.get() guarded via
#                _PURE_PYTHON_METHODS in the indirect path and non-DB receiver in direct path.
# "create"     — Model.objects.create() = INSERT per call; factory.create() guarded by receiver.
_RECEIVER_REQUIRED = frozenset({
    "execute", "exec", "prepare",
    "scalar", "scalars", "fetchall", "fetchone",
    "fetch", "fetchrow", "fetchval",       # asyncpg
    "commit",                              # N commits in loop — should be 1 outside
    "hget",                                # Redis HGET (single field) — requires connection receiver
    # Django ORM methods (need "objects" manager or "_set" reverse-FK receiver)
    "filter", "exclude",                   # SELECT WHERE / SELECT WHERE NOT
    "all",                                 # SELECT *
    "count",                               # SELECT COUNT
    "values", "values_list",               # SELECT (as dict / as list)
    "delete",                              # DELETE — N deletes per row in loop
    "get",                                 # SELECT (single) — N selects in loop
    "create",                              # INSERT — N inserts in loop
})
# ORM methods where the receiver IS the data carrier (the loop variable appears
# in the receiver chain, not in the arguments).
#
# For these methods, ``_receiver_uses_any`` is applied as a fallback when
# ``_uses_any`` (args/kwargs only) returns False.  This handles patterns like::
#
#     for author in authors:
#         author.book_set.all()        # "author" is in receiver
#         author.book_set.filter(...)  # same
#         await event.fetch_related("attendees")  # "event" is in receiver
#
# General driver methods (execute_command, execute, scalar, …) are intentionally
# excluded to avoid flagging protocol-mandated fan-out patterns::
#
#     for sentinel in sentinels:
#         sentinel.execute_command(cmd)  # fan-out — NOT an accidental N+1
#
_ORM_RECEIVER_METHODS: frozenset[str] = frozenset({
    # Django QuerySet methods (receiver is manager or reverse-FK manager)
    "filter", "exclude", "all", "count", "values", "values_list",
    "delete", "get", "create",
    # High-level ORM methods (always-DB, receiver is model instance or manager)
    "fetch_related", "prefetch_related", "get_or_create", "update_or_create",
    "fetch_link", "fetch_all_links",
})

# Methods that are always DB-specific regardless of receiver name.
_ALWAYS_DB = frozenset(
    {
        "execute_async", "find_one", "insert_one", "insert_many",
        "update_one", "update_many", "delete_one", "delete_many",
        "bulk_write", "execute_command", "execute_concurrent",
        "execute_concurrent_with_args",
        # Redis hash operations — specific enough to never collide with Python builtins
        "hgetall",      # HGETALL — fetch all fields of a Redis hash (RQ, Celery backends)
        # High-level ORM methods (specific enough, rarely collide with generic Python APIs)
        "fetch_related",      # Tortoise ORM: await obj.fetch_related("field")
        "prefetch_related",   # Django ORM: QuerySet.prefetch_related() — triggers extra queries
        "get_or_create",      # Django/Tortoise: SELECT + optional INSERT per call
        "update_or_create",   # Django: SELECT + INSERT or UPDATE per call
        "fetch_link",         # Beanie ODM: await obj.fetch_link("field")
        "fetch_all_links",    # Beanie ODM: await obj.fetch_all_links()
    }
)


def _is_direct_db_call(node: ast.Call) -> bool:
    """True if this call looks like a direct DB access.

    Uses ``_is_db_receiver()`` for receiver matching, which covers both exact
    names (``session``, ``conn``) and common suffixes (``_listener_conn``,
    ``_write_session``, etc.).
    """
    func = node.func
    if isinstance(func, ast.Name):
        # Bare name calls (not method calls) — only always-DB patterns.
        return func.id in _ALWAYS_DB
    if isinstance(func, ast.Attribute):
        method = func.attr
        if method in _ALWAYS_DB:
            return True
        if method not in _RECEIVER_REQUIRED:
            return False
        # Receiver check required for ambiguous names.
        receiver = func.value
        if isinstance(receiver, ast.Name):
            return _is_db_receiver(receiver.id)
        if isinstance(receiver, ast.Attribute):
            # self._executor.execute, self._listener_conn.execute, etc.
            return _is_db_receiver(receiver.attr) or (
                isinstance(receiver.value, ast.Name)
                and _is_db_receiver(receiver.value.id)
            )
    return False


# Django ORM methods that are safe to detect on multi-level receivers (obj.rel.method())
# without a recognised receiver name (objects, _set, session, etc.).
# Only methods with signatures that don't collide with common Python/stdlib APIs are
# included here; risky names (get, delete, create) stay out because they appear on
# dicts, caches, and factory objects.
#
#  all()          — no args: Python's all(iterable) always has exactly 1 arg
#  values_list()  — Django-specific; no Python builtin or stdlib equivalent
#  select_related()   — Django-specific
#  prefetch_related() — already in _ALWAYS_DB; kept here for symmetry
#  select_for_update()— Django-specific
#  filter(kw=…)   — kwargs-only: Python's filter(fn, it) always has 2 positional args
#  exclude(kw=…)  — kwargs-only: no Python stdlib equivalent
#  count()        — no args: list.count(value) always has 1 arg
_DJANGO_RELATED_MANAGER_METHODS: frozenset[str] = frozenset({
    "all", "values_list", "select_related", "select_for_update",
    "filter", "exclude", "count",
})


# Django/ORM instance methods that mutate or refresh a single object.
# Called as ``obj.save()``, ``obj.delete()``, ``obj.refresh_from_db()`` where
# ``obj`` is the loop variable — each iteration issues a separate DB round-trip.
# ``save`` and ``delete`` are generic enough that we require the receiver to be
# a plain Name that matches a loop variable (not ``form.save()`` on a non-loop var).
_ORM_INSTANCE_MUTATION_METHODS: frozenset[str] = frozenset({
    "save",
    "delete",
    "refresh_from_db",  # Django: re-fetches the object from the database
    "full_clean",       # Django: validation + DB read — costly per-instance
})


def _is_orm_instance_mutation(node: ast.Call) -> bool:
    """True when this looks like ``obj.save()`` / ``obj.delete()`` on a plain Name.

    Only matches single-level receivers (``obj.save()``) — not multi-level chains
    like ``form.instance.save()``.  The caller must additionally verify that the
    receiver name is a loop variable via ``_receiver_uses_any``.
    """
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in _ORM_INSTANCE_MUTATION_METHODS:
        return False
    # Single-level receiver only: obj.save(), not self.obj.save()
    return isinstance(func.value, ast.Name)


def _is_django_related_manager_call(node: ast.Call) -> bool:
    """True when this looks like a Django reverse-manager / queryset method on a
    multi-level receiver that wasn't caught by ``_is_direct_db_call``.

    Examples caught::

        product.collections.all()        # M2M reverse manager
        line.discounts.filter(type=X)    # custom related_name FK
        order.fulfillments.count()       # reverse FK manager

    Guards against common FPs:
    - all([True, False])   → 1-level receiver (bare Name) → excluded
    - list.count(value)    → has positional arg → excluded
    - filter(fn, iterable) → has positional args → excluded
    - Model.objects.all()  → objects in _DB_RECEIVER_HINTS → caught by _is_direct_db_call first
    """
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    method = func.attr
    if method not in _DJANGO_RELATED_MANAGER_METHODS:
        return False
    receiver = func.value
    # Must be at least 2 levels deep: obj.rel.method(), not just rel.method()
    # (1-level cases are already handled by _is_direct_db_call)
    if not isinstance(receiver, ast.Attribute):
        return False
    # all() and count() must have no arguments — distinguishes from Python builtins
    if method in ("all", "count") and (node.args or node.keywords):
        return False
    # filter() and exclude() must use kwargs only — Python's filter(fn, it) has positional args
    if method in ("filter", "exclude") and node.args:
        return False
    return True


class CallGraph:
    """Builds and queries an inter-procedural call graph from AST modules.

    Usage::

        cg = CallGraph()
        for path, module in my_modules:
            cg.add_module(path, module)
        cg.compute()

        # Now query:
        for finding in cg.n1_findings():
            print(finding)
    """

    def __init__(self) -> None:
        # fn_name → list of FunctionInfo (multiple functions can share a name)
        self._functions: dict[str, list[_FunctionInfo]] = defaultdict(list)
        # Modules added but not yet processed
        self._pending: list[tuple[Path, ast.Module, str]] = []
        # Module-level constant iterables: path → {var_name → (list|tuple) node}
        # Populated by _collect; consulted by _check_loop via _is_constant_n_loop.
        self._module_consts: dict[Path, dict[str, ast.List | ast.Tuple]] = defaultdict(dict)
        # Source text per module — used to generate code snippets in findings.
        self._sources: dict[Path, str] = {}

    def add_module(self, path: Path, module: ast.Module, source: str = "") -> None:
        """Register an AST module for analysis."""
        self._sources[path] = source
        self._pending.append((path, module, source))

    def compute(self) -> None:
        """Process all pending modules — build graph and mark DB-adjacent functions."""
        for path, module, source in self._pending:
            self._collect(path, module, source)
        self._pending.clear()
        self._mark_db_adjacent()

    def n1_findings(self) -> Iterable[Finding]:
        """Yield findings for loops that call DB-adjacent functions."""
        for infos in self._functions.values():
            for fn_info in infos:
                yield from self._check_function(fn_info)

    # ------------------------------------------------------------------

    def _collect(self, path: Path, module: ast.Module, source: str) -> None:
        # ── Case 7: index module-level constant iterables ─────────────────────
        # Collect top-level assignments like:
        #   _extensions = [("citext", (13,)), ("hstore", (13,))]
        # These are not visible inside function scopes via ast.walk(fn_node),
        # so we build a per-module index here and pass it to _is_constant_n_iter.
        mod_consts = self._module_consts[path]
        for stmt in module.body:
            if not isinstance(stmt, ast.Assign):
                continue
            if not isinstance(stmt.value, (ast.List, ast.Tuple)):
                continue
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    mod_consts[tgt.id] = stmt.value

        # ── Collect functions with ancestor-parameter tracking ─────────────────
        # We do a recursive walk (not ast.walk) so we can track which function
        # parameters are in scope at each nesting level.  This lets us identify
        # calls to ancestor parameters (closures) and suppress those from the
        # BFS name-pollution check.
        self._collect_scope(path, module.body, ancestor_params=frozenset())

    def _collect_scope(
        self,
        path: Path,
        stmts: list[ast.stmt],
        ancestor_params: frozenset[str],
    ) -> None:
        """Recursively collect functions from a list of statements.

        ``ancestor_params`` accumulates the parameter names of all lexically
        enclosing function definitions, so nested functions can know which
        names are caller-supplied callbacks rather than real DB functions.
        """
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node = stmt
                info = _FunctionInfo(
                    name=node.name,
                    node=node,
                    module_path=path,
                    direct_calls=_called_names(node),
                    ancestor_params=ancestor_params,
                )
                # Check if this function directly calls a DB pattern.
                # NOTE: we walk only the *direct* body (not nested function
                # definitions) to avoid marking a function as db_adjacent
                # merely because it *returns a closure* that does DB work.
                # Example: _load_subclass_via_in() in SQLAlchemy ORM creates
                # a ``do_load`` closure whose body calls session.execute().
                # The outer function itself does not execute a query — it only
                # manufactures a callable.  Marking it as db_adjacent causes
                # false positives in loops that register closures for deferred
                # execution (a common ORM / event-system pattern).
                for child in _iter_direct_calls_no_nested(node):
                    if _is_direct_db_call(child):
                        info.is_db_adjacent = True
                        break
                self._functions[node.name].append(info)

                # Recurse into the function body with this function's params added.
                own_params = frozenset(
                    a.arg for a in (
                        node.args.args
                        + node.args.posonlyargs
                        + node.args.kwonlyargs
                        + ([node.args.vararg] if node.args.vararg else [])
                        + ([node.args.kwarg] if node.args.kwarg else [])
                    )
                )
                self._collect_scope(
                    path,
                    node.body,
                    ancestor_params=ancestor_params | own_params,
                )
            elif isinstance(stmt, ast.ClassDef):
                # Recurse into class body with same ancestor params.
                self._collect_scope(path, stmt.body, ancestor_params)
            elif hasattr(stmt, "body"):
                # if/try/with/for/while — recurse into nested blocks.
                for attr in ("body", "orelse", "handlers", "finalbody"):
                    block = getattr(stmt, attr, None)
                    if isinstance(block, list):
                        if block and isinstance(block[0], ast.ExceptHandler):
                            for handler in block:
                                self._collect_scope(path, handler.body, ancestor_params)
                        else:
                            self._collect_scope(path, block, ancestor_params)

    def _mark_db_adjacent(self) -> None:
        """BFS: propagate db_adjacent flag to all transitive callers.

        Seeding strategy: only production-path functions are used as seeds.
        Functions living in test/benchmark/example directories (as determined
        by ``_is_background_path``) may directly call ``execute()`` or similar
        as part of test fixtures, assertions, or benchmarks.  If we allow them
        to seed the BFS, very common function names like ``fn``, ``execute``,
        or ``callback`` get flagged as "db_adjacent" across the entire codebase,
        causing massive false positives in production code.

        Functions from background paths are still marked ``is_db_adjacent``
        individually (so findings *within* those files can be reported as INFO
        when requested), but they do NOT propagate the flag to their callers.
        """
        # Seed only with functions whose path is NOT a background/test path.
        # Background-path functions that directly call DB remain db_adjacent
        # for their own scope but must not contaminate the broader BFS.
        queue: deque[str] = deque(
            name
            for name, infos in self._functions.items()
            if any(
                i.is_db_adjacent and not _is_background_path(i.module_path)
                for i in infos
            )
        )
        visited: set[str] = set(queue)

        while queue:
            db_fn_name = queue.popleft()
            # Find all functions that call db_fn_name.
            for caller_name, caller_infos in self._functions.items():
                if caller_name in visited:
                    continue
                for caller_info in caller_infos:
                    if db_fn_name in caller_info.direct_calls:
                        for ci in caller_infos:
                            ci.is_db_adjacent = True
                        visited.add(caller_name)
                        queue.append(caller_name)
                        break

    def _check_function(self, fn_info: _FunctionInfo) -> Iterable[Finding]:
        """Walk the function body for loops and gather/await-listcomp N+1 patterns."""
        fn_node = fn_info.node
        # Build variable → ListComp index once per function for Variant B detection.
        listcomp_index = _build_listcomp_index(fn_node)
        for stmt in fn_node.body:
            yield from self._check_stmt(stmt, fn_info)
            # Skip nested function definitions — they are processed as their own
            # _FunctionInfo and must not produce findings attributed to this scope.
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield from self._check_gather_in_stmt(stmt, fn_info, listcomp_index)
                yield from self._check_await_listcomp_in_stmt(stmt, fn_info)

    def _check_stmt(self, stmt: ast.stmt, fn_info: _FunctionInfo) -> Iterable[Finding]:
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            yield from self._check_loop(stmt, fn_info)
        elif isinstance(stmt, ast.While):
            yield from self._check_while_loop(stmt, fn_info)
        elif isinstance(stmt, (ast.If, ast.With, ast.AsyncWith, ast.Try)):
            # Recurse into nested blocks.
            for child_body in _get_bodies(stmt):
                for child_stmt in child_body:
                    yield from self._check_stmt(child_stmt, fn_info)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Nested functions are their own scope — skip (already in graph).
            pass

    def _check_loop(
        self, loop: ast.For | ast.AsyncFor, fn_info: _FunctionInfo
    ) -> Iterable[Finding]:
        # ── Pagination-loop suppression ─────────────────────────────────────
        # ``for _ in range(max_pages):`` with an internal break is the universal
        # cursor-pagination idiom.  It is not a data-driven N+1.
        if _is_pagination_loop(loop):
            return

        # ── Severity selection ──────────────────────────────────────────────
        # Background / maintenance functions, benchmark / example files, and
        # early-exit loops are expected to iterate row-by-row without
        # user-latency impact.  Downgrade to INFO instead of suppressing so
        # they still appear in reports with appropriate context.
        early_exit = _has_early_exit_after_db(loop)
        background = _is_background_fn(fn_info.name) or _is_background_path(fn_info.module_path)
        severity = Severity.INFO if (early_exit or background) else Severity.WARNING

        loop_vars = _target_names(loop.target)
        # Expand with aliases defined in the loop body (e.g. ``msg = delivery``
        # means ``msg`` should also be treated as a loop variable for usage checks).
        loop_vars = _collect_loop_var_aliases(loop.body, loop_vars)

        # Precompute constant-N check at both thresholds so we don't repeat the
        # walk for every call node.
        mod_consts = self._module_consts.get(fn_info.module_path, {})
        is_small_n_direct = _is_constant_n_loop(
            loop, fn_info.node, max_n=_MAX_SMALL_N_DIRECT, module_consts=mod_consts
        )
        is_small_n_indirect = _is_constant_n_loop(
            loop, fn_info.node, max_n=_MAX_SMALL_N_INDIRECT, module_consts=mod_consts
        )

        for stmt in loop.body:
            # Nested for/async-for: recurse with the inner loop's own loop_vars
            # instead of walking into it with the outer loop's loop_vars, which
            # would cause missed detections when the inner var differs from outer.
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                # Also check the inner loop's iterable for DB calls parameterised
                # by the OUTER loop's variable.  Pattern:
                #   for order in orders:
                #       for gc in order.gift_cards.select_for_update():  # N+1!
                # The iterable evaluates once per outer iteration — that is an N+1
                # even though the inner body is trivial.
                if not is_small_n_direct:
                    for iter_node in ast.walk(stmt.iter):
                        if not isinstance(iter_node, ast.Call):
                            continue
                        is_iter_db = (
                            _is_direct_db_call(iter_node)
                            or _is_django_related_manager_call(iter_node)
                        )
                        if not is_iter_db:
                            continue
                        if loop_vars and not (
                            _receiver_uses_any(iter_node, loop_vars)
                            or _uses_any(iter_node, loop_vars)
                        ):
                            continue
                        if loop_vars and _is_batch_in_query(iter_node, loop_vars):
                            continue
                        callee = self._callee_name(iter_node) or "query"
                        yield self._make_finding(loop, iter_node, callee, fn_info, severity)
                        return
                yield from self._check_loop(stmt, fn_info)
                continue
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call):
                    continue
                # Direct DB call inside the loop body.
                # Apply a SMALL constant-N threshold: loops over 3 status literals
                # are suppressed, but 6+ elements or non-string literals are flagged.
                if _is_direct_db_call(node):
                    if is_small_n_direct:
                        continue
                    # execute(pending_batch) / execute(batch) — the single argument
                    # is a BatchStatement accumulator: this is a batch round-trip,
                    # not an individual per-row query.  Suppress as pipeline flush.
                    if _is_batch_arg_execute(node):
                        continue
                    # pipe.execute_command(...) / batch.execute(...) —
                    # the receiver itself is a pipeline/batch accumulator.
                    # Calls on it buffer commands; the real I/O is the single
                    # execute() outside the loop.
                    if any(p in _receiver_name(node) for p in _PIPELINE_RECEIVERS):
                        continue
                    if loop_vars:
                        uses_var = _uses_any(node, loop_vars)
                        # ORM fallback: methods like all(), filter(), fetch_related()
                        # encode the predicate in the receiver chain, not the args.
                        # Apply receiver-chain check ONLY for ORM methods to avoid
                        # flagging protocol-mandated fan-out (sentinel.execute_command).
                        if not uses_var:
                            callee_m = self._callee_name(node)
                            if callee_m in _ORM_RECEIVER_METHODS:
                                uses_var = _receiver_uses_any(node, loop_vars)
                        if not uses_var:
                            continue  # DB call doesn't use loop var — probably not N+1
                    # Batch-chunked query: filter(pk__in=batch) or filter(id__in=ids)
                    # is a single SQL "WHERE pk IN (...)" — NOT an N+1.
                    if loop_vars and _is_batch_in_query(node, loop_vars):
                        continue
                    callee = self._callee_name(node) or "execute"
                    yield self._make_finding(loop, node, callee, fn_info, severity)
                    return
                # Django reverse manager: obj.related_name.all() / .filter(kw=v)
                # The receiver name isn't a recognised DB hint (not "objects", not
                # "_set" suffix) but the method signature is unambiguously ORM.
                # We require the loop variable to appear in the receiver chain to
                # confirm the call is data-driven (not a one-time setup call).
                if _is_django_related_manager_call(node):
                    if is_small_n_direct:
                        continue
                    if loop_vars and not _receiver_uses_any(node, loop_vars):
                        continue
                    callee = self._callee_name(node) or "all"
                    yield self._make_finding(loop, node, callee, fn_info, severity)
                    return
                # ORM instance mutations: obj.save() / obj.delete() / obj.refresh_from_db()
                # These are single-object writes that issue one query per loop iteration.
                # We require the receiver (the loop variable) to be a plain Name that
                # appears in loop_vars to avoid flagging form.save() on non-loop objects.
                if _is_orm_instance_mutation(node):
                    if is_small_n_direct:
                        continue
                    if loop_vars:
                        receiver = node.func.value  # type: ignore[union-attr]
                        if not (
                            isinstance(receiver, ast.Name)
                            and receiver.id in loop_vars
                        ):
                            continue
                    callee = self._callee_name(node) or "save"
                    yield self._make_finding(loop, node, callee, fn_info, severity)
                    return
                # Indirect: call to a DIRECTLY db-adjacent function (1 hop only).
                # Apply a LARGER constant-N threshold (schema-init loops can have
                # 10-15 column/field definitions and are never user-data-driven).
                # Also require that the loop variable appears in the call's arguments
                # to filter out startup loops that call a helper N times for N
                # companies/instances without parameterising by loop variable.
                if is_small_n_indirect:
                    continue
                callee = self._callee_name(node)
                if callee and self._is_directly_db_adjacent(callee):
                    if loop_vars and not _uses_any(node, loop_vars):
                        continue
                    # ── Ancestor-parameter (closure) guard ─────────────────
                    # If the callee is a bare Name call AND it is a parameter
                    # of a lexically enclosing function, it is a caller-supplied
                    # callback (higher-order function pattern).  The BFS may
                    # have marked the name as db_adjacent because an unrelated
                    # function with the same name does DB work somewhere else.
                    # Example: visit_binary_product(fn, expr) defines a nested
                    # visit() that calls fn(l, r) in a loop — ``fn`` is a
                    # closure parameter, not a global DB function.
                    if (
                        isinstance(node.func, ast.Name)
                        and node.func.id in fn_info.ancestor_params
                    ):
                        continue
                    # ── Built-in bare-call guard ────────────────────────────
                    # Libraries like redis-py define methods named ``range``,
                    # ``list``, ``type``, ``get``, etc. that call
                    # ``execute_command()``.  The BFS propagates is_db_adjacent
                    # to those names.  When the *actual* Python built-in with
                    # the same name appears in a loop (e.g. ``range(0, n, 2)``,
                    # ``list(set(...))``, ``type(x)(x)``), we get a false
                    # positive.  Guard: if the call is a bare ``ast.Name``
                    # (no receiver) and the name is a known Python built-in,
                    # skip — the built-in cannot be a DB operation.
                    if (
                        isinstance(node.func, ast.Name)
                        and node.func.id in _BUILTIN_BARE_CALL_NAMES
                    ):
                        continue
                    # ── Fan-out routing guard ──────────────────────────────
                    # ``fn.name == callee`` with a non-self receiver means this
                    # function is *delegating* the same operation to a
                    # per-shard/per-node object.  Classic examples:
                    #   ClusterPubSub.ssubscribe()  → pubsub.ssubscribe(ch)
                    #   ClusterPubSub.sunsubscribe() → p.sunsubscribe(ch)
                    # This is protocol-mandated fan-out (Redis Cluster sharded
                    # pub/sub), not an accidental N+1.  The receiver being
                    # something other than ``self`` distinguishes delegation
                    # from genuine recursive N+1 (``self.query_db()``).
                    if (
                        callee == fn_info.name
                        and isinstance(node.func, ast.Attribute)
                        and not (
                            isinstance(node.func.value, ast.Name)
                            and node.func.value.id == "self"
                        )
                    ):
                        continue
                    # ── Same-file local-version guard ──────────────────────
                    # BFS propagation can mark a method name as db_adjacent
                    # because a *different class in a different file* has a
                    # method with the same name that calls execute_command().
                    # When the caller uses ``self.<method>()`` AND the local
                    # module defines a version of ``<method>`` that is NOT
                    # db_adjacent, the call resolves to the local version —
                    # the DB-adjacent version from another file is irrelevant.
                    #
                    # Example: Rich's Table.add_column() (not DB) shares its
                    # name with SQLAlchemy's schema.add_column() (DDL), and
                    # ConfigParser.get() shares its name with Redis commands.get().
                    #
                    # Guard: only applies to ``self.<method>`` calls where a
                    # local (same-file) non-db version exists.  Cross-module
                    # calls (other_obj.method()) still go through the normal path.
                    if (
                        isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "self"
                    ):
                        local_versions = [
                            i for i in self._functions.get(callee, [])
                            if i.module_path == fn_info.module_path
                        ]
                        if local_versions and not any(
                            i.is_db_adjacent for i in local_versions
                        ):
                            continue  # local version is not DB — suppress
                    # Suppress if this looks like a built-in Python method on a
                    # non-service receiver (e.g. dict.get(), set.update(),
                    # batch.add()) — name-collision false positive.
                    if _is_likely_in_memory_call(node, callee):
                        continue
                    yield self._make_finding(loop, node, callee, fn_info, severity)
                    return
                # ── asyncio.TaskGroup / create_task transparency ────────────
                # ``tg.create_task(db_fn(uid))`` in a loop schedules N concurrent
                # coroutines.  The outer ``create_task`` is not a DB call, but its
                # first argument ``db_fn(uid)`` IS.  We unwrap and check the inner
                # call.  Severity is always INFO (concurrent, not serial).
                inner = _unwrap_create_task(node)
                if inner is None:
                    continue
                inner_callee = self._callee_name(inner)
                if not inner_callee:
                    continue
                if is_small_n_indirect:
                    continue
                is_inner_direct = _is_direct_db_call(inner)
                if is_inner_direct:
                    if _is_batch_arg_execute(inner):
                        continue
                    if any(p in _receiver_name(inner) for p in _PIPELINE_RECEIVERS):
                        continue
                elif self._is_directly_db_adjacent(inner_callee):
                    if _is_likely_in_memory_call(inner, inner_callee):
                        continue
                else:
                    continue
                if loop_vars and not _uses_any(inner, loop_vars):
                    continue
                yield self._make_finding(loop, inner, inner_callee, fn_info, Severity.INFO)
                return

    @staticmethod
    def _callee_name(call: ast.Call) -> str | None:
        func = call.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    def _is_db_adjacent_name(self, name: str) -> bool:
        infos = self._functions.get(name, [])
        return any(i.is_db_adjacent for i in infos)

    def _is_directly_db_adjacent(self, name: str) -> bool:
        """True only if the function DIRECTLY executes a query (not just prepares).

        ``prepare()`` creates a ``PreparedStatement`` object without executing
        a query or returning data.  Helpers that only call ``prepare()`` (e.g.
        statement-builder utilities with an internal cache) are not N+1 sources
        and must not trigger the indirect call check.  All other recognised DB
        methods (``execute``, ``scalar``, ``fetchall``, …) still count.

        We also exclude DB calls that appear only inside nested function
        definitions (closures returned by the function).  A function that
        *returns* a closure containing session.execute() does not itself issue
        a query — it manufactures a callable for the caller to invoke later.
        Counting such functions as db_adjacent causes false positives in loops
        that register deferred-execution callbacks (SQLAlchemy ORM PostLoad,
        event-system hooks, etc.).

        Background-path instances (test fixtures, benchmarks, example files)
        are excluded from this check so that a test helper whose name collides
        with a production function does not make production loops false-positive.
        """
        infos = self._functions.get(name, [])
        for info in infos:
            # Skip functions in test / benchmark / example paths.
            if _is_background_path(info.module_path):
                continue
            for node in _iter_direct_calls_no_nested(info.node):
                if not _is_direct_db_call(node):
                    continue
                # Skip prepare() — it's statement setup, not query execution.
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "prepare":
                    continue
                return True
        return False

    def _make_finding(
        self,
        loop: ast.For | ast.AsyncFor,
        call: ast.Call,
        callee: str,
        fn_info: _FunctionInfo,
        severity: Severity = Severity.WARNING,
    ) -> Finding:
        loop_type = "async for" if isinstance(loop, ast.AsyncFor) else "for"
        severity_hint = (
            " (background operation — lower priority)"
            if severity == Severity.INFO
            else ""
        )
        bg_tag = " [background]" if severity == Severity.INFO else ""
        return Finding.from_node(
            rule_id="PKN102",
            message=(
                f"Potential cross-function N+1: ``{loop_type}`` loop in "
                f"``{fn_info.name}()`` calls ``{callee}()``, which transitively "
                "accesses a database. Each iteration may issue a separate query. "
                f"Consider batching or restructuring the loop.{severity_hint}"
            ),
            short_message=(
                f"N+1 in {fn_info.name}: {callee}() per {loop_type}-loop iter{bg_tag}"
            ),
            node=loop,
            ctx=AstContext(
                path=fn_info.module_path,
                source=self._sources.get(fn_info.module_path, ""),
                module=ast.Module(body=[], type_ignores=[]),
            ),
            severity=severity,
            fix=Fix(
                description=(
                    f"Refactor ``{callee}()`` to accept a list of IDs and fetch "
                    "all results in a single query, then join in Python."
                )
            ),
        )

    def _check_while_loop(
        self, loop: ast.While, fn_info: _FunctionInfo
    ) -> Iterable[Finding]:
        """Detect N+1 inside ``while True`` consumer loops (Kafka, MQTT, IoT).

        Pattern::

            while True:
                msg = consumer.poll()
                if msg is None:
                    continue
                await session.execute(query, [msg.key])  # N+1!

        ``while`` loops have no explicit iteration variable, so we flag any
        DB call in the body.  We only process obvious infinite-loop patterns
        (``while True`` / ``while 1``) to avoid flagging bounded while loops
        that are semantically safe (pagination cursors, retry loops, etc.).
        """
        cond = loop.test
        is_infinite = isinstance(cond, ast.Constant) and bool(cond.value)
        if not is_infinite:
            return

        # Retry / backoff loops (``while True: try: return await op() ...``)
        # repeat the SAME operation, not a NEW item per iteration.
        # They are definitively NOT consumer N+1 patterns — suppress entirely.
        if _is_while_retry_loop(loop):
            return

        background = _is_background_fn(fn_info.name) or _is_background_path(fn_info.module_path)
        severity = Severity.INFO if background else Severity.WARNING

        for stmt in loop.body:
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                yield from self._check_loop(stmt, fn_info)
                continue
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call):
                    continue
                if _is_direct_db_call(node):
                    if _is_batch_arg_execute(node):
                        continue
                    if any(p in _receiver_name(node) for p in _PIPELINE_RECEIVERS):
                        continue
                    callee = self._callee_name(node) or "execute"
                    yield self._make_while_finding(loop, node, callee, fn_info, severity)
                    return
                if _is_django_related_manager_call(node):
                    callee = self._callee_name(node) or "all"
                    yield self._make_while_finding(loop, node, callee, fn_info, severity)
                    return
                if _is_orm_instance_mutation(node):
                    callee = self._callee_name(node) or "save"
                    yield self._make_while_finding(loop, node, callee, fn_info, severity)
                    return
                callee = self._callee_name(node)
                if callee and self._is_directly_db_adjacent(callee):
                    if (
                        isinstance(node.func, ast.Name)
                        and node.func.id in fn_info.ancestor_params
                    ):
                        continue
                    if (
                        isinstance(node.func, ast.Name)
                        and node.func.id in _BUILTIN_BARE_CALL_NAMES
                    ):
                        continue
                    if (
                        callee == fn_info.name
                        and isinstance(node.func, ast.Attribute)
                        and not (
                            isinstance(node.func.value, ast.Name)
                            and node.func.value.id == "self"
                        )
                    ):
                        continue
                    if (
                        isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "self"
                    ):
                        local_versions = [
                            i for i in self._functions.get(callee, [])
                            if i.module_path == fn_info.module_path
                        ]
                        if local_versions and not any(i.is_db_adjacent for i in local_versions):
                            continue
                    if _is_likely_in_memory_call(node, callee):
                        continue
                    yield self._make_while_finding(loop, node, callee, fn_info, severity)
                    return

    def _make_while_finding(
        self,
        loop: ast.While,
        call: ast.Call,
        callee: str,
        fn_info: _FunctionInfo,
        severity: Severity = Severity.WARNING,
    ) -> Finding:
        severity_hint = (
            " (background operation — lower priority)"
            if severity == Severity.INFO
            else ""
        )
        bg_tag = " [background]" if severity == Severity.INFO else ""
        return Finding.from_node(
            rule_id="PKN102",
            message=(
                f"Potential N+1 in consumer loop: ``while True`` loop in "
                f"``{fn_info.name}()`` calls ``{callee}()`` for each "
                "message/event, which accesses a database. Each iteration "
                "may issue a separate query. Consider accumulating messages "
                f"in a buffer and batch-querying.{severity_hint}"
            ),
            short_message=(
                f"N+1 in {fn_info.name}: while-loop calls {callee}() per event{bg_tag}"
            ),
            node=loop,
            ctx=AstContext(
                path=fn_info.module_path,
                source=self._sources.get(fn_info.module_path, ""),
                module=ast.Module(body=[], type_ignores=[]),
            ),
            severity=severity,
            fix=Fix(
                description=(
                    f"Accumulate messages in a buffer and call ``{callee}()`` "
                    "once with the full batch, or use a batch query to process "
                    "multiple messages in a single database round-trip."
                )
            ),
        )

    def _check_gather_in_stmt(
        self,
        stmt: ast.stmt,
        fn_info: _FunctionInfo,
        listcomp_index: dict[str, ast.ListComp | ast.GeneratorExp],
    ) -> Iterable[Finding]:
        """Detect concurrent N+1 via ``asyncio.gather(*<source>)``.

        Handles five source patterns (via ``_extract_gather_source``):

        A. ``*[f(x) for x in items]``         — list comprehension
        B. ``*(f(x) for x in items)``          — generator expression
        C. ``*tasks`` where ``tasks=[f(x)…]``  — variable reference
        D. ``*tuple(f(x) for x in items)``     — tuple()/list() wrapper
        E. ``*map(db_fn, items)``               — implicit map-based loop

        DB-adjacency is checked in two passes:

        1. ``_is_directly_db_adjacent`` (1-hop) — high precision, low recall.
        2. ``_is_db_adjacent_name`` (BFS) — catches 2+ hop chains with extra
           filtering to keep FP rate acceptable (built-ins, pure-Python methods,
           and in-memory call heuristics are all applied).

        Severity is always ``INFO`` — concurrent execution reduces latency but
        not query count (N round-trips still occur).
        """
        mod_consts = self._module_consts.get(fn_info.module_path, {})
        for node in _iter_calls_no_inner_fns(stmt):
            if not _is_gather_call(node):
                continue
            for arg in node.args:
                if not isinstance(arg, ast.Starred):
                    continue

                source = _extract_gather_source(arg.value, listcomp_index)
                if source is None:
                    continue

                # ── map(db_fn, items) case ─────────────────────────────────
                if isinstance(source, tuple):
                    fn_name, iter_expr = source
                    if _is_constant_n_iter(
                        iter_expr, fn_info.node,
                        max_n=_MAX_SMALL_N_DIRECT, module_consts=mod_consts,
                    ):
                        continue
                    if fn_name in _BUILTIN_BARE_CALL_NAMES:
                        continue
                    is_adj = (
                        self._is_directly_db_adjacent(fn_name)
                        or self._is_db_adjacent_name(fn_name)
                    )
                    if is_adj and fn_name not in _PURE_PYTHON_METHODS:
                        yield self._make_gather_finding(node, fn_name, fn_info)
                    break

                # ── comprehension / generator case ─────────────────────────
                comp = source
                if not comp.generators:
                    continue
                gen = comp.generators[0]
                if _is_constant_n_iter(
                    gen.iter, fn_info.node,
                    max_n=_MAX_SMALL_N_DIRECT, module_consts=mod_consts,
                ):
                    continue

                elt = comp.elt
                if not isinstance(elt, ast.Call):
                    continue

                # Unwrap create_task(db_fn(x)) → check the inner db_fn.
                inner_via_task = _unwrap_create_task(elt)
                actual_elt = inner_via_task if inner_via_task is not None else elt

                callee = self._callee_name(actual_elt)
                if not callee:
                    continue

                if _is_direct_db_call(actual_elt):
                    if _is_batch_arg_execute(actual_elt):
                        continue
                    if any(p in _receiver_name(actual_elt) for p in _PIPELINE_RECEIVERS):
                        continue
                elif self._is_directly_db_adjacent(callee):
                    # 1-hop: high precision
                    if _is_likely_in_memory_call(actual_elt, callee):
                        continue
                elif self._is_db_adjacent_name(callee):
                    # BFS fallback: 2+ hop chains (e.g. _get_article_from_db_record)
                    # Apply extra guards to keep FP rate acceptable.
                    if callee in _BUILTIN_BARE_CALL_NAMES:
                        continue
                    if callee in _PURE_PYTHON_METHODS:
                        continue
                    if _is_likely_in_memory_call(actual_elt, callee):
                        continue
                else:
                    continue

                yield self._make_gather_finding(node, callee, fn_info)
                break

    def _make_gather_finding(
        self,
        gather_call: ast.Call,
        callee: str,
        fn_info: _FunctionInfo,
    ) -> Finding:
        """Emit a PKN102 finding for a gather-based concurrent N+1."""
        return Finding.from_node(
            rule_id="PKN102",
            message=(
                f"Potential concurrent N+1: ``asyncio.gather()`` in "
                f"``{fn_info.name}()`` calls ``{callee}()`` once per element — "
                "N queries are still issued to the database (concurrently, not "
                "serially). Concurrent execution reduces latency but not query "
                "count. Consider a batch query with ``IN`` clause or a DataLoader "
                "to reduce the total query count to 1. "
                "(concurrent — lower priority than sequential N+1)"
            ),
            short_message=(
                f"N+1 in {fn_info.name}: gather maps {callee}() over N elements [concurrent]"
            ),
            node=gather_call,
            ctx=AstContext(
                path=fn_info.module_path,
                source=self._sources.get(fn_info.module_path, ""),
                module=ast.Module(body=[], type_ignores=[]),
            ),
            severity=Severity.INFO,
            fix=Fix(
                description=(
                    f"Refactor ``{callee}()`` to accept a list of keys and "
                    "return all results in a single query (``IN`` clause), or "
                    "use the DataLoader pattern to batch requests automatically."
                )
            ),
        )


    def _check_await_listcomp_in_stmt(
        self,
        stmt: ast.stmt,
        fn_info: _FunctionInfo,
    ) -> Iterable[Finding]:
        """Detect N+1 via async list comprehension — serial or concurrent.

        Handles three sub-patterns, all sharing the same listcomp structure:

        **Serial** (WARNING — worst case, O(Σ t_i) latency)::

            users = [await get_user(session, uid) for uid in ids]

        **Concurrent via TaskGroup** (INFO — O(max t_i) latency, Python 3.11+)::

            async with asyncio.TaskGroup() as tg:
                tasks = [tg.create_task(get_user(session, uid)) for uid in ids]

        **Concurrent via create_task** (INFO)::

            tasks = [asyncio.create_task(get_user(session, uid)) for uid in ids]

        Serial is strictly worse than ``asyncio.gather`` and must be WARNING.
        TaskGroup / create_task are concurrent and equivalent to gather → INFO.
        The correct fix for all is a batch query with ``IN`` clause or DataLoader.
        """
        background = _is_background_fn(fn_info.name) or _is_background_path(fn_info.module_path)
        mod_consts = self._module_consts.get(fn_info.module_path, {})

        for comp in _iter_listcomps_no_inner_fns(stmt):
            elt = comp.elt
            if not comp.generators:
                continue

            gen = comp.generators[0]
            if _is_constant_n_iter(
                gen.iter, fn_info.node,
                max_n=_MAX_SMALL_N_DIRECT, module_consts=mod_consts,
            ):
                continue

            # ── Protocol-loop suppression (Fix 4) ────────────────────────────
            # ``[await self._read_response(...) for _ in range(expr)]`` is the
            # Redis/RESP wire-protocol multi-bulk reader: each element of the
            # array is read from the network socket by a recursive call.  The
            # count (``int(response)``) comes from the server, not from user
            # data — this is protocol framing, not a data-driven N+1.
            # Heuristic: throwaway loop variable (``_`` / ``__``) combined with
            # a ``range()`` call whose argument is NOT a plain constant —
            # i.e. ``range(int(x))``.  The callee being ``_read_response``
            # (a self-recursive parser) strengthens the signal, but we apply
            # the suppression for any throwaway-range pattern to avoid FPs
            # in other wire-protocol parsers.
            if (
                _is_throwaway_target(gen.target)
                and isinstance(gen.iter, ast.Call)
                and isinstance(gen.iter.func, ast.Name)
                and gen.iter.func.id == "range"
            ):
                continue

            # Determine the actual DB call and whether it is concurrent.
            is_concurrent = False
            actual_call: ast.Call | None = None

            if isinstance(elt, ast.Await) and isinstance(elt.value, ast.Call):
                # [await f(x) for x in items] — serial (worst case)
                actual_call = elt.value
                is_concurrent = False
            elif isinstance(elt, ast.Call):
                inner = _unwrap_create_task(elt)
                if inner is not None:
                    # [tg.create_task(f(x)) for x in items] — concurrent
                    actual_call = inner
                    is_concurrent = True

            if actual_call is None:
                continue

            callee = self._callee_name(actual_call)
            if not callee:
                continue

            if _is_direct_db_call(actual_call):
                if _is_batch_arg_execute(actual_call):
                    continue
                if any(p in _receiver_name(actual_call) for p in _PIPELINE_RECEIVERS):
                    continue
            elif self._is_directly_db_adjacent(callee):
                # 1-hop: precise
                if _is_likely_in_memory_call(actual_call, callee):
                    continue
            elif self._is_db_adjacent_name(callee):
                # BFS fallback: captures 2+ hop N+1 chains like
                # ``[await _get_article_from_db_record(row) for row in rows]``
                # where the callee transitively calls DB but not directly.
                # Apply extra guards to keep FP rate acceptable.
                if callee in _BUILTIN_BARE_CALL_NAMES:
                    continue
                if callee in _PURE_PYTHON_METHODS:
                    continue
                if _is_likely_in_memory_call(actual_call, callee):
                    continue
            else:
                continue

            if is_concurrent:
                severity = Severity.INFO
            elif background:
                severity = Severity.INFO
            else:
                severity = Severity.WARNING

            yield self._make_await_listcomp_finding(
                comp, callee, fn_info, severity, is_concurrent=is_concurrent
            )
            break

    def _make_await_listcomp_finding(
        self,
        comp: ast.ListComp,
        callee: str,
        fn_info: _FunctionInfo,
        severity: Severity = Severity.WARNING,
        *,
        is_concurrent: bool = False,
    ) -> Finding:
        """Emit a PKN102 finding for an async list comprehension N+1."""
        if is_concurrent:
            description = (
                f"Concurrent N+1 via ``create_task`` in list comprehension: "
                f"``{fn_info.name}()`` schedules ``{callee}()`` once per element — "
                "N queries are issued concurrently (like ``asyncio.gather``). "
                "Consider a batch query with ``IN`` clause or a DataLoader. "
                "(concurrent — lower priority than sequential N+1)"
            )
        else:
            severity_hint = (
                " (background operation — lower priority)"
                if severity == Severity.INFO
                else ""
            )
            description = (
                f"Serial N+1 via ``await`` in list comprehension: "
                f"``{fn_info.name}()`` calls ``{callee}()`` once per element — "
                "each ``await`` runs sequentially, issuing N separate queries. "
                "This is **worse than** ``asyncio.gather`` (which at least runs "
                "concurrently). Consider a batch query with ``IN`` clause or a "
                f"DataLoader.{severity_hint}"
            )
        mode = "concurrent" if is_concurrent else "serial await"
        bg_tag = " [background]" if severity == Severity.INFO and not is_concurrent else ""
        return Finding.from_node(
            rule_id="PKN102",
            message=description,
            short_message=(
                f"N+1 in {fn_info.name}: {mode} {callee}() per listcomp element{bg_tag}"
            ),
            node=comp,
            ctx=AstContext(
                path=fn_info.module_path,
                source=self._sources.get(fn_info.module_path, ""),
                module=ast.Module(body=[], type_ignores=[]),
            ),
            severity=severity,
            fix=Fix(
                description=(
                    f"Refactor ``{callee}()`` to accept a list of keys and "
                    "return all results in a single query, or use "
                    "``asyncio.gather(*[{callee}(x) for x in items])`` as an "
                    "intermediate step while the batch API is not available."
                )
            ),
        )


def _iter_direct_calls_no_nested(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterable[ast.Call]:
    """Yield all Call nodes in ``fn_node``, NOT crossing into nested function defs.

    Unlike ``ast.walk``, this stops recursion when it encounters a nested
    ``FunctionDef`` or ``AsyncFunctionDef``.  This prevents marking a function
    as DB-adjacent merely because it *returns a closure* that contains a DB
    call — only DB calls in the function's own direct body are counted.

    Example pattern that should NOT make the outer function db_adjacent::

        def _build_loader(session):
            def do_load(ids):
                session.execute(query, ids)   # ← inside a closure, not outer fn
            return do_load                    # ← outer fn just creates a callable
    """
    def _walk(node: ast.AST) -> Iterable[ast.Call]:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue  # stop at nested function boundary
            if isinstance(child, ast.Call):
                yield child
            yield from _walk(child)

    yield from _walk(fn_node)


def _is_gather_call(node: ast.Call) -> bool:
    """True if ``node`` is ``asyncio.gather(...)`` or bare ``gather(...)``."""
    func = node.func
    if isinstance(func, ast.Attribute):
        return (
            func.attr == "gather"
            and isinstance(func.value, ast.Name)
            and func.value.id == "asyncio"
        )
    if isinstance(func, ast.Name):
        return func.id == "gather"
    return False


def _iter_calls_no_inner_fns(node: ast.AST) -> Iterable[ast.Call]:
    """Yield all Call nodes under ``node``, stopping at nested function/class boundaries.

    Unlike ``ast.walk``, this never crosses into a nested ``def`` or ``class``,
    which prevents attributing a finding to the wrong (outer) function.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    if isinstance(node, ast.Call):
        yield node
    for child in ast.iter_child_nodes(node):
        yield from _iter_calls_no_inner_fns(child)


def _iter_listcomps_no_inner_fns(node: ast.AST) -> Iterable[ast.ListComp]:
    """Yield all ListComp nodes under ``node``, stopping at nested function/class boundaries."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    if isinstance(node, ast.ListComp):
        yield node
    for child in ast.iter_child_nodes(node):
        yield from _iter_listcomps_no_inner_fns(child)


def _is_background_path(path: Path) -> bool:
    """True when the source file lives under a benchmark/example/doctest directory.

    Files in ``/benchmarks/``, ``/examples/``, ``/doctests/``, etc. are never
    in the production request path.  Any finding sourced from them is downgraded
    to INFO so it does not pollute WARNING reports with intentional test patterns.
    """
    path_str = str(path).lower()
    return any(frag in path_str for frag in _BACKGROUND_PATH_FRAGMENTS)


def _unwrap_create_task(node: ast.Call) -> ast.Call | None:
    """If ``node`` is ``create_task(f(x))`` or ``tg.create_task(f(x))``, return ``f(x)``.

    ``asyncio.create_task`` and ``TaskGroup.create_task`` schedule coroutines
    concurrently — they are *transparent scheduling wrappers*, not DB calls.
    The actual potential N+1 is the function passed AS THE FIRST ARGUMENT.

    Returns ``None`` when the outer call is not a ``create_task`` wrapper or
    when the first argument is not itself a Call node.
    """
    func = node.func
    is_create_task = (
        (isinstance(func, ast.Name) and func.id == "create_task")
        or (isinstance(func, ast.Attribute) and func.attr == "create_task")
    )
    if not is_create_task:
        return None
    if node.args and isinstance(node.args[0], ast.Call):
        return node.args[0]
    return None


def _extract_gather_source(
    arg_value: ast.expr,
    listcomp_index: dict[str, ast.ListComp | ast.GeneratorExp],
) -> ast.ListComp | ast.GeneratorExp | tuple[str, ast.expr] | None:
    """Normalise a ``*arg`` value into the iterable source for DB-adjacency checks.

    Handles five source patterns for ``asyncio.gather(*<source>)``:

    A. Direct comprehension:  ``*[f(x) for x in items]``
    B. Generator expression:  ``*(f(x) for x in items)``
    C. Variable assignment:   ``tasks = [f(x) for x in items]; gather(*tasks)``
    D. Sequence wrapper:      ``*tuple(f(x) for x in items)`` /
                               ``*list(f(x) for x in items)``
    E. map() call:            ``*map(db_fn, items)``

    Returns:
    - ``ListComp`` or ``GeneratorExp`` for cases A–D
    - ``(callee_name, iter_expr)`` tuple for case E
    - ``None`` if the pattern is not recognised
    """
    # A/B — direct comprehension
    if isinstance(arg_value, (ast.ListComp, ast.GeneratorExp)):
        return arg_value

    # C — variable previously assigned a comprehension
    if isinstance(arg_value, ast.Name) and arg_value.id in listcomp_index:
        return listcomp_index[arg_value.id]

    if not isinstance(arg_value, ast.Call):
        return None

    func = arg_value.func
    if not isinstance(func, ast.Name):
        return None

    # D — tuple()/list()/set() wrapping a generator
    if func.id in ("tuple", "list", "set") and arg_value.args:
        inner = arg_value.args[0]
        if isinstance(inner, (ast.ListComp, ast.GeneratorExp)):
            return inner

    # E — map(db_fn, items)
    if func.id == "map" and len(arg_value.args) >= 2:
        fn_arg = arg_value.args[0]
        iter_arg = arg_value.args[1]
        fn_name: str | None = None
        if isinstance(fn_arg, ast.Name):
            fn_name = fn_arg.id
        elif isinstance(fn_arg, ast.Attribute):
            fn_name = fn_arg.attr
        if fn_name:
            return (fn_name, iter_arg)

    return None


def _build_listcomp_index(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, ast.ListComp | ast.GeneratorExp]:
    """Map variable names to the ``ListComp``/``GeneratorExp`` they were assigned.

    Scans the entire function body (including nested ``if``/``try``/``with``
    blocks) for simple assignments of the form::

        tasks = [f(x) for x in items]   # ListComp
        coros = (f(x) for x in items)   # GeneratorExp

    Used to resolve ``gather(*tasks)`` (Variant B) back to the comprehension,
    so the same DB-adjacency check can be applied.  Only the **last** assignment
    to a given name is kept (sufficient for straight-line code).
    """
    index: dict[str, ast.ListComp | ast.GeneratorExp] = {}
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, (ast.ListComp, ast.GeneratorExp)):
                    index[node.targets[0].id] = node.value
    return index


def _target_names(target: ast.expr) -> frozenset[str]:
    """Extract all Name ids from a for-loop target (handles tuples, etc.)."""
    names: set[str] = set()
    for node in ast.walk(target):
        if isinstance(node, ast.Name):
            names.add(node.id)
    return frozenset(names)


def _collect_loop_var_aliases(
    stmts: list[ast.stmt],
    loop_vars: frozenset[str],
) -> frozenset[str]:
    """Expand loop_vars with variables assigned from them in the loop body.

    Handles common aliasing patterns inside loops::

        msg = delivery          → adds "msg"
        key, val = item         → adds "key", "val"
        data = item.copy()      → NOT expanded (method call on item, too risky)

    Two passes handle transitive chains (``a = b; c = a``).
    """
    if not loop_vars:
        return loop_vars
    result = set(loop_vars)
    for _ in range(2):
        for stmt in stmts:
            if not isinstance(stmt, ast.Assign):
                continue
            # Check if RHS references any current result variable (simple Name only).
            rhs_uses = any(
                isinstance(n, ast.Name) and n.id in result
                for n in ast.walk(stmt.value)
            )
            if not rhs_uses:
                continue
            # Only expand for simple RHS (Name, Subscript, Attribute — not calls)
            # to avoid false expansions like ``data = transform(item)`` where data
            # is not really equivalent to the loop var.
            if isinstance(stmt.value, ast.Call):
                continue
            for target in stmt.targets:
                for n in ast.walk(target):
                    if isinstance(n, ast.Name):
                        result.add(n.id)
    return frozenset(result)


def _receiver_name(call: ast.Call) -> str:
    """Return the lowercase receiver variable/attribute name of a method call.

    Examples::

        item.get("x")          → "item"
        self._executor.execute  → "_executor"
        self._alert_service.update → "_alert_service"
    Returns '' for bare function calls (no receiver).
    """
    func = call.func
    if not isinstance(func, ast.Attribute):
        return ""
    receiver = func.value
    if isinstance(receiver, ast.Name):
        return receiver.id.lower()
    if isinstance(receiver, ast.Attribute):
        return receiver.attr.lower()
    return ""


def _is_likely_in_memory_call(call: ast.Call, callee: str) -> bool:
    """True when the indirect call is almost certainly on an in-memory object.

    We suppress false positives caused by name collisions between:
    - Python built-in method names (dict.get, set.update, list.add …)
    - Redis / Cassandra pipeline / batch accumulators (pipe.delete, batch.add)
    - User-defined service methods that happen to share the same name

    Suppression logic (in priority order):

    1. The receiver is a known pipeline/batch accumulator (pipe, batch, tx …):
       commands are queued, not executed; the single I/O is outside the loop.

    2. The callee is in ``_PURE_PYTHON_METHODS`` AND:
       a. The call is a method call (not a bare function).
       b. The receiver is NOT ``self`` (could be a service calling another).
       c. The receiver is NOT in ``_DB_RECEIVER_HINTS``.
       d. The receiver name does NOT contain a service/repository pattern.
    """
    if not isinstance(call.func, ast.Attribute):
        # Bare function call — can't determine receiver; do not suppress.
        return False
    recv = _receiver_name(call)

    # Rule 1: pipeline / batch accumulator receivers are always safe.
    if any(p in recv for p in _PIPELINE_RECEIVERS):
        return True

    # Rule 2: pure-Python method on a non-service, non-DB receiver.
    if callee not in _PURE_PYTHON_METHODS:
        return False
    if recv == "self":
        return False
    if recv in _DB_RECEIVER_HINTS:
        return False
    # Split the receiver name on underscores to get word tokens, then check
    # for exact word matches against service patterns.  This prevents
    # substring false-positives like "handlers" matching "handler".
    recv_tokens = set(recv.split("_"))
    if recv_tokens & _SERVICE_RECEIVER_PATTERNS:
        return False
    return True


def _is_batch_arg_execute(node: ast.Call) -> bool:
    """True when execute() is called with a single batch/pipeline variable.

    Pattern::

        await self._executor.execute(pending_batch)   # ← batch round-trip
        await self._executor.execute(batch)           # ← batch round-trip

    Cassandra/Redis batch objects accumulate statements and send them in a
    single network round-trip.  Calling execute(batch) inside a loop that
    *builds* the batch is not an N+1 — it is a controlled flush (e.g. every
    20 items).  We distinguish this from execute(query, params) which issues
    one query per call.

    Detection: single positional argument, no keyword args, argument is a
    Name whose lowercase form contains a pipeline receiver token.
    """
    if len(node.args) != 1 or node.keywords:
        return False
    arg = node.args[0]
    if not isinstance(arg, ast.Name):
        return False
    arg_lower = arg.id.lower()
    return any(p in arg_lower for p in _PIPELINE_RECEIVERS)


def _is_batch_in_query(node: ast.Call, loop_vars: frozenset[str]) -> bool:
    """True when this queryset call uses the loop variable in a ``__in`` lookup.

    Django's ``field__in=iterable`` lookup fetches ALL matching rows in a
    single SQL ``WHERE field IN (...)`` query.  When the loop variable is the
    iterable, the call is a batch / chunked fetch — NOT an N+1::

        for batch_pks in queryset_in_batches(qs):
            Model.objects.filter(pk__in=batch_pks)   ← one query per batch

    Suppressed: any ``filter``/``exclude``/``get`` keyword where the key ends
    with ``__in`` and the value is (or contains) the loop variable.
    """
    for kw in node.keywords:
        if not kw.arg or not kw.arg.endswith("__in"):
            continue
        for n in ast.walk(kw.value):
            if isinstance(n, ast.Name) and n.id in loop_vars:
                return True
    return False


def _uses_any(call: ast.Call, names: frozenset[str]) -> bool:
    """True if any Name in the call's args/kwargs matches a name in ``names``."""
    for arg in call.args:
        for node in ast.walk(arg):
            if isinstance(node, ast.Name) and node.id in names:
                return True
    for kw in call.keywords:
        if kw.value:
            for node in ast.walk(kw.value):
                if isinstance(node, ast.Name) and node.id in names:
                    return True
    return False


def _receiver_uses_any(call: ast.Call, names: frozenset[str]) -> bool:
    """True if any Name in the RECEIVER chain of a method call is in ``names``.

    Used as a fallback for ORM methods where the receiver IS the data carrier::

        for author in authors:
            author.book_set.all()   # loop var "author" is in receiver, not args

    This is intentionally NOT included in ``_uses_any`` to avoid false positives
    in fan-out patterns like ``for sentinel in sentinels: sentinel.execute_command(cmd)``
    where the receiver IS the loop var but the call is protocol-mandated fan-out,
    not an accidental N+1.  We apply receiver-chain checking only for ORM methods
    that inherently encode the query predicate in the receiver relationship.
    """
    func = call.func
    if not isinstance(func, ast.Attribute):
        return False
    for node in ast.walk(func.value):
        if isinstance(node, ast.Name) and node.id in names:
            return True
    return False


def _get_bodies(stmt: ast.stmt) -> list[list[ast.stmt]]:
    bodies: list[list[ast.stmt]] = []
    for attr in ("body", "orelse", "handlers", "finalbody", "items"):
        val = getattr(stmt, attr, None)
        if isinstance(val, list):
            if val and isinstance(val[0], ast.stmt):
                bodies.append(val)
            elif val and isinstance(val[0], ast.ExceptHandler):
                for handler in val:
                    bodies.append(handler.body)
    return bodies


# ── False-positive heuristic helpers ─────────────────────────────────────────


def _all_module_const_elts(elts: list[ast.expr]) -> bool:
    """True when every element looks like a module-level configuration constant.

    More permissive than ``_all_enum_like``: accepts tuples that contain
    integers, because version-check tuples like ``(13,)`` are legitimate
    constant data, not user IDs.  The key invariant is that the structure
    is *statically known*: every element is a compile-time constant or
    attribute, possibly wrapped in a tuple.

    Accepted:
    - String constants:            ``"citext"``, ``"hstore"``
    - Integer constants:           ``13``, ``0``
    - Attribute access:            ``Status.OPEN``
    - Tuple of any of the above:   ``("citext", (13,))``, ``((2, 0),)``

    Rejected:
    - ``ast.Name`` nodes (could be a runtime variable)
    - Arbitrary expressions (function calls, subscripts, etc.)
    """
    if not elts:
        return False
    for elt in elts:
        if isinstance(elt, ast.Constant):
            continue  # any scalar constant is fine
        if isinstance(elt, ast.Attribute):
            continue  # enum member or dotted constant
        if isinstance(elt, ast.Tuple):
            # Recursively validate nested tuple elements.
            if not _all_module_const_elts(elt.elts):
                return False
            continue
        return False
    return True


def _all_enum_like(elts: list[ast.expr]) -> bool:
    """True when every element looks like a fixed configuration constant.

    We accept:
    - String literals:        ``"OPEN"``, ``"WAITING"``
    - Attribute access:       ``Status.OPEN``, ``Status.OPEN.value`` (enum members)
    - Tuples of the above:    ``("src_key", "dst_key")`` — field-mapping pairs
    - Pair-variable tuples:   ``(self.attr, local_var)`` — when the outer list
      has ≤ 2 elements, each a tuple whose elements are Attribute or Name nodes.
      This covers the SQLAlchemy pattern:
          for joincond, collection in [
              (self.primaryjoin, sync_pairs),
              (self.secondaryjoin, secondary_sync_pairs),
          ]:
      where the 2 tuples are hardcoded pairs of ORM objects — not user IDs.

    We reject integers, floats, and bare Name variables at the top level,
    because those could represent user-data IDs (e.g. ``[1, 2, 3]`` in a
    test fixture) that in production would be an unbounded list.

    Pair-variable tuples (Name nodes) are only accepted when the containing
    list has ≤ 2 elements AND every element is a tuple of Attribute/Name —
    both conditions together make it extremely unlikely to be user-data-driven.
    """
    if not elts:
        return False

    # Check for the "pair-variable" pattern first: all elements are tuples
    # of (Attribute | Name) nodes, and the list is small (≤ 2).  This covers
    # patterns like [(self.primaryjoin, sync_pairs), (self.secondaryjoin, ...)].
    if len(elts) <= 2 and all(
        isinstance(elt, ast.Tuple)
        and elt.elts
        and all(isinstance(e, (ast.Attribute, ast.Name)) for e in elt.elts)
        for elt in elts
    ):
        return True

    for elt in elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            continue  # string literal — always a fixed value
        if isinstance(elt, ast.Attribute):
            continue  # enum member or dotted constant
        # Tuple of string/attribute constants: ("field_a", "field_b")
        if isinstance(elt, ast.Tuple) and elt.elts and all(
            isinstance(e, (ast.Constant, ast.Attribute)) for e in elt.elts
        ):
            continue
        return False
    return True


def _is_constant_n_iter(
    iter_expr: ast.expr,
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    max_n: int = _MAX_SMALL_N_INDIRECT,
    module_consts: dict[str, ast.List | ast.Tuple] | None = None,
) -> bool:
    """Return True when ``iter_expr`` is provably a small, constant-sized set.

    Used both by ``_is_constant_n_loop`` (for ``for`` loops) and by the
    ``asyncio.gather`` comprehension check (for list comprehension generators),
    so the suppression logic is defined only once.

    We detect seven cases:

    1. Direct list/tuple literal with enum-like elements only:
       ``["OPEN", "WAITING"]``, ``[Status.A, Status.B]``.

    2. ``range(K)`` with compile-time constant ``K ≤ max_n``.

    3. Named variable assigned to an enum-like literal in the same function
       scope::

           statuses = [ConversationStatus.OPEN, ConversationStatus.WAITING]
           for status in statuses:  # resolved to case 1

    4. ALL_CAPS or _ALL_CAPS variable name → module-level constant by convention.

    5. ``<obj>.<config_attr>`` — configuration / schema attribute access.

    6. Wrapped call chains ending in a config-attribute variable.

    7. Named variable whose definition is a module-level constant list/tuple
       of enum-like elements.  Covers patterns like::

           _extensions = [("citext", (13,)), ("hstore", (13,))]
           for ext, ver in _extensions: conn.execute(...)

       where ``_extensions`` is not assigned inside the function but at
       module scope.  ``module_consts`` is populated by ``CallGraph._collect``
       and passed through ``_is_constant_n_loop``.

    Integer elements are NOT accepted (``[1, 2, 3]`` could be user IDs).
    ``max_n`` is caller-supplied so direct/indirect calls use different budgets.
    """
    # Case 1: direct literal.
    if isinstance(iter_expr, (ast.List, ast.Tuple)):
        elts = iter_expr.elts
        return len(elts) <= max_n and _all_enum_like(elts)

    # Case 2: range(K) with a compile-time constant K.
    if (
        isinstance(iter_expr, ast.Call)
        and isinstance(iter_expr.func, ast.Name)
        and iter_expr.func.id == "range"
        and iter_expr.args
        and isinstance(iter_expr.args[0], ast.Constant)
        and isinstance(iter_expr.args[0].value, int)
    ):
        return iter_expr.args[0].value <= max_n

    # Cases 3, 4 & 7: named variable.
    if isinstance(iter_expr, ast.Name):
        iter_name = iter_expr.id

        # Case 4: ALL_CAPS / _ALL_CAPS → Python module-level constant convention.
        bare = iter_name.lstrip("_")
        if bare and bare.isupper():
            return True

        # Case 3: scan the function scope for an assignment of that name.
        for node in ast.walk(fn_node):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == iter_name
                        and isinstance(node.value, (ast.List, ast.Tuple))
                        and len(node.value.elts) <= max_n
                        and _all_enum_like(node.value.elts)
                    ):
                        return True

        # Case 7: module-level constant (not visible inside the function body).
        # Examples: ``_extensions = [("citext", (13,)), ("hstore", (13,))]``
        # The list itself can contain tuples mixing strings and sub-tuples of
        # ints (version checks), so we accept Tuple elements here.
        if module_consts and iter_name in module_consts:
            mod_val = module_consts[iter_name]
            if len(mod_val.elts) <= max_n and _all_module_const_elts(mod_val.elts):
                return True

    # Case 5: ``<obj>.<config_attr>`` or ``<obj>.<config_attr>.items()`` —
    # configuration / schema attributes are never user-data collections.
    # We recognise both ``self.<attr>`` and external-object accesses like
    # ``base_mapper._sorted_tables.items()`` (SQLAlchemy ORM persistence).
    # The receiver must be a simple Name (not a chained call).
    def _is_config_attr(name: str) -> bool:
        """True when ``name`` looks like an instance configuration attribute.

        Handles compound names like ``sqlite_extensions`` by checking each
        underscore-separated token against ``_CONFIG_SELF_ATTRS`` (both exact
        and singular forms), in addition to the full attribute name.
        """
        n = name.lower().lstrip("_")
        if n in _CONFIG_SELF_ATTRS or n.rstrip("s") in _CONFIG_SELF_ATTRS:
            return True
        # Compound attribute names: "sqlite_extensions" → check "extensions" token
        for token in n.split("_"):
            if token and (token in _CONFIG_SELF_ATTRS or token.rstrip("s") in _CONFIG_SELF_ATTRS):
                return True
        return False

    # Direct attribute:   for ext in self.extensions: ...
    #                     for table in base_mapper._sorted_tables: ...
    if (
        isinstance(iter_expr, ast.Attribute)
        and isinstance(iter_expr.value, ast.Name)
        and _is_config_attr(iter_expr.attr)
    ):
        return True
    # Method call on a config attribute:
    #   for k, v in self.pragmas.items(): ...
    #   for table, mapper in base_mapper._sorted_tables.items(): ...
    #   for table in reversed(list(table_to_mapper.keys())): ...
    if (
        isinstance(iter_expr, ast.Call)
        and isinstance(iter_expr.func, ast.Attribute)
        and iter_expr.func.attr in ("items", "keys", "values")
        and isinstance(iter_expr.func.value, ast.Attribute)
        and isinstance(iter_expr.func.value.value, ast.Name)
        and _is_config_attr(iter_expr.func.value.attr)
    ):
        return True

    # Case 6: ``reversed(list(<config_attr>.keys()))`` — SQLAlchemy deletion order.
    # Also: ``for x in var`` where ``var`` was built from a config-attr collection.
    #
    # Sub-case 6a: iter is a wrapped call chain ending in ``<var>.keys()``:
    #   ``for table in reversed(list(table_to_mapper.keys()))``
    #   where ``table_to_mapper = base_mapper._sorted_tables``
    #
    # Sub-case 6b: iter is a plain variable assigned from a config-attr
    # list comprehension:
    #   ``mappers_to_run = [(t, m) for t, m in base_mapper._sorted_tables.items()]``
    #   ``for table, super_mapper in mappers_to_run:``
    #
    # Implementation note: we peel up to 4 wrapping calls (reversed/list/tuple)
    # and then check whether the innermost expression is ``<var>.keys()`` where
    # ``<var>`` was assigned from a config attribute.  We must check the
    # ``<var>.method()`` branch BEFORE checking for positional args because
    # ``.keys()`` / ``.values()`` take no args (``inner.args == []``).

    def _assigned_from_config_attr(var_name: str) -> bool:
        """True if ``var_name`` was assigned from a config attribute or a
        list comprehension whose generator iterates over a config attribute."""
        for assign_node in ast.walk(fn_node):
            if not isinstance(assign_node, ast.Assign):
                continue
            for tgt in assign_node.targets:
                if not (isinstance(tgt, ast.Name) and tgt.id == var_name):
                    continue
                val = assign_node.value
                # Direct attribute assignment: var = obj._sorted_tables
                if isinstance(val, ast.Attribute) and _is_config_attr(val.attr):
                    return True
                # ListComp from a config attr:
                #   var = [(t, m) for t, m in obj._sorted_tables.items() ...]
                if isinstance(val, ast.ListComp) and val.generators:
                    gen_iter = val.generators[0].iter
                    # obj.<config_attr>.items()
                    if (
                        isinstance(gen_iter, ast.Call)
                        and isinstance(gen_iter.func, ast.Attribute)
                        and gen_iter.func.attr in ("items", "keys", "values")
                        and isinstance(gen_iter.func.value, ast.Attribute)
                        and _is_config_attr(gen_iter.func.value.attr)
                    ):
                        return True
                    # obj.<config_attr>  (no method call)
                    if (
                        isinstance(gen_iter, ast.Attribute)
                        and _is_config_attr(gen_iter.attr)
                    ):
                        return True
        return False

    # Sub-case 6a: peeling call wrappers to reach <var>.keys()
    if isinstance(iter_expr, ast.Call):
        inner: ast.expr = iter_expr
        for _ in range(4):  # max 4 layers of wrapping
            if not isinstance(inner, ast.Call):
                break
            func = inner.func

            # Check the .keys()/.values()/.items() branch first — these take
            # no positional args so we must NOT guard on ``inner.args``.
            if (
                isinstance(func, ast.Attribute)
                and func.attr in ("keys", "values", "items")
                and isinstance(func.value, ast.Name)
            ):
                if _assigned_from_config_attr(func.value.id):
                    return True
                break  # var not a config attr assignment — stop peeling

            # Peel wrapper calls: reversed(...) / list(...) / tuple(...)
            if (
                isinstance(func, ast.Name)
                and func.id in ("reversed", "list", "tuple")
                and inner.args
            ):
                inner = inner.args[0]
            else:
                break  # unknown structure — stop peeling

    # Sub-case 6b: plain variable name whose assignment derives from config attr
    if isinstance(iter_expr, ast.Name):
        if _assigned_from_config_attr(iter_expr.id):
            return True

    return False


def _is_constant_n_loop(
    loop: ast.For | ast.AsyncFor,
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    max_n: int = _MAX_SMALL_N_INDIRECT,
    module_consts: dict[str, ast.List | ast.Tuple] | None = None,
) -> bool:
    """Return True when the ``for``-loop's N is provably small and constant.

    Thin wrapper around ``_is_constant_n_iter`` that extracts the loop iterator.
    """
    return _is_constant_n_iter(loop.iter, fn_node, max_n, module_consts=module_consts)


def _is_pagination_loop(loop: ast.For | ast.AsyncFor) -> bool:
    """Return True when the loop looks like a cursor-pagination driver.

    Pattern::

        for _ in range(max_iterations):
            rows = await fetch_page(cursor=cursor)
            if not rows:
                break
            ...

    The loop variable being ``_`` (or ``__``) combined with iterating over
    ``range(...)`` is a universal pagination idiom — not a data-driven N+1.
    """
    if not (
        isinstance(loop.iter, ast.Call)
        and isinstance(loop.iter.func, ast.Name)
        and loop.iter.func.id == "range"
    ):
        return False
    return _is_throwaway_target(loop.target)


def _is_throwaway_target(target: ast.expr) -> bool:
    """True if the loop target is the conventional unused-variable name."""
    return isinstance(target, ast.Name) and target.id in ("_", "__")


def _has_early_exit_after_db(loop: ast.For | ast.AsyncFor) -> bool:
    """Return True if the loop short-circuits with return/break after each DB call.

    Pattern::

        for variant in phone_variants:
            row = await db_call(variant)
            if row:
                return row   ← exits on first result

    In practice this means the loop executes 1-2 iterations rather than N.
    We downgrade the severity to INFO rather than suppressing entirely,
    because the pattern still sends sequential queries on cache-miss paths.
    """
    for stmt in loop.body:
        # Direct return/break at top level of body.
        if isinstance(stmt, (ast.Return, ast.Break)):
            return True
        # if <cond>: return / break
        if isinstance(stmt, ast.If):
            for sub in stmt.body:
                if isinstance(sub, (ast.Return, ast.Break)):
                    return True
    return False


def _is_while_retry_loop(loop: ast.While) -> bool:
    """Return True when the ``while True`` loop is a retry/backoff pattern.

    Retry loops repeat the SAME operation until it succeeds, unlike consumer
    loops that process a DIFFERENT item on each iteration.  We identify retries
    by the presence of a ``return`` or ``break`` statement at the top level or
    inside an immediate ``try``/``if`` block.  Either exits or escapes the
    loop as soon as the operation succeeds.

    Patterns suppressed::

        while True:                          # lock acquire retry
            try:
                return await do_operation()
            except SomeError:
                await asyncio.sleep(delay)

        while True:                          # success-break (WATCH/MULTI/EXEC)
            try:
                pipe.watch(key)
                ...
                break                        ← exits on success
            except WatchError:
                continue                     ← retries on conflict

        while True:                          # bounded monitoring loop
            try:
                retpid, _, _ = wait()
                break                        ← exits when horse finishes
            except HorseMonitorTimeout:
                maintain_heartbeats(job)     ← keep-alive, then retry

    These should be SUPPRESSED rather than flagged — they are definitively not
    per-message consumer N+1 patterns.
    """
    for stmt in loop.body:
        # Direct ``return`` at the top level → immediate exit on success.
        if isinstance(stmt, ast.Return):
            return True
        # ``if <cond>: return`` → conditional success exit.
        # NOTE: ``if <cond>: break`` is intentionally NOT included here because
        # consumer loops commonly use ``if msg is None: break`` to stop iteration.
        # Only ``return`` in an if body reliably signals a retry-or-succeed pattern.
        if isinstance(stmt, ast.If):
            for sub in stmt.body:
                if isinstance(sub, ast.Return):
                    return True
        # ``try: ...; break/return ... except: retry`` pattern.
        # ``break`` inside a ``try`` block means "success, exit the retry loop."
        # This covers WATCH/MULTI/EXEC patterns (Redis optimistic locking):
        #   while True:
        #       try:
        #           pipe.watch(key); ...; pipe.execute(); break  ← success
        #       except WatchError:
        #           continue  ← retry
        # and bounded monitoring loops:
        #   while True:
        #       try:
        #           retpid = wait(); break  ← done when horse exits
        #       except Timeout:
        #           maintain_heartbeats(job)  ← keep-alive, then retry
        if isinstance(stmt, ast.Try):
            for sub in stmt.body:
                if isinstance(sub, (ast.Return, ast.Break)):
                    return True
    return False


def _is_background_fn(name: str) -> bool:
    """Return True when the function name suggests an offline maintenance job.

    Functions whose names contain tokens like ``cleanup``, ``migrate``,
    ``backfill``, ``repair``, etc. are expected to iterate row-by-row because
    they process historical data, not live request traffic.  Their per-row
    latency has no impact on end-user response times.

    We split by ``_`` to get word tokens and check exact membership, avoiding
    substring false-positives: e.g. ``get_data_async`` must NOT match on
    ``sync`` even though ``async`` contains it.

    We also check singularised token forms so that ``_refresh_schemas``
    (token: ``schemas``) matches ``schema`` in the fragment set, and
    ``drop_views`` (token: ``views``) would match ``view`` if added.

    We downgrade these to INFO rather than suppress, so they still appear in
    reports but with appropriate context.
    """
    tokens = set(name.lower().split("_"))
    if tokens & _BACKGROUND_FN_FRAGMENTS:
        return True
    # Singularise tokens: "schemas" → "schema", "chunks" → "chunk", etc.
    return bool({t.rstrip("s") for t in tokens if t} & _BACKGROUND_FN_FRAGMENTS)
