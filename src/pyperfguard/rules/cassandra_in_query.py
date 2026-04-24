"""PKN012 — CQL ``IN`` clause with parametrised binding (potential multi-partition).

    # RISKY — coordinator does scatter-gather across N partition owners
    ids = [u1, u2, …, u200]
    session.execute("SELECT * FROM users WHERE id IN %s", [tuple(ids)])

    # BETTER — token-aware parallel queries; each goes to the correct replica
    stmt = session.prepare("SELECT * FROM users WHERE id = ?")
    results = execute_concurrent_with_args(session, stmt, [(i,) for i in ids])

When ``id`` is a partition key, ``IN (…)`` forces the *coordinator* node to
scatter the request across N replica groups and gather the responses.  The
coordinator becomes a bottleneck and a SPOF for that query.

Executing N parallel ``SELECT … WHERE id = ?`` with ``execute_concurrent``
and token-aware routing sends each sub-query **directly** to the owning
replica, eliminating the coordinator overhead.

Note: ``IN`` on a *clustering* key within a single partition is fine — this
rule fires on heuristic match (parametrised binding with a variable-size
argument) and may have false positives when the ``IN`` column is a CK.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding, Fix
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

# Matches IN followed by a parametrised placeholder (%s, ?, :name, %(name)s).
# The opening paren is optional — CQL drivers accept "IN %s" without parens
# when passing a tuple directly (cassandra-driver legacy style).
_IN_PARAM_RE = re.compile(
    # Named params like :user_id end at a word boundary; RST :role:` won't match
    # because \b lands between the last letter and ':', then (?!:) rejects ':'.
    # Backtracking can't shorten the match further since partial prefixes don't
    # end at word boundaries (e.g. ':fil' in ':file:' is not at \b).
    r"\bIN\s*(?:\(\s*)?(?:\?|%s|%\([^)]+\)s|:[a-z_]+\b(?!:))",
    re.IGNORECASE,
)

# Require at least two DISTINCT CQL/SQL keywords so we don't flag English prose like
# "Please move the object into the main module body to use migrations." which has
# only one SQL word ("into") and happens to have "in %s" from a format placeholder.
# Real SQL/CQL strings always have at least two structural keywords (SELECT+FROM,
# DELETE+FROM, WHERE+FROM, etc.).
_CQL_KEYWORD_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|CREATE|DROP|INTO|TABLE|KEYSPACE)\b",
    re.IGNORECASE,
)


def _has_enough_cql_keywords(text: str) -> bool:
    """Return True if ``text`` contains at least two distinct SQL/CQL keywords."""
    matches = set(m.lower() for m in _CQL_KEYWORD_RE.findall(text))
    return len(matches) >= 2


class CassandraInQueryRule:
    id = "PKN012"
    name = "cassandra-in-multi-partition"
    severity = Severity.INFO
    scope = RuleScope.AST
    node_types: tuple[type[ast.AST], ...] = (ast.Constant,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Constant)
        # Skip Constant children of JoinedStr (handled by parent)
        if isinstance(ctx.parent_node(), ast.JoinedStr):
            return
        if not isinstance(node.value, str):
            return
        if "IN" not in node.value.upper():
            return
        # Skip docstrings — CQL examples in docstrings are documentation, not live queries.
        if self._is_docstring(ctx):
            return
        if not _has_enough_cql_keywords(node.value):
            return
        if not _IN_PARAM_RE.search(node.value):
            return
        yield Finding.from_node(
            rule_id=self.id,
            message=(
                "CQL ``IN`` clause with a parametrised binding may perform a "
                "multi-partition scatter-gather via the coordinator. "
                "If the ``IN`` column is a partition key, use "
                "``execute_concurrent_with_args`` with individual ``WHERE pk = ?`` "
                "queries and token-aware routing for better performance."
            ),
            node=node,
            ctx=ctx,
            severity=self.severity,
            fix=Fix(
                description=(
                    "Replace ``IN %s`` with parallel ``WHERE pk = ?`` queries via "
                    "``cassandra.concurrent.execute_concurrent_with_args``."
                )
            ),
        )

    @staticmethod
    def _is_docstring(ctx: AstContext) -> bool:
        """True if the Constant is a documentation string, not a live query.

        Covers two cases:
        1. Classic docstring: first statement of a function/class/module body.
        2. Informal module-level doc: any standalone string expression at module
           level that isn't the first statement. These are never live queries —
           Python executes them but discards the value; they're used for ad-hoc
           documentation (e.g. cassandra/query.py ValueSequence description).
        """
        ancestors = ctx.ancestors
        if len(ancestors) < 2:
            return False
        parent = ancestors[-1]
        grandparent = ancestors[-2]
        if not isinstance(parent, ast.Expr):
            return False
        # Any standalone string at module level is documentation, not a live query.
        if isinstance(grandparent, ast.Module):
            return True
        # Classic docstring: first statement in a function or class body.
        if isinstance(grandparent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = grandparent.body
            return bool(body) and body[0] is parent
        return False
