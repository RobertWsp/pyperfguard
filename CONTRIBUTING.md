# Contributing to pyperfguard

## Setup

```bash
git clone https://github.com/RobertWsp/pyperfguard
cd pyperfguard
pip install -e ".[dev]"
pytest   # must pass before you start
```

## Project layout

```
src/pyperfguard/
├── core/          Finding, Rule, Registry, Config, Severity — never import from subpackages
├── ast_engine/    Static analysis: AstEngine, PyperfVisitor, AstContext, CallGraph
├── runtime_engine/ RuntimeEngine, Scope, EventBus, Patcher protocol
├── rules/         Built-in AST rules (PKN001–PKN025)
├── detectors/     Runtime N+1 detectors (PKN100, PKN101)
├── patchers/      Driver monkey-patchers
├── fingerprint/   Query normalization (SQL, CQL, Mongo)
├── reporters/     terminal, json, sarif
├── integrations/  FastAPI middleware
└── _bootstrap/    sitecustomize.py installer
tests/
├── rules/         Per-rule unit tests
├── e2e/           End-to-end fixture-based tests
└── test_*.py      Engine, reporter, CLI, config tests
```

## Adding a rule

1. Create `src/pyperfguard/rules/my_rule.py`:

```python
import ast
from typing import Iterable
from pyperfguard.ast_engine.context import AstContext
from pyperfguard.core.finding import Finding
from pyperfguard.core.rule import RuleScope
from pyperfguard.core.severity import Severity

class MyRule:
    id = "PKN0XX"         # next available ID
    name = "my-rule"      # kebab-case, unique
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types = (ast.Call,)

    def check(self, node: ast.AST, ctx: AstContext) -> Iterable[Finding]:
        ...
```

2. Register in `pyproject.toml` under `[project.entry-points."pyperfguard.rules"]`.

3. Add tests in `tests/rules/test_my_rule.py` — must cover:
   - At least one "flagged" case
   - At least one "not flagged" case (the fix pattern)
   - Edge cases for guard clauses

4. Add the rule to the table in `README.md`.

## Rule guidelines

- Rules must be stateless and side-effect-free (called once per matching node per file).
- Use `ctx.in_loop()`, `ctx.enclosing_loop()`, `ctx.in_async_function()` — don't re-walk ancestors.
- `ctx.source_segment(node)` gives the snippet for up to 200 chars.
- Provide a `Fix` with a `description` explaining what to change.
- Keep `message` under 300 chars. Use RST double-backticks for code: `` ``foo()`` ``.
- Set `short_message` when the first sentence of `message` isn't good enough for compact output.
- Inline suppression via `# noqa: PKNXXX` is handled by the engine automatically.

## Running checks

```bash
pytest                  # full suite (600+ tests, ~2s)
pytest tests/rules/     # rules only
ruff check src/ tests/
ruff format src/ tests/
mypy src/
```

## Pull request checklist

- [ ] `pytest` passes
- [ ] `ruff check` passes
- [ ] `mypy` passes (strict mode)
- [ ] New rule: entry point registered in `pyproject.toml`
- [ ] New rule: README table updated
- [ ] Tests cover the flagged case, the fix case, and at least one edge case
- [ ] No new `# type: ignore` without a comment explaining why

## Commit style

```
PKN0XX: add rule for <short description>
fix: <what was wrong> in <where>
test: <what is tested>
docs: <what was updated>
```

One logical change per commit. No "WIP" or "misc" commits in PRs.
