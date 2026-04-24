# pyperfguard

**Agnostic, pluggable Python performance linter — AST + runtime hybrid.**

Catches anti-patterns that profilers miss and unit tests never exercise: N+1 queries that only appear under load, blocking calls that starve your event loop, Cassandra patterns that look fine locally but destroy latency at scale.

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/pyperfguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/RobertWsp/pyperfguard/actions/workflows/ci.yml/badge.svg)](https://github.com/RobertWsp/pyperfguard/actions/workflows/ci.yml)

---

## Why pyperfguard?

Performance bugs in Python are rarely caught by tests. They hide in production patterns:

- **N+1 queries** look correct in unit tests with mocked databases, but fire one query per loop iteration under real load.
- **Blocking calls in async code** (`time.sleep`, `requests.get`) pass all tests locally but starve the event loop in production.
- **Cassandra `ALLOW FILTERING`** returns fast on a 100-row dev cluster, but scans every partition at scale.
- **O(n²) string concatenation** (`+=` in a loop) is undetectable by linters that only check types.

**pyperfguard was built specifically to be used alongside AI coding assistants.** When an LLM writes or reviews code, it produces context fast — but it doesn't run the code under load. pyperfguard runs statically (AST pass, no execution) and emits compact, structured output designed to fit inside an AI tool's context window:

```
src/views.py:135:16 PKN009[W] Blocking call requests.get() inside async def.
src/service.py:52:9 PKN010[E] CQL query contains ALLOW FILTERING.
```

Each finding is one line: file, line, column, rule ID, severity, short message. No noise, no prose. Feed it directly to your AI assistant's context and ask it to fix what pyperfguard found — the loop closes automatically.

The compact JSON format (`--format json`) is optimized for the same use case:

```json
{"findings": [{"rule_id": "PKN010", "sev": "E", "file": "src/service.py", "line": 52, "col": 9, "msg": "CQL query contains ALLOW FILTERING."}]}
```

No nulls. No schema metadata. No redundant fields. Just the signal the model needs.

> **Typical flow:** `pyperfguard analyze src/ --format json | <pipe to LLM>` → model sees all findings in one context window, generates targeted fixes.

---

## What it detects

| Rule | ID | Severity | Category |
|------|----|----------|----------|
| Mutable default argument | PKN001 | warning | correctness |
| Bare `except` | PKN002 | warning | correctness |
| String `+=` in loop (O(n²)) | PKN003 | warning | performance |
| `open()` inside loop | PKN004 | warning | performance |
| `re.compile()` inside loop | PKN005 | warning | performance |
| `copy.deepcopy()` inside loop | PKN006 | warning | performance |
| `datetime.now()` inside loop | PKN007 | info | performance |
| `await` in `for` loop (no gather) | PKN008 | warning | async |
| Blocking call in `async def` | PKN009 | warning | async |
| Cassandra `ALLOW FILTERING` | PKN010 | **error** | cassandra |
| `session.prepare()` in loop | PKN011 | warning | cassandra |
| CQL `IN` multi-partition scatter | PKN012 | info | cassandra |
| `BatchStatement.add()` in loop | PKN013 | warning | cassandra |
| Heavy `import` inside function | PKN014 | info | performance |
| `list()` wrapping a `for` iterable | PKN015 | info | style |
| `try/except` inside hot loop | PKN016 | info | performance |
| `@lru_cache` on instance method | PKN017 | warning | correctness |
| Late-binding closure in loop | PKN018 | warning | correctness |
| `list.append` → comprehension | PKN019 | info | style |
| `for x in list(iter)` redundant | PKN020 | warning | performance |
| `dict` loop → dict comprehension | PKN021 | info | style |
| `list` literal as `for` iterable | PKN022 | info | style |
| `isinstance(x, [A, B])` → tuple | PKN023 | warning | correctness |
| Blocking Cassandra call in async | PKN024 | **error** | cassandra |
| Sequential `await` → `gather` | PKN025 | warning | async |
| Inter-procedural N+1 (CallGraph) | PKN102 | info | n+1 |

Runtime rules (require instrumentation):

| Rule | ID | Severity | What it watches |
|------|----|----------|----------------|
| N+1 query detector | PKN100 | warning | SQL / CQL / Mongo fingerprints per scope |
| Execution-graph N+1 | PKN101 | warning | DB call stacks per request |

---

## Quick start

```bash
pip install pyperfguard
pyperfguard analyze src/
```

```
src/views.py:66:50 PKN001[W] Function 'build_filter_params' uses a mutable default argument.
src/views.py:114:9 PKN003[W] String concatenation with += inside a loop is O(n²).
src/views.py:135:16 PKN009[W] Blocking call requests.get() inside async def blocks the event loop.

3 findings (3W)
```

Filter by rule or severity:

```bash
pyperfguard analyze src/ --select PKN010 PKN011          # only Cassandra rules
pyperfguard analyze src/ --ignore PKN019 PKN021          # skip style hints
pyperfguard analyze src/ --min-severity warning          # suppress info
pyperfguard analyze src/ --format sarif > findings.sarif # SARIF for GitHub / VS Code
pyperfguard analyze src/ --format json                   # compact JSON for LLM pipelines
pyperfguard analyze src/ --verbose                       # full message + snippet + fix
```

---

## Output formats

**Compact (default)** — one line per finding, relative paths, short message. Optimized for LLM consumption and CI pipelines.

```
src/cassandra_service.py:52:9  PKN010[E] CQL query contains ALLOW FILTERING.
src/cassandra_service.py:89:20 PKN011[W] session.prepare() called inside a loop.
src/cassandra_service.py:146:13 PKN013[W] BatchStatement.add() called inside a loop.

12 findings (4E 4I 4W)
```

**Verbose** (`--verbose` / `-v`) — full message + code snippet + fix description.

**JSON compact** (`--format json`) — LLM-optimized minimal dict, no nulls, no schema overhead:

```json
{
  "findings": [
    {"rule_id": "PKN010", "sev": "E", "file": "src/service.py", "line": 52, "col": 9, "msg": "CQL query contains ALLOW FILTERING."}
  ]
}
```

**JSON verbose** (`--format json --verbose`) — full schema with location spans, snippets, fix descriptions, severity values.

**SARIF** (`--format sarif`) — [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for GitHub Code Scanning, VS Code SARIF Viewer, and any SARIF-compatible tool.

---

## Runtime instrumentation

For N+1 detection that works without source code changes, instrument your app at the boundary:

```python
from pyperfguard.runtime_engine.profile import profile

# Context manager — instruments one logical unit of work
with profile(name="list_posts") as session:
    posts = Post.objects.filter(active=True)
    for post in posts:
        _ = post.author.name  # N+1 — each iteration fires a new query

for finding in session.findings:
    print(finding.message)
```

**Auto-instrumentation via sitecustomize** — instruments the entire process at startup:

```bash
pyperfguard bootstrap install   # writes hook to sitecustomize.py
PYPERFGUARD_AUTO=1 python app.py
pyperfguard bootstrap uninstall # removes the hook
```

**FastAPI middleware**:

```python
from fastapi import FastAPI
from pyperfguard.integrations.fastapi import PyperfguardMiddleware

app = FastAPI()
app.add_middleware(PyperfguardMiddleware)
```

Each request becomes a scope. N+1 findings appear in `X-Pyperfguard-Findings` response headers (dev mode) and are forwarded to the configured reporter.

**Supported drivers** (auto-patched when installed):

| Driver | What's patched |
|--------|---------------|
| SQLAlchemy (Core + ORM) | `execute`, `cursor.execute` |
| Cassandra Python Driver | `session.execute`, `session.execute_async` |
| PyMongo | `Collection.find`, `find_one`, `aggregate` |
| Any DB-API 2.0 driver | `cursor.execute` via `DBAPIPatcher` |

---

## Configuration

`pyproject.toml`:

```toml
[tool.pyperfguard]
select  = ["PKN"]        # rule prefixes or exact IDs to run (default: all PKN)
ignore  = ["PKN019", "PKN021"]   # exact IDs or prefixes to skip
exclude = ["**/migrations/**", "**/.venv/**"]
min_severity = "warning" # "error" | "warning" | "info" | "hint"
verbose = false          # true = full message + snippet in all reporters

[tool.pyperfguard.runtime]
enabled       = false    # opt in to runtime instrumentation
sampling_rate = 1        # 1 = every call, N = 1-in-N sampling

[tool.pyperfguard.report]
format = "terminal"      # terminal | json | sarif
```

### Inline suppression

```python
handlers.append(lambda: i)           # noqa: PKN018
session.execute(ALLOW_FILTER_QUERY)  # noqa: PKN010
result = []; for x in data: result.append(x)  # noqa
```

---

## Plugin API

Rules, reporters, and patchers are all loaded via `importlib.metadata` entry points — the same channel used by built-ins, so third-party plugins are first-class.

### Custom rule

```python
# my_pkg/rules.py
import ast
from pyperfguard.core.finding import Finding
from pyperfguard.core.severity import Severity
from pyperfguard.core.rule import RuleScope

class NoPrintRule:
    id = "MYR001"
    name = "no-print"
    severity = Severity.WARNING
    scope = RuleScope.AST
    node_types = (ast.Call,)

    def check(self, node, ctx):
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            yield Finding.from_node(
                rule_id=self.id,
                message="Use logging instead of print().",
                node=node, ctx=ctx, severity=self.severity,
            )
```

Register in `pyproject.toml`:

```toml
[project.entry-points."pyperfguard.rules"]
no_print = "my_pkg.rules:NoPrintRule"
```

### Custom patcher (runtime)

```python
# my_pkg/patchers.py
from pyperfguard.runtime_engine.patcher import Patcher

class MyDriverPatcher:
    def install(self, emit) -> None:
        import mydriver
        original = mydriver.execute

        def patched(query, *a, **kw):
            emit(kind="mydriver", fingerprint=str(query))
            return original(query, *a, **kw)

        mydriver.execute = patched

    def uninstall(self) -> None:
        pass  # restore originals
```

```toml
[project.entry-points."pyperfguard.patchers"]
mydriver = "my_pkg.patchers:MyDriverPatcher"
```

---

## Architecture

```
src/pyperfguard/
├── core/              Finding · Location · Fix · Rule · Registry · Config · Severity
├── ast_engine/        AstEngine · PyperfVisitor · AstContext · CallGraph (PKN102)
├── runtime_engine/    RuntimeEngine · Scope · EventBus · Patcher protocol · profile()
├── rules/             25 built-in AST rules (PKN001–PKN025)
├── detectors/         NPlusOneDetector (PKN100) · ExecutionGraphN1Detector (PKN101)
├── patchers/          SQLAlchemy · Cassandra · PyMongo · DB-API 2.0
├── fingerprint/       SQL · CQL · Mongo query normalization
├── reporters/         terminal · json · sarif
├── integrations/      FastAPI ASGI middleware
├── _bootstrap/        sitecustomize.py auto-instrumentation installer
├── plugins.py         Entry-point discovery
└── cli.py             CLI entrypoint
```

**Two analysis passes:**

1. **AST pass** — `PyperfVisitor` walks each file, dispatches nodes to registered rules (O(rules-for-this-node-type) per node, not O(all-rules)). Rules are isolated: a crash in one rule never aborts analysis of a file.

2. **CallGraph pass** (PKN102) — inter-procedural 3-phase analysis: collect function definitions → BFS-propagate DB-adjacency → detect loops calling DB-adjacent callees across file boundaries.

**Runtime pipeline:**

```
driver call → Patcher → EventBus → Scope.record() → Detector.evaluate() → Finding
```

Scope propagates via `contextvars` (PEP 567) — automatically follows asyncio tasks, no manual threading.

---

## CI integration

**GitHub Actions:**

```yaml
- name: Run pyperfguard
  run: pyperfguard analyze src/ --format sarif --min-severity warning > findings.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: findings.sarif
```

**pre-commit:**

```yaml
repos:
  - repo: local
    hooks:
      - id: pyperfguard
        name: pyperfguard
        entry: pyperfguard analyze
        args: [src/, --min-severity, warning]
        language: system
        pass_filenames: false
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | No findings (or all below `--min-severity`) |
| `1` | At least one `ERROR`-severity finding |

Override with `--exit-zero` to always exit `0` (useful in CI annotation-only mode).

---

## Development

```bash
git clone https://github.com/RobertWsp/pyperfguard
cd pyperfguard
pip install -e ".[dev]"
pytest              # 600+ tests
ruff check src/
mypy src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## License

MIT — see [LICENSE](LICENSE).
