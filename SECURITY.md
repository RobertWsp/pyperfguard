# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/RobertWsp/pyperfguard/security/advisories/new).

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (minimal reproducer preferred)
- Affected versions

You will receive an acknowledgement within 48 hours and a status update within 7 days.

## Scope

pyperfguard is a static analysis and runtime instrumentation tool. Security considerations specific to this project:

### AST engine

- **Untrusted source files**: pyperfguard parses Python source via `ast.parse()` (no `eval`, no `exec`, no code execution of analyzed files). Parsing an adversarially crafted `.py` file is safe — worst case is a `SyntaxError` that is caught and logged.
- **Plugin loading**: Rules/reporters/patchers loaded via `importlib.metadata` entry points execute arbitrary code from installed packages. Only install packages you trust.

### Runtime engine (patchers)

- **Monkey-patching**: The runtime engine patches driver internals at the module level. If an attacker can influence which patchers are loaded, they can intercept DB calls. Use `[tool.pyperfguard.runtime] enabled = false` (default) in untrusted environments.
- **Bootstrap / sitecustomize**: `pyperfguard bootstrap install` appends a snippet to `sitecustomize.py`, which runs on every Python startup for that environment. Only run this command in controlled environments. The snippet is guarded by the `PYPERFGUARD_AUTO` environment variable.
- **Event buffer**: The runtime `Scope` event buffer is capped at 10,000 events (`deque(maxlen=10_000)`). There is no network egress; events are in-process only.

### Configuration

- `pyproject.toml` is parsed with `tomllib` (stdlib). A malformed file emits a `UserWarning` and falls back to defaults — it is never executed.
- `Config.exclude` patterns use `fnmatch`, not shell expansion. No shell execution occurs.

## Out of scope

- Issues in third-party packages that pyperfguard instruments (SQLAlchemy, Cassandra driver, etc.)
- Denial of service via extremely large source files (pyperfguard is a dev/CI tool, not a server)
- Theoretical timing attacks on the event fingerprinting logic
