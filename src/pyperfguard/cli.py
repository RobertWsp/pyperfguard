from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from pyperfguard import __version__
from pyperfguard.ast_engine.runner import analyze
from pyperfguard.core.config import Config
from pyperfguard.core.severity import Severity
from pyperfguard.plugins import bootstrap


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pyperfguard",
        description="Agnostic Python performance & anti-pattern guard.",
    )
    p.add_argument("--version", action="version", version=f"pyperfguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Run the static AST engine")
    a.add_argument("paths", nargs="+", type=Path, help="Files or directories to scan")
    a.add_argument(
        "--format",
        "-f",
        default=None,
        choices=("terminal", "json", "sarif"),
        help="Output format (default: terminal, or value of report.format in pyproject.toml)",
    )
    a.add_argument(
        "--output", "-o", type=Path, default=None, help="Write to file instead of stdout"
    )
    a.add_argument(
        "--select", action="append", default=None, help="Rule id prefix to include (repeatable)"
    )
    a.add_argument(
        "--ignore", action="append", default=None, help="Rule id prefix to exclude (repeatable)"
    )
    a.add_argument(
        "--min-severity",
        default=None,
        choices=("error", "warning", "info", "hint"),
        metavar="LEVEL",
        help="Minimum severity to report: error, warning, info, hint (default: all)",
    )
    a.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help=(
            "Full output: absolute paths, complete messages, snippets, fix descriptions. "
            "Default is compact one-line-per-finding format optimised for LLM consumption."
        ),
    )
    a.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always exit 0 even when findings are reported",
    )

    sub.add_parser("rules", help="List discovered rules and exit")
    sub.add_parser("reporters", help="List discovered reporters and exit")
    sub.add_parser(
        "lsp",
        help=(
            "Start a Language Server Protocol server on stdio. "
            "Publishes pyperfguard diagnostics on textDocument/didOpen and didChange events."
        ),
    )

    bs = sub.add_parser("bootstrap", help="Manage sitecustomize.py auto-instrumentation")
    bs_sub = bs.add_subparsers(dest="bs_command", required=True)
    bs_inst = bs_sub.add_parser("install", help="Add auto-instrument hook to sitecustomize.py")
    bs_inst.add_argument("--site-packages", default=None, help="Target site-packages directory")
    bs_un = bs_sub.add_parser("uninstall", help="Remove auto-instrument hook from sitecustomize.py")
    bs_un.add_argument("--site-packages", default=None, help="Target site-packages directory")

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    registry = bootstrap()

    if args.command == "rules":
        for r in registry.rules():
            print(f"{r.id}\t{r.severity.value}\t{r.name}")
        return 0

    if args.command == "reporters":
        for name in registry.reporter_names():
            print(name)
        return 0

    if args.command == "analyze":
        cfg = Config.load()
        if args.select:
            cfg.select = args.select
        if args.ignore:
            cfg.ignore = args.ignore
        if args.format:
            cfg.report.format = args.format
        if args.output:
            cfg.report.output = args.output
        if args.min_severity:
            cfg.min_severity = args.min_severity
        if args.verbose:
            cfg.verbose = True

        findings = analyze(args.paths, config=cfg, registry=registry, discover=False)

        if cfg.min_severity:
            _severity_order = {"error": 0, "warning": 1, "info": 2, "hint": 3}
            min_level = _severity_order.get(cfg.min_severity, 3)
            findings = [
                f for f in findings if _severity_order.get(f.severity.value, 3) <= min_level
            ]

        reporter_cls = registry.reporter(cfg.report.format)
        stream = cfg.report.output.open("w", encoding="utf-8") if cfg.report.output else sys.stdout
        try:
            reporter_cls(stream=stream, verbose=cfg.verbose).report(findings)
        finally:
            if cfg.report.output:
                stream.close()

        if args.exit_zero:
            return 0
        # Non-zero exit only on errors; warnings/info don't fail the build.
        return 1 if any(f.severity is Severity.ERROR for f in findings) else 0

    if args.command == "lsp":
        from pyperfguard.lsp_server import main as lsp_main

        lsp_main()
        return 0  # lsp_main calls sys.exit internally; this is unreachable

    if args.command == "bootstrap":
        from pyperfguard._bootstrap.bootstrap import install_sitecustomize, uninstall_sitecustomize

        sp = getattr(args, "site_packages", None)
        if args.bs_command == "install":
            path = install_sitecustomize(sp)
            print(f"pyperfguard: auto-instrumentation installed → {path}")
            return 0
        if args.bs_command == "uninstall":
            removed_path = uninstall_sitecustomize(sp)
            if removed_path:
                print(f"pyperfguard: auto-instrumentation removed from {removed_path}")
            else:
                print("pyperfguard: hook not found — nothing to remove")
            return 0

    parser.error(f"unknown command {args.command!r}")
    return 2  # unreachable


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
