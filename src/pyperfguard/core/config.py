from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10 fallback
    import tomli as tomllib


@dataclass(slots=True)
class RuntimeConfig:
    enabled: bool = False
    sampling_rate: int = 1  # 1 = every call, N = 1 in N
    patchers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReportConfig:
    format: str = "terminal"
    output: Path | None = None


@dataclass(slots=True)
class Config:
    select: list[str] = field(default_factory=lambda: ["PKN"])
    ignore: list[str] = field(default_factory=list)
    exclude: list[str] = field(
        default_factory=lambda: [
            "**/.venv/**",
            "**/build/**",
            "**/dist/**",
            "**/__pycache__/**",
            "**/.git/**",
            "**/node_modules/**",
        ]
    )
    # Minimum severity level to report. Findings below this level are silently
    # dropped. Valid values: "error", "warning", "info", "hint" (case-insensitive).
    # When None (default), all findings are reported.
    min_severity: str | None = None
    # Verbose mode: show full message, snippet, and fix description.
    # Default (False) = compact single-line output optimised for LLM consumption.
    verbose: bool = False
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    report: ReportConfig = field(default_factory=ReportConfig)

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        """Load config from pyproject.toml ``[tool.pyperfguard]`` if present."""
        cfg = cls()
        pyproject = path or _find_pyproject(Path.cwd())
        if pyproject is None or not pyproject.exists():
            return cfg
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except Exception as exc:
            import warnings

            warnings.warn(
                f"pyperfguard: failed to parse pyproject.toml ({pyproject}): {exc}. "
                "Using default configuration.",
                UserWarning,
                stacklevel=2,
            )
            return cfg
        section = data.get("tool", {}).get("pyperfguard", {})
        return cls.from_dict(section)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        cfg = cls()
        if "select" in data:
            cfg.select = list(data["select"])
        if "ignore" in data:
            cfg.ignore = list(data["ignore"])
        if "exclude" in data:
            cfg.exclude = list(data["exclude"])
        if "min_severity" in data:
            cfg.min_severity = str(data["min_severity"]).lower()
        if "verbose" in data:
            cfg.verbose = bool(data["verbose"])
        if "runtime" in data:
            rt = data["runtime"]
            cfg.runtime = RuntimeConfig(
                enabled=bool(rt.get("enabled", False)),
                sampling_rate=int(rt.get("sampling_rate", 1)),
                patchers=list(rt.get("patchers", [])),
            )
        if "report" in data:
            rp = data["report"]
            cfg.report = ReportConfig(
                format=str(rp.get("format", "terminal")),
                output=Path(rp["output"]) if rp.get("output") else None,
            )
        return cfg


def _find_pyproject(start: Path) -> Path | None:
    """Walk parents until a pyproject.toml is found, or root."""
    for parent in (start, *start.parents):
        candidate = parent / "pyproject.toml"
        if candidate.exists():
            return candidate
    return None
