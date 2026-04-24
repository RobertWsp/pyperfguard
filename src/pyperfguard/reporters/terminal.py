from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, TextIO

from pyperfguard.core.finding import Finding, SEV_CODE, rel_path
from pyperfguard.core.severity import Severity

_COLORS = {
    Severity.ERROR: "\033[31m",
    Severity.WARNING: "\033[33m",
    Severity.INFO: "\033[36m",
    Severity.HINT: "\033[35m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


class TerminalReporter:
    """Terminal reporter.

    **Default (compact)** — one line per finding, relative paths, short message.
    Optimised for LLM consumption; no snippets, no fix descriptions.

    **Verbose** (``verbose=True`` / ``--verbose``) — multi-line with snippet and
    fix description.  Intended for human review at the terminal.
    """

    def __init__(
        self,
        stream: TextIO | None = None,
        color: bool | None = None,
        verbose: bool = False,
    ) -> None:
        self.stream = stream or sys.stdout
        self.color = self.stream.isatty() if color is None else color
        self.verbose = verbose

    def report(self, findings: Iterable[Finding]) -> None:
        findings = list(findings)
        if not findings:
            self._write(f"{self._green('OK')} no findings\n")
            return

        findings.sort(key=lambda f: (str(f.location.path), f.location.start_line))
        cwd = Path.cwd()

        counts: dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            if self.verbose:
                self._write(self._format_verbose(f))
            else:
                self._write(self._format_compact(f, cwd))
            self._write("\n")

        total = len(findings)
        if self.verbose:
            summary = ", ".join(f"{n} {s.value}" for s, n in counts.items())
            self._write(f"\n{self._bold(str(total))} findings ({summary})\n")
        else:
            parts = " ".join(f"{n}{SEV_CODE[s]}" for s, n in counts.items())
            self._write(f"\n{self._bold(str(total))} findings ({parts})\n")

    # ----- compact format --------------------------------------------------

    def _format_compact(self, f: Finding, cwd: Path) -> str:
        path = rel_path(f.location.path, cwd)
        loc = f"{path}:{f.location.start_line}:{f.location.start_col + 1}"
        code = SEV_CODE[f.severity]
        rule = self._bold(f"{f.rule_id}[{code}]")
        msg = f.compact_message()
        return f"{loc} {rule} {msg}"

    # ----- verbose format --------------------------------------------------

    def _format_verbose(self, f: Finding) -> str:
        loc = f"{f.location.path}:{f.location.start_line}:{f.location.start_col + 1}"
        sev = self._sev(f.severity)
        head = f"{loc}: {sev} {self._bold(f.rule_id)} {f.message}"
        out = [head]
        if f.snippet:
            out.append(self._dim(f"    {f.snippet}"))
        if f.fix and f.fix.description:
            out.append(self._dim(f"    fix: {f.fix.description}"))
        if f.stack:
            for frame in f.stack[:5]:
                out.append(self._dim(f"      at {frame}"))
        return "\n".join(out)

    # ----- color helpers ---------------------------------------------------

    def _sev(self, s: Severity) -> str:
        text = s.value.upper()
        if not self.color:
            return text
        return f"{_COLORS[s]}{text}{_RESET}"

    def _bold(self, s: str) -> str:
        return f"{_BOLD}{s}{_RESET}" if self.color else s

    def _dim(self, s: str) -> str:
        return f"{_DIM}{s}{_RESET}" if self.color else s

    def _green(self, s: str) -> str:
        return f"\033[32m{s}{_RESET}" if self.color else s

    def _write(self, s: str) -> None:
        self.stream.write(s)
