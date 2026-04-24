"""Cheap stack-walking helpers.

Rules:
- Never use :func:`inspect.stack` or :func:`traceback.extract_stack` on a hot
  path: both read source files from disk per frame.
- Prefer :func:`sys._getframe` and walk ``f_back`` manually.
- Materialize only ``(filename, lineno, funcname)`` and format lazily.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass

# Resolve the package directory dynamically so we filter our own frames
# without false positives when the user's repo happens to contain
# "/pyperfguard/" in its path (e.g. running from this very repo's tests).
_PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_INTERNAL_PATH_MARKERS = (
    _PKG_DIR + os.sep,
    os.sep + "site-packages" + os.sep + "wrapt" + os.sep,
    os.sep + "cassandra" + os.sep,
    os.sep + "sqlalchemy" + os.sep,
    os.sep + "pymongo" + os.sep,
)


@dataclass(frozen=True, slots=True)
class FrameRef:
    filename: str
    lineno: int
    funcname: str

    def fingerprint(self) -> int:
        return hash((self.filename, self.lineno, self.funcname))

    def format(self) -> str:
        return f"{self.filename}:{self.lineno} in {self.funcname}"


def walk_user_frames(skip: int = 1, limit: int = 10) -> list[FrameRef]:
    """Return up to ``limit`` user-code frames, skipping the ``skip`` innermost.

    "User" = path does not contain any marker in :data:`_INTERNAL_PATH_MARKERS`.
    """
    out: list[FrameRef] = []
    try:
        frame = sys._getframe(skip + 1)
    except ValueError:
        return out
    while frame is not None and len(out) < limit:
        filename = frame.f_code.co_filename
        if not _is_internal(filename):
            out.append(
                FrameRef(
                    filename=filename,
                    lineno=frame.f_lineno,
                    funcname=frame.f_code.co_name,
                )
            )
        frame = frame.f_back
    return out


def first_user_frame(skip: int = 1) -> FrameRef | None:
    # walk_user_frames already adds +1 for its own frame via sys._getframe(skip+1),
    # so we do NOT add another +1 here.
    frames = walk_user_frames(skip=skip, limit=1)
    return frames[0] if frames else None


def call_site_fingerprint(skip: int = 1, depth: int = 3) -> int:
    """Hash of the top ``depth`` user frames — used to dedup N+1 sources."""
    frames = walk_user_frames(skip=skip, limit=depth)
    return hash(tuple(f.fingerprint() for f in frames))


def format_frames(frames: Iterable[FrameRef]) -> tuple[str, ...]:
    return tuple(f.format() for f in frames)


def _is_internal(path: str) -> bool:
    return any(marker in path for marker in _INTERNAL_PATH_MARKERS)
