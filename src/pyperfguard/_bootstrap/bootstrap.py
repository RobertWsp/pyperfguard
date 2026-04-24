"""Auto-instrumentation bootstrap.

Activated via:
  - sitecustomize.py (``pyperfguard bootstrap install``)
  - Manual: ``import pyperfguard._bootstrap; pyperfguard._bootstrap.auto_instrument()``
  - Env var:  PYPERFGUARD_AUTO=1 python app.py
"""

from __future__ import annotations

import os
import sys

_active = False


def is_active() -> bool:
    return _active


def auto_instrument() -> None:
    """Install the runtime engine globally (patchers + import hook).

    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _active
    if _active:
        return
    _active = True

    from pyperfguard.core.config import Config
    from pyperfguard.plugins import bootstrap as _bootstrap
    from pyperfguard.runtime_engine.engine import RuntimeEngine

    cfg = Config.load()
    registry = _bootstrap()
    engine = RuntimeEngine(config=cfg, registry=registry)
    engine.start()

    # Store on sys so teardown can reach it from any module.
    sys.__pyperfguard_engine__ = engine  # type: ignore[attr-defined]


def _sitecustomize_snippet(site_packages: str) -> str:
    return (
        "# pyperfguard auto-instrumentation — managed by `pyperfguard bootstrap`\n"
        "import os as _os\n"
        "if _os.environ.get('PYPERFGUARD_AUTO', '').lower() not in ('0', 'false', 'no', ''):\n"
        "    try:\n"
        "        import pyperfguard._bootstrap as _b; _b.auto_instrument()\n"
        "    except Exception:\n"
        "        pass\n"
        "# end pyperfguard\n"
    )


_MARKER_START = "# pyperfguard auto-instrumentation"
_MARKER_END = "# end pyperfguard"


def _find_site_packages() -> str:
    import site

    candidates = site.getsitepackages() if hasattr(site, "getsitepackages") else []
    if site.getusersitepackages():
        candidates = [site.getusersitepackages(), *list(candidates)]
    # Prefer the one that already contains pyperfguard (editable install).
    for sp in candidates:
        if os.path.isdir(os.path.join(sp, "pyperfguard")):
            return sp
    return candidates[0] if candidates else sys.prefix + "/lib/python/site-packages"


def install_sitecustomize(site_packages: str | None = None) -> str:
    """Write the auto-instrument hook into sitecustomize.py.  Returns the path."""
    sp = site_packages or _find_site_packages()
    path = os.path.join(sp, "sitecustomize.py")

    existing = ""
    if os.path.exists(path):
        with open(path) as f:
            existing = f.read()

    if _MARKER_START in existing:
        return path  # already installed

    snippet = _sitecustomize_snippet(sp)
    with open(path, "a") as f:
        f.write("\n" + snippet)
    return path


def uninstall_sitecustomize(site_packages: str | None = None) -> str | None:
    """Remove the auto-instrument hook from sitecustomize.py.  Returns path or None."""
    sp = site_packages or _find_site_packages()
    path = os.path.join(sp, "sitecustomize.py")

    if not os.path.exists(path):
        return None

    with open(path) as f:
        content = f.read()

    if _MARKER_START not in content:
        return None

    lines = content.splitlines(keepends=True)
    out: list[str] = []
    skip = False
    for line in lines:
        if _MARKER_START in line:
            skip = True
        if not skip:
            out.append(line)
        if skip and _MARKER_END in line:
            skip = False

    with open(path, "w") as f:
        f.writelines(out)
    return path
