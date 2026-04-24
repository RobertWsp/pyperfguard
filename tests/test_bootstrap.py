"""Tests for the bootstrap module (sitecustomize.py installer)."""

from __future__ import annotations


def test_auto_instrument_is_idempotent(tmp_path):
    """Calling auto_instrument() twice should not install patchers twice."""
    from pyperfguard._bootstrap import bootstrap as bs_mod

    # Reset state between tests
    bs_mod._active = False
    try:
        # First call should succeed without raising
        # (no real drivers installed, engine will start with zero patchers)
        bs_mod.auto_instrument()
        assert bs_mod.is_active()
        # Second call — no-op
        bs_mod.auto_instrument()
        assert bs_mod.is_active()
    finally:
        bs_mod._active = False
        import sys

        sys.__dict__.pop("__pyperfguard_engine__", None)


def test_install_sitecustomize_appends_snippet(tmp_path):
    from pyperfguard._bootstrap.bootstrap import _MARKER_START, install_sitecustomize

    sc = tmp_path / "sitecustomize.py"
    sc.write_text("# existing content\n")

    path = install_sitecustomize(site_packages=str(tmp_path))
    assert path == str(sc)

    content = sc.read_text()
    assert _MARKER_START in content
    assert "auto_instrument" in content
    assert "PYPERFGUARD_AUTO" in content


def test_install_sitecustomize_idempotent(tmp_path):
    from pyperfguard._bootstrap.bootstrap import _MARKER_START, install_sitecustomize

    install_sitecustomize(site_packages=str(tmp_path))
    install_sitecustomize(site_packages=str(tmp_path))  # second call

    sc = tmp_path / "sitecustomize.py"
    content = sc.read_text()
    # Marker appears exactly once
    assert content.count(_MARKER_START) == 1


def test_install_creates_file_if_missing(tmp_path):
    from pyperfguard._bootstrap.bootstrap import install_sitecustomize

    sc = tmp_path / "sitecustomize.py"
    assert not sc.exists()

    install_sitecustomize(site_packages=str(tmp_path))
    assert sc.exists()


def test_uninstall_removes_snippet(tmp_path):
    from pyperfguard._bootstrap.bootstrap import (
        _MARKER_START,
        install_sitecustomize,
        uninstall_sitecustomize,
    )

    install_sitecustomize(site_packages=str(tmp_path))
    result = uninstall_sitecustomize(site_packages=str(tmp_path))
    assert result is not None

    sc = tmp_path / "sitecustomize.py"
    content = sc.read_text()
    assert _MARKER_START not in content


def test_uninstall_preserves_other_content(tmp_path):
    from pyperfguard._bootstrap.bootstrap import install_sitecustomize, uninstall_sitecustomize

    sc = tmp_path / "sitecustomize.py"
    sc.write_text("# my custom hook\nprint('hello')\n")

    install_sitecustomize(site_packages=str(tmp_path))
    uninstall_sitecustomize(site_packages=str(tmp_path))

    content = sc.read_text()
    assert "my custom hook" in content
    assert "print('hello')" in content


def test_uninstall_returns_none_when_not_installed(tmp_path):
    from pyperfguard._bootstrap.bootstrap import uninstall_sitecustomize

    result = uninstall_sitecustomize(site_packages=str(tmp_path))
    assert result is None


def test_is_active_false_initially():
    from pyperfguard._bootstrap import bootstrap as bs_mod

    initial = bs_mod._active
    # Ensure we don't bleed state from other tests
    bs_mod._active = False
    assert not bs_mod.is_active()
    bs_mod._active = initial
