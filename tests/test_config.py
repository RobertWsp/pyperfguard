from __future__ import annotations

from pathlib import Path

from pyperfguard.core.config import Config


def test_default_config_values():
    cfg = Config()
    assert cfg.select == ["PKN"]
    assert cfg.runtime.enabled is False
    assert cfg.report.format == "terminal"


def test_load_from_pyproject(tmp_path: Path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        "[tool.pyperfguard]\n"
        'select = ["PKN001"]\n'
        'ignore = ["PKN002"]\n'
        "\n"
        "[tool.pyperfguard.runtime]\n"
        "enabled = true\n"
        "sampling_rate = 50\n"
        'patchers = ["sqlalchemy"]\n'
        "\n"
        "[tool.pyperfguard.report]\n"
        'format = "sarif"\n'
    )
    cfg = Config.load(py)
    assert cfg.select == ["PKN001"]
    assert cfg.ignore == ["PKN002"]
    assert cfg.runtime.enabled is True
    assert cfg.runtime.sampling_rate == 50
    assert cfg.runtime.patchers == ["sqlalchemy"]
    assert cfg.report.format == "sarif"


def test_missing_pyproject_returns_defaults(tmp_path: Path):
    cfg = Config.load(tmp_path / "missing.toml")
    assert cfg.select == ["PKN"]


def test_malformed_pyproject_returns_defaults(tmp_path: Path):
    py = tmp_path / "pyproject.toml"
    py.write_text("not = valid = toml = [")
    cfg = Config.load(py)
    assert cfg.select == ["PKN"]


def test_malformed_pyproject_emits_warning(tmp_path: Path):
    import warnings

    py = tmp_path / "pyproject.toml"
    py.write_text("not = valid = toml = [")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        Config.load(py)
    user_warns = [w for w in caught if issubclass(w.category, UserWarning)]
    assert len(user_warns) == 1
    assert "pyproject.toml" in str(user_warns[0].message).lower()


def test_min_severity_loaded_from_config(tmp_path: Path):
    py = tmp_path / "pyproject.toml"
    py.write_text('[tool.pyperfguard]\nmin_severity = "error"\n')
    cfg = Config.load(py)
    assert cfg.min_severity == "error"


def test_verbose_loaded_from_config(tmp_path: Path):
    py = tmp_path / "pyproject.toml"
    py.write_text("[tool.pyperfguard]\nverbose = true\n")
    cfg = Config.load(py)
    assert cfg.verbose is True
