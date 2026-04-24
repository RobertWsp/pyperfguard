from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.import_in_function import ImportInFunctionRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(ImportInFunctionRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_import_pandas_in_function_flagged():
    src = "def handler():\n    import pandas as pd\n    return pd.DataFrame()\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN014"
    assert "pandas" in findings[0].message


def test_import_numpy_in_function_flagged():
    src = "def compute():\n    import numpy as np\n    return np.array([])\n"
    findings = _run(src)
    assert len(findings) == 1
    assert "numpy" in findings[0].message


def test_import_torch_in_function_flagged():
    src = "def load_model():\n    import torch\n    return torch.load('model.pt')\n"
    findings = _run(src)
    assert len(findings) == 1


def test_import_at_module_level_not_flagged():
    src = "import pandas as pd\ndef handler():\n    return pd.DataFrame()\n"
    findings = _run(src)
    assert findings == []


def test_light_module_not_flagged():
    src = "def f():\n    import json\n    return json.dumps({})\n"
    findings = _run(src)
    assert findings == []


def test_try_except_guard_not_flagged():
    src = (
        "def f():\n"
        "    try:\n"
        "        import pandas as pd\n"
        "    except ImportError:\n"
        "        pd = None\n"
    )
    findings = _run(src)
    assert findings == []


def test_from_import_heavy_module_flagged():
    src = "def f():\n    from sklearn import svm\n    return svm.SVC()\n"
    findings = _run(src)
    assert len(findings) == 1


def test_multiple_heavy_imports_multiple_findings():
    src = "def f():\n    import pandas\n    import numpy\n"
    findings = _run(src)
    assert len(findings) == 2


def test_import_inside_async_function_flagged():
    src = "async def handler():\n    import tensorflow as tf\n"
    findings = _run(src)
    assert len(findings) == 1


def test_cached_property_not_flagged():
    # Regression: `@cached_property` methods are called at most once per instance —
    # lazy import inside is intentional (cost paid once and cached).
    src = (
        "from functools import cached_property\n"
        "class Loader:\n"
        "    @cached_property\n"
        "    def data(self):\n"
        "        import pandas as pd\n"
        "        return pd.read_csv('data.csv')\n"
    )
    findings = _run(src)
    assert findings == []


def test_lru_cache_not_flagged():
    # @lru_cache / @cache — result cached after first call.
    src = (
        "from functools import lru_cache\n"
        "@lru_cache(maxsize=1)\n"
        "def get_schema():\n"
        "    import sqlalchemy\n"
        "    return sqlalchemy.MetaData()\n"
    )
    findings = _run(src)
    assert findings == []


def test_functools_cache_not_flagged():
    src = (
        "import functools\n"
        "@functools.cache\n"
        "def model():\n"
        "    import torch\n"
        "    return torch.load('model.pt')\n"
    )
    findings = _run(src)
    assert findings == []


def test_uncached_function_still_flagged():
    # No caching decorator → still a true positive.
    src = (
        "def get_data():\n"
        "    import pandas as pd\n"
        "    return pd.read_csv('data.csv')\n"
    )
    findings = _run(src)
    assert len(findings) == 1
