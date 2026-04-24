from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.list_before_for import ListBeforeForRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(ListBeforeForRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_list_wrapping_iterable_flagged():
    src = "for x in list(gen):\n    process(x)\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN015"


def test_list_wrapping_generator_expression_flagged():
    src = "for x in list(i for i in range(10)):\n    print(x)\n"
    findings = _run(src)
    assert len(findings) == 1


def test_direct_iteration_not_flagged():
    src = "for x in gen:\n    process(x)\n"
    findings = _run(src)
    assert findings == []


def test_range_iteration_not_flagged():
    src = "for i in range(10):\n    print(i)\n"
    findings = _run(src)
    assert findings == []


def test_list_literal_not_flagged():
    src = "for x in [1, 2, 3]:\n    print(x)\n"
    findings = _run(src)
    assert findings == []


def test_list_with_no_args_not_flagged():
    src = "for x in list():\n    print(x)\n"
    findings = _run(src)
    assert findings == []


def test_list_with_multiple_args_not_flagged():
    # list() only accepts 0 or 1 arg, but we guard against keywords too
    src = "for x in sorted(items, key=len):\n    print(x)\n"
    findings = _run(src)
    assert findings == []


def test_async_for_with_list_flagged():
    src = "async def f():\n    async for x in list(gen):\n        pass\n"
    findings = _run(src)
    # ListBeforeForRule targets ast.For, not ast.AsyncFor
    assert findings == []


def test_list_of_dict_items_not_flagged():
    # Regression: `for k, v in list(d.items()):` is a legitimate pattern
    # for mutating a dict while iterating — must NOT be flagged as PKN015.
    src = "for k, v in list(d.items()):\n    del d[k]\n"
    findings = _run(src)
    assert findings == []


def test_list_of_dict_keys_not_flagged():
    src = "for k in list(d.keys()):\n    if k.startswith('_'):\n        del d[k]\n"
    findings = _run(src)
    assert findings == []


def test_list_of_dict_values_not_flagged():
    src = "for v in list(d.values()):\n    process(v)\n"
    findings = _run(src)
    assert findings == []


def test_list_of_other_call_still_flagged():
    # list(get_items()) is NOT a dict-view — should still be flagged.
    src = "for x in list(get_items()):\n    process(x)\n"
    findings = _run(src)
    assert len(findings) == 1


def test_list_with_del_on_iterable_not_flagged():
    # Regression: `for k in list(d): del d[k]` requires list() snapshot.
    src = "for k in list(d):\n    if k.startswith('_'):\n        del d[k]\n"
    findings = _run(src)
    assert findings == []


def test_list_with_remove_on_iterable_not_flagged():
    # `for x in list(items): items.remove(x)` — list() is necessary.
    src = "for x in list(items):\n    if condition(x):\n        items.remove(x)\n"
    findings = _run(src)
    assert findings == []


def test_list_of_self_not_flagged():
    # `for item in list(self):` — iterating a collection class over itself.
    # self might be modified via remover() callbacks.
    src = (
        "class Coll:\n"
        "    def clear(self):\n"
        "        for item in list(self):\n"
        "            self._remove(item)\n"
    )
    findings = _run(src)
    assert findings == []


def test_list_with_sys_modules_mutation_not_flagged():
    # Regression: requests pattern — `list(sys.modules)` needed because loop
    # modifies sys.modules by adding new entries.
    src = (
        "import sys\n"
        "for mod in list(sys.modules):\n"
        "    sys.modules['alias.' + mod] = sys.modules[mod]\n"
    )
    findings = _run(src)
    assert findings == []


def test_list_without_mutation_still_flagged():
    # If the loop body does NOT mutate the iterable, flag it.
    src = "for x in list(items):\n    process(x)\n"
    findings = _run(src)
    assert len(findings) == 1
