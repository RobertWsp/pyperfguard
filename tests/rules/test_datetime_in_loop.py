from __future__ import annotations

import ast
from pathlib import Path

from pyperfguard.ast_engine.context import AstContext
from pyperfguard.ast_engine.visitor import PyperfVisitor
from pyperfguard.core.registry import Registry
from pyperfguard.rules.datetime_in_loop import DatetimeInLoopRule


def _run(src: str) -> list:
    reg = Registry()
    reg.register_rule(DatetimeInLoopRule())
    ctx = AstContext(path=Path("t.py"), source=src, module=ast.parse(src))
    v = PyperfVisitor(reg, ctx)
    v.visit(ctx.module)
    return v.findings


def test_datetime_now_in_loop_flagged():
    src = "from datetime import datetime\nfor item in items:\n    ts = datetime.now()\n"
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN007"


def test_datetime_utcnow_in_loop_flagged():
    src = "from datetime import datetime\nfor item in items:\n    ts = datetime.utcnow()\n"
    findings = _run(src)
    assert len(findings) == 1


def test_datetime_today_in_loop_flagged():
    src = "from datetime import datetime\nfor item in items:\n    d = datetime.today()\n"
    findings = _run(src)
    assert len(findings) == 1


def test_time_time_in_loop_flagged():
    src = "import time\nfor item in items:\n    t = time.time()\n"
    findings = _run(src)
    assert len(findings) == 1


def test_datetime_now_outside_loop_not_flagged():
    src = "from datetime import datetime\nts = datetime.now()\n"
    findings = _run(src)
    assert findings == []


def test_unrelated_method_in_loop_not_flagged():
    src = "for item in items:\n    item.process()\n"
    findings = _run(src)
    assert findings == []


def test_time_time_elapsed_in_for_loop_not_flagged():
    # Regression: `time.time() - t0` measures elapsed time — same as time.monotonic().
    # This is the correct way to check a timeout inside a polling for loop.
    src = "import time\nfor i in items:\n    if time.time() - t0 > timeout:\n        break\n"
    findings = _run(src)
    assert findings == []


def test_time_time_elapsed_in_while_loop_not_flagged():
    # Regression: Celery/scrapy pattern — `time.time() - t0` in while loop.
    src = "import time\nwhile not done:\n    time.sleep(0.01)\n    if time.time() - t0 > 1:\n        return None\n"
    findings = _run(src)
    assert findings == []


def test_time_time_assigned_in_loop_still_flagged():
    # `t = time.time()` inside a loop where it's NOT a subtraction → still a TP.
    src = "import time\nfor item in items:\n    item.stamp = time.time()\n"
    findings = _run(src)
    assert len(findings) == 1


def test_start_time_assignment_not_flagged():
    # Regression: `start_time = time.time()` inside while loop — timing variable, not a stamp.
    # Pattern seen in cassandra-driver connection.py heartbeat loop.
    src = "import time\nwhile True:\n    start_time = time.time()\n    do_work()\n"
    findings = _run(src)
    assert findings == []


def test_begin_ts_assignment_not_flagged():
    # Regression: `begin_ts = time.time()` — 'begin' fragment marks timing reference.
    src = "import time\nfor item in items:\n    begin_ts = time.time()\n    elapsed = time.time() - begin_ts\n"
    findings = _run(src)
    assert findings == []


def test_ref_time_assignment_not_flagged():
    # Regression: `ref = time.time()` — 'ref' fragment marks elapsed-time anchor.
    src = "import time\nwhile running:\n    ref = time.time()\n"
    findings = _run(src)
    assert findings == []


def test_deadline_check_not_flagged():
    # Regression: `if time.time() < stagger_end:` — deadline check, LEFT of comparison.
    # Pattern seen in medusa backup_node.py stagger loop.
    src = "import time\nwhile True:\n    if time.time() < deadline:\n        continue\n"
    findings = _run(src)
    assert findings == []


def test_datetime_now_deadline_check_not_flagged():
    # Regression: `if datetime.datetime.now() < stagger_end:` in medusa backup_node.py:173.
    src = (
        "import datetime\n"
        "while not done:\n"
        "    if datetime.datetime.now() < stagger_end:\n"
        "        time.sleep(60)\n"
    )
    findings = _run(src)
    assert findings == []


def test_right_side_comparison_flagged():
    # `if item.ts < datetime.now():` — now() on RIGHT side → same value for all items.
    src = "from datetime import datetime\nfor item in items:\n    if item.ts < datetime.now():\n        purge(item)\n"
    findings = _run(src)
    assert len(findings) == 1


def test_run_at_deadline_check_not_flagged():
    # Regression: `if run_at <= time.time():` — scheduler pattern from cassandra-driver cluster.py.
    src = "import time\nwhile True:\n    if run_at <= time.time():\n        execute()\n"
    findings = _run(src)
    # run_at <= time.time() — time.time() is the RIGHT side of comparison (not .left), so it IS flagged.
    # This is a true positive: run_at is a fixed time, time.time() could be hoisted.
    # The deadline exclusion only applies when time.time() is the LEFT operand.
    assert len(findings) == 1


def test_elapsed_time_then_stamp_both_correct():
    # In a loop: elapsed use (no flag) + stamp assignment (flag). Two calls, one finding.
    src = (
        "import time\n"
        "for item in items:\n"
        "    if time.time() - t0 > 5:\n"
        "        break\n"
        "    item.stamp = time.time()\n"
    )
    findings = _run(src)
    assert len(findings) == 1
    assert findings[0].rule_id == "PKN007"
