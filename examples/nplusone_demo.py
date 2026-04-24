"""Hand-written examples that the static engine should flag.

Run::

    pyperfguard analyze examples/

Expected: 3+ findings (mutable default, bare except, ALLOW FILTERING).
"""

from __future__ import annotations


def make_user(roles=[]):  # noqa: B006 — intentional
    roles.append("guest")
    return roles


def safe_call():
    try:
        risky()
    except:  # noqa: E722 — intentional
        pass


def list_pending(session):
    return session.execute("SELECT * FROM events WHERE status = 'pending' ALLOW FILTERING")


def risky():
    raise RuntimeError
