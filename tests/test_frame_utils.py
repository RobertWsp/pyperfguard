from __future__ import annotations

from pyperfguard.core.frame_utils import (
    call_site_fingerprint,
    first_user_frame,
    walk_user_frames,
)


def test_first_user_frame_returns_caller_location():
    f = first_user_frame()
    assert f is not None
    assert f.filename.endswith("test_frame_utils.py")
    assert f.funcname == "test_first_user_frame_returns_caller_location"


def test_walk_user_frames_respects_limit():
    frames = walk_user_frames(limit=2)
    assert 0 < len(frames) <= 2


def test_call_site_fingerprint_is_stable_across_calls_from_same_line():
    a = _call_site_helper()
    b = _call_site_helper()
    assert a == b


def _call_site_helper() -> int:
    # depth=1: only capture the frame of _call_site_helper itself.
    # The co_firstlineno of this function is constant → fingerprint is stable.
    return call_site_fingerprint(depth=1)


def test_call_site_fingerprint_differs_for_different_functions():
    # Two helpers at different definition points produce different fingerprints.
    a = _call_site_helper()
    b = _call_site_helper2()
    assert a != b


def _call_site_helper2() -> int:
    return call_site_fingerprint(depth=1)
