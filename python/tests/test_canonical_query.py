"""canonicalQuery 向量组:21 例,含 6 例必须抛异常的拒绝用例。"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from slaunchx_plutus_sdk import CanonicalQueryError, canonicalize_query, encode_query

from conftest import group_params, load_group


def test_group_size() -> None:
    cases = load_group("canonicalQuery")
    assert len(cases) == 21
    assert sum(1 for case in cases if case["expectError"]) == 6


@group_params("canonicalQuery")
def test_canonical_query_vector(case: Dict[str, Any]) -> None:
    if case["expectError"]:
        with pytest.raises(CanonicalQueryError):
            canonicalize_query(case["input"])
    else:
        assert canonicalize_query(case["input"]) == case["expected"]


def test_canonicalization_is_idempotent() -> None:
    for case in load_group("canonicalQuery"):
        if case["expectError"]:
            continue
        once = canonicalize_query(case["input"])
        assert canonicalize_query(once) == once


@pytest.mark.parametrize(
    "raw",
    ["q=a b", "q=%", "q=%2", "q=%G0", "a=1&q=中", "q=a/b", "q=a?b", "q=a#b"],
)
def test_additional_rejections(raw: str) -> None:
    with pytest.raises(CanonicalQueryError):
        canonicalize_query(raw)


def test_encode_query_uses_percent20_not_plus() -> None:
    raw = encode_query({"note": "hello world", "sign": "+1"})
    assert raw is not None
    assert "+" not in raw.replace("%2B", "")
    assert canonicalize_query(raw) == "note=hello%20world&sign=%2B1"


def test_encode_query_repeated_key() -> None:
    raw = encode_query([("a", "2"), ("a", "1"), ("a", "10")])
    assert canonicalize_query(raw) == "a=1&a=10&a=2"


def test_encode_query_passthrough_and_none() -> None:
    assert encode_query(None) is None
    assert encode_query("b=2&a=1") == "b=2&a=1"
