"""bodyHash 向量组:7 例,含 GET/DELETE 强制空体。"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from slaunchx_plutus_sdk import EMPTY_BODY_SHA256, FORCED_EMPTY_BODY_METHODS, body_sha256_hex

from conftest import group_params, load_group


def test_group_size() -> None:
    assert len(load_group("bodyHash")) == 7


@group_params("bodyHash")
def test_body_hash_vector(case: Dict[str, Any]) -> None:
    method = case.get("method")
    raw = None if case["body"] is None else case["body"].encode("utf-8")
    forced = method is not None and method.upper() in FORCED_EMPTY_BODY_METHODS
    assert forced == case["forcedEmptyBody"]
    assert body_sha256_hex(raw, method) == case["expected"]


@pytest.mark.parametrize("method", ["GET", "get", "HEAD", "DELETE", "delete"])
def test_forced_empty_body_methods_ignore_payload(method: str) -> None:
    assert body_sha256_hex(b'{"ignored":true}', method) == EMPTY_BODY_SHA256


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_other_methods_hash_actual_bytes(method: str) -> None:
    assert body_sha256_hex(b'{"ignored":true}', method) != EMPTY_BODY_SHA256
    assert body_sha256_hex(b"", method) == EMPTY_BODY_SHA256
    assert body_sha256_hex(None, method) == EMPTY_BODY_SHA256


def test_whitespace_is_significant() -> None:
    assert body_sha256_hex(b'{"a":1}') != body_sha256_hex(b'{"a": 1}')
