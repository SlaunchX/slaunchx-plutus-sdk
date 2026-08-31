"""黄金向量与测试密钥的公共 fixture。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from slaunchx_plutus_sdk import load_private_key, load_public_key

VECTORS_PATH = Path(__file__).resolve().parents[2] / "shared" / "test-vectors.json"


@pytest.fixture(scope="session")
def vectors() -> Dict[str, Any]:
    if not VECTORS_PATH.is_file():
        pytest.fail("找不到黄金向量: %s" % VECTORS_PATH)
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def keys(vectors: Dict[str, Any]) -> Dict[str, Any]:
    return vectors["keys"]


@pytest.fixture(scope="session")
def private_keys(keys: Dict[str, Any]) -> Dict[str, Any]:
    return {name: load_private_key(key["privateKeyPem"]) for name, key in keys.items()}


@pytest.fixture(scope="session")
def public_keys(keys: Dict[str, Any]) -> Dict[str, Any]:
    return {name: load_public_key(key["publicKeyPem"]) for name, key in keys.items()}


def load_group(name: str) -> List[Dict[str, Any]]:
    """在参数化阶段(fixture 尚不可用)直接读取某个向量分组。"""
    data = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    return data["vectors"][name]


def group_params(name: str) -> Any:
    cases = load_group(name)
    return pytest.mark.parametrize(
        "case", cases, ids=[case["id"] for case in cases]
    )
