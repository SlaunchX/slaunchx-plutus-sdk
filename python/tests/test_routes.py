"""已知加密端点 routeTemplate 常量表:逐字节匹配与判定函数。"""

from __future__ import annotations

from slaunchx_plutus_sdk import ENCRYPTED_ROUTE_TEMPLATES, is_known_encrypted_route

#: SPEC.md 第 3 节「已知的加密请求端点」表,逐字节复述作为回归基线。
_EXPECTED_ROUTE_TEMPLATES = (
    "/card-products/10010105/cards/create",
    "/card-products/10010106/shared/cards/create",
    "/card-products/10010106/prepaid/cards/create",
    "/card-products/10010107/prepaid/cards/create",
    "/card-products/10010107/prepaid/cards/recharge",
    "/card-products/10010107/prepaid/cards/withdraw",
)


def test_encrypted_route_templates_match_spec_exactly() -> None:
    assert ENCRYPTED_ROUTE_TEMPLATES == _EXPECTED_ROUTE_TEMPLATES
    assert len(ENCRYPTED_ROUTE_TEMPLATES) == 6
    assert len(set(ENCRYPTED_ROUTE_TEMPLATES)) == 6, "常量表不应含重复项"


def test_is_known_encrypted_route_true_for_known_routes() -> None:
    for route in _EXPECTED_ROUTE_TEMPLATES:
        assert is_known_encrypted_route(route) is True


def test_is_known_encrypted_route_false_for_unknown_routes() -> None:
    assert is_known_encrypted_route("/card-products/99999999/cards/create") is False
    assert is_known_encrypted_route("/card-products/10010105/cards/create/") is False
    assert is_known_encrypted_route("") is False
    assert is_known_encrypted_route("/card-products/10010106/shared/cards/creat") is False
