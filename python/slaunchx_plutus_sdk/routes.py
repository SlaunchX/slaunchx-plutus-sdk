"""已知加密请求端点的 ``routeTemplate`` 常量表。

数据来源是 ``SPEC.md`` 第 3 节「已知的加密请求端点」,与 java/php/node/go 等其余语言 SDK
共享同一份字面量。这些端点强制走混合加密信封,``routeTemplate`` 即该端点的外部路径,
作为信封 AAD 的第 2 个分量参与 ``RSA-OAEP-AES-256-GCM`` 认证(见 SPEC 第 8 节)。

设计取舍:平台新增加密端点是预期中的演进,SDK 不应因常量表滞后而卡死商户请求。因此
:class:`~slaunchx_plutus_sdk.client.PlutusClient` 对不在本表中的 ``route_template`` 默认
仅发出 :class:`UnknownEncryptedRouteWarning`,不阻断请求;只有显式开启
``PlutusConfig.strict_encrypted_route_validation`` 的商户,才会在遇到未知加密路由时
抛出 :class:`~slaunchx_plutus_sdk.errors.ConfigurationError`。
"""

from __future__ import annotations

from typing import Tuple

__all__ = [
    "ENCRYPTED_ROUTE_TEMPLATES",
    "is_known_encrypted_route",
]

#: SPEC 第 3 节「已知的加密请求端点」表,六语言 SDK 共享同一份字面量。
ENCRYPTED_ROUTE_TEMPLATES: Tuple[str, ...] = (
    "/card-products/10010105/cards/create",
    "/card-products/10010106/shared/cards/create",
    "/card-products/10010106/prepaid/cards/create",
    "/card-products/10010107/prepaid/cards/create",
    "/card-products/10010107/prepaid/cards/recharge",
    "/card-products/10010107/prepaid/cards/withdraw",
)


def is_known_encrypted_route(route_template: str) -> bool:
    """判断 ``route_template`` 是否在 SPEC 第 3 节的已知加密端点表中。"""
    return route_template in ENCRYPTED_ROUTE_TEMPLATES
