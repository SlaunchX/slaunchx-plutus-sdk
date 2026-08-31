"""统一响应包络的成功码常量。

平台统一响应包络形如::

    {"version":"2.0.0","timestamp":1755600000123,
     "success":true,"code":"2000","message":"Success","data":{}}

``code`` 是**字符串**。本模块列出成功族码,仅供文档与便利判断使用。

.. warning::
   本模块的常量与 :func:`is_success_code` **不是成功判定依据**。成功与否只看包络中
   布尔类型的 ``success`` 字段;该字段缺失或非布尔时回退到 HTTP 2xx。判定实现见
   :attr:`slaunchx_plutus_sdk.client.ApiResponse.is_success`。
"""

from __future__ import annotations

from typing import Any, FrozenSet

__all__ = [
    "SUCCESS_CODES",
    "ACCOUNT_PENDING_APPROVAL",
    "is_success_code",
]

#: 账号待审批。**这是成功码**:登录本身成功,但平台不签发 JWT,``success`` 仍为 ``true``。
ACCOUNT_PENDING_APPROVAL = "2101"

#: 成功族结果码集合。``"2101"`` 是其中的特殊成功码(账号待审批)。
#: 仅作文档与便利用途,不参与成功判定。
SUCCESS_CODES: FrozenSet[str] = frozenset(
    {
        "2000",  # 通用成功
        "2001",  # 创建成功
        "2002",  # 更新成功
        "2004",  # 删除成功
        "2006",  # 已接受 / 异步处理中
        ACCOUNT_PENDING_APPROVAL,  # 账号待审批,仍属成功
    }
)


def is_success_code(code: Any) -> bool:
    """``code`` 是否属于成功族。

    仅作文档与便利用途,**不是成功判定依据** —— 成功判定以包络的 ``success`` 布尔为准。

    :param code: 结果码;非字符串一律返回 ``False``(数字请先字符串化)。
    """
    return isinstance(code, str) and code in SUCCESS_CODES
