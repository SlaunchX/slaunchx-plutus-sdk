"""统一响应包络与成功判定。

判定算法(五语言逐字对齐)::

    isSuccess(parsedBody, httpStatus):
        如果 parsedBody 是 JSON 对象,且键 "success" 存在且其值是布尔类型:
            返回 该布尔值
        否则:
            返回 200 <= httpStatus < 300

本文件全部使用本地 fixture,不取自 ``shared/test-vectors.json``。
"""

from __future__ import annotations

import json
from typing import Any, Optional

import pytest

from slaunchx_plutus_sdk import (
    ACCOUNT_PENDING_APPROVAL,
    SUCCESS_CODES,
    ApiError,
    PlutusClient,
    PlutusConfig,
    is_success_code,
)

from test_client import BASE_URL, _FakeSession


def _body(payload: Any) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@pytest.fixture()
def session(private_keys) -> _FakeSession:
    return _FakeSession(private_keys["platform_auth"])


@pytest.fixture()
def lenient_config(keys) -> PlutusConfig:
    """不抛错的配置,便于直接检查 ApiResponse 的判定结果。"""
    return PlutusConfig(
        base_url=BASE_URL,
        api_key="apk_vector_0001",
        merchant_auth_private_key=keys["merchant_auth"]["privateKeyPem"],
        platform_auth_public_key=keys["platform_auth"]["publicKeyPem"],
        raise_on_http_error=False,
        raise_on_business_error=False,
    )


def _fetch(config: PlutusConfig, session: _FakeSession, status: int, body: bytes):
    session.status_code = status
    session.response_body = body
    client = PlutusClient(config, session=session)  # type: ignore[arg-type]
    return client.get("/card-products/cards/page")


# 契约「测试要求」表格的 7 个用例
_CASES = [
    pytest.param(
        200,
        {
            "version": "2.0.0",
            "timestamp": 1755600000123,
            "success": True,
            "code": "2000",
            "message": "Success",
            "data": {"ok": True},
        },
        True,
        "2000",
        id="standard-success",
    ),
    pytest.param(
        201,
        {
            "version": "2.0.0",
            "timestamp": 1755600000123,
            "success": True,
            "code": "2001",
            "message": "Created",
            "data": {"bizId": "card_example_001"},
        },
        True,
        "2001",
        id="created-success",
    ),
    pytest.param(
        200,
        {
            "version": "2.0.0",
            "timestamp": 1755600000123,
            "success": True,
            "code": "2101",
            "message": "Account pending approval",
            "data": None,
        },
        True,
        "2101",
        id="pending-approval-success",
    ),
    pytest.param(
        200,
        {
            "version": "2.0.0",
            "timestamp": 1755600000123,
            "success": False,
            "code": "4022",
            "message": "Validation Error",
            "data": None,
        },
        False,
        "4022",
        id="business-failure-on-http-200",
    ),
    pytest.param(
        401,
        {
            "version": "2.0.0",
            "timestamp": 1755600000123,
            "success": False,
            "code": "API.SIGNATURE_INVALID",
            "message": "Signature invalid",
            "data": None,
        },
        False,
        "API.SIGNATURE_INVALID",
        id="gateway-failure",
    ),
    pytest.param(200, {"data": {}}, True, None, id="no-success-field-http-2xx"),
    pytest.param(500, {"message": "boom"}, False, None, id="no-success-field-http-5xx"),
]


@pytest.mark.parametrize("status,payload,expected_success,expected_code", _CASES)
def test_success_determination(
    lenient_config: PlutusConfig,
    session: _FakeSession,
    status: int,
    payload: Any,
    expected_success: bool,
    expected_code: Optional[str],
) -> None:
    response = _fetch(lenient_config, session, status, _body(payload))
    assert response.is_success is expected_success
    assert response.is_error is (not expected_success)
    assert response.code == expected_code


@pytest.mark.parametrize(
    "status,success_value,expected",
    [
        (200, "true", True),
        (200, "false", True),
        (200, 1, True),
        (200, 0, True),
        (200, None, True),
        (500, "true", False),
        (500, 1, False),
        (500, None, False),
    ],
)
def test_non_boolean_success_falls_back_to_http_status(
    lenient_config: PlutusConfig,
    session: _FakeSession,
    status: int,
    success_value: Any,
    expected: bool,
) -> None:
    """只有布尔类型的 ``success`` 才是权威;字符串 / 数字 / null 一律走 HTTP 回退。"""
    response = _fetch(
        lenient_config, session, status, _body({"success": success_value, "data": {}})
    )
    assert response.success_flag is None
    assert response.is_success is expected


def test_boolean_success_overrides_http_status(
    lenient_config: PlutusConfig, session: _FakeSession
) -> None:
    """``success:true`` 配 HTTP 500 仍判成功;``success:false`` 配 HTTP 200 判失败。"""
    ok = _fetch(lenient_config, session, 500, _body({"success": True, "code": "2000"}))
    assert ok.success_flag is True and ok.is_success is True

    bad = _fetch(lenient_config, session, 200, _body({"success": False, "code": "5001"}))
    assert bad.success_flag is False and bad.is_success is False
    assert bad.code == "5001"


def test_numeric_code_is_stringified(
    lenient_config: PlutusConfig, session: _FakeSession
) -> None:
    """数字结果码字符串化后保留,不因「看起来是数字」被丢弃;原值仍可从 json_body 读取。"""
    response = _fetch(
        lenient_config, session, 200, _body({"success": False, "code": 4022, "message": "x"})
    )
    assert response.code == "4022"
    assert response.json_body["code"] == 4022


def test_non_json_body_falls_back_to_http_status(
    lenient_config: PlutusConfig, session: _FakeSession
) -> None:
    assert _fetch(lenient_config, session, 200, b"not json").is_success is True
    assert _fetch(lenient_config, session, 503, b"not json").is_success is False
    assert _fetch(lenient_config, session, 204, b"").is_success is True


def test_envelope_fields_are_extracted(
    lenient_config: PlutusConfig, session: _FakeSession
) -> None:
    response = _fetch(
        lenient_config,
        session,
        200,
        _body(
            {
                "version": "2.0.0",
                "timestamp": 1755600000123,
                "success": True,
                "code": "2000",
                "message": "Success",
                "data": {"ok": True},
                "traceId": "trace_0001",
            }
        ),
    )
    assert response.version == "2.0.0"
    assert response.timestamp_ms == 1755600000123
    assert response.success_flag is True
    assert response.message == "Success"
    assert response.data == {"ok": True}
    # 包络固有键不进 extras,厂商附加键才进
    assert response.extras == {"traceId": "trace_0001"}


def test_boolean_timestamp_is_rejected(
    lenient_config: PlutusConfig, session: _FakeSession
) -> None:
    """``isinstance(True, int)`` 为真,timestamp 判定必须先排除 bool。"""
    response = _fetch(
        lenient_config, session, 200, _body({"success": True, "timestamp": True})
    )
    assert response.timestamp_ms is None


def test_pending_approval_does_not_raise(keys, session: _FakeSession) -> None:
    """``2101`` 账号待审批是成功码,默认配置下不抛错。"""
    config = PlutusConfig(
        base_url=BASE_URL,
        api_key="apk_vector_0001",
        merchant_auth_private_key=keys["merchant_auth"]["privateKeyPem"],
        platform_auth_public_key=keys["platform_auth"]["publicKeyPem"],
    )
    response = _fetch(
        config,
        session,
        200,
        _body({"success": True, "code": "2101", "message": "Pending approval"}),
    )
    assert response.is_success is True
    assert response.code == ACCOUNT_PENDING_APPROVAL


def test_http_200_business_failure_raises_by_default(
    keys, session: _FakeSession
) -> None:
    """默认配置下,HTTP 200 + ``success:false`` 必须抛 ApiError。"""
    config = PlutusConfig(
        base_url=BASE_URL,
        api_key="apk_vector_0001",
        merchant_auth_private_key=keys["merchant_auth"]["privateKeyPem"],
        platform_auth_public_key=keys["platform_auth"]["publicKeyPem"],
    )
    with pytest.raises(ApiError) as excinfo:
        _fetch(
            config,
            session,
            200,
            _body({"success": False, "code": "4022", "message": "Validation Error"}),
        )
    assert excinfo.value.status_code == 200
    assert excinfo.value.code == "4022"


def test_success_codes_constant() -> None:
    assert SUCCESS_CODES == frozenset({"2000", "2001", "2002", "2004", "2006", "2101"})
    assert ACCOUNT_PENDING_APPROVAL == "2101"
    assert ACCOUNT_PENDING_APPROVAL in SUCCESS_CODES
    for code in SUCCESS_CODES:
        assert is_success_code(code) is True
    assert is_success_code("4022") is False
    assert is_success_code("API.SIGNATURE_INVALID") is False
    # 只接受字符串;数字码请先字符串化
    assert is_success_code(2000) is False
    assert is_success_code(None) is False


def test_success_codes_do_not_drive_determination(
    lenient_config: PlutusConfig, session: _FakeSession
) -> None:
    """成功码常量不参与判定:成功码 + ``success:false`` 仍判失败。"""
    response = _fetch(
        lenient_config, session, 200, _body({"success": False, "code": "2000"})
    )
    assert is_success_code(response.code) is True
    assert response.is_success is False
