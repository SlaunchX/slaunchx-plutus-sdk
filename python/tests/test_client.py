"""HTTP 客户端端到端:头组装、同一字节签名并发送、响应验签、错误映射。"""

from __future__ import annotations

import base64
import hashlib
import json
import warnings
from typing import Any, Dict, List, Optional

import pytest
import requests

from slaunchx_plutus_sdk import (
    ApiError,
    ApiResponse,
    AuthenticationError,
    ConfigurationError,
    ConflictError,
    NotFoundError,
    PlutusClient,
    PlutusConfig,
    PublicErrorCode,
    RateLimitedError,
    ResponseSignatureError,
    SecureChannelError,
    TransportError,
    UnknownEncryptedRouteWarning,
    ValidationError,
    build_aad,
    build_response_canonical_string,
    decrypt_envelope,
    response_body_sha256_hex,
    sign_canonical_string,
)
from slaunchx_plutus_sdk.errors import TimestampExpiredError
from slaunchx_plutus_sdk.routes import ENCRYPTED_ROUTE_TEMPLATES
from slaunchx_plutus_sdk.signer import NONCE_PATTERN

UNKNOWN_ENCRYPTED_ROUTE = "/card-products/99999999/cards/create"

BASE_URL = "https://consumer-api.example.test"
API_KEY = "apk_vector_0001"

#: 平台统一响应包络的标准成功形态
SUCCESS_ENVELOPE = (
    b'{"version":"2.0.0","timestamp":1755600000123,'
    b'"success":true,"code":"2000","message":"Success","data":{"ok":true}}'
)


def envelope_bytes(**overrides: Any) -> bytes:
    """构造统一响应包络字节。"""
    body: Dict[str, Any] = {
        "version": "2.0.0",
        "timestamp": 1755600000123,
        "success": True,
        "code": "2000",
        "message": "Success",
        "data": {"ok": True},
    }
    body.update(overrides)
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class _FakeResponse:
    def __init__(self, status_code: int, headers: Dict[str, str], content: bytes) -> None:
        self.status_code = status_code
        self.headers = headers
        self.content = content


class _FakeSession:
    """记录请求并按平台规则签发响应的假 Session。"""

    def __init__(self, platform_auth_private, api_version: str = "1") -> None:
        self.calls: List[Dict[str, Any]] = []
        self._private = platform_auth_private
        self._api_version = api_version
        self.status_code = 200
        self.response_body = SUCCESS_ENVELOPE
        self.content_type = "application/json;charset=UTF-8"
        self.operation_id: Optional[str] = None
        self.sign_response = True
        self.raise_exception: Optional[Exception] = None

    def close(self) -> None:
        pass

    def request(self, *, method, url, headers, data, timeout):
        if self.raise_exception is not None:
            raise self.raise_exception
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "body": data,
                "timeout": timeout,
            }
        )
        path, _, query = url[len(BASE_URL) :].partition("?")
        canonical_request = "\n".join(
            [
                method,
                path,
                query,
                headers["X-Timestamp"],
                headers["X-Nonce"],
                headers["X-API-VERSION"],
                headers.get("X-Idempotency-Key", ""),
                hashlib.sha256(data).hexdigest()
                if data and method not in ("GET", "HEAD", "DELETE")
                else hashlib.sha256(b"").hexdigest(),
            ]
        )
        request_id = headers.get("X-Request-Id", "req_fake_0001")
        response_headers = {
            "Content-Type": self.content_type,
            "X-Request-Id": request_id,
            "X-Response-Timestamp": "1755600000123",
            "X-Response-Signature-Algorithm": "RSA-SHA256",
        }
        if self.operation_id:
            response_headers["X-Operation-Id"] = self.operation_id
        if self.sign_response:
            canonical_response = build_response_canonical_string(
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
                self._api_version,
                path,
                self.operation_id,
                request_id,
                self.status_code,
                self.content_type,
                "1755600000123",
                response_body_sha256_hex(self.response_body),
            )
            response_headers["X-Response-Signature"] = sign_canonical_string(
                self._private, canonical_response
            )
        return _FakeResponse(self.status_code, response_headers, self.response_body)


@pytest.fixture()
def session(private_keys) -> _FakeSession:
    return _FakeSession(private_keys["platform_auth"])


@pytest.fixture()
def config(keys) -> PlutusConfig:
    return PlutusConfig(
        base_url=BASE_URL + "/",
        api_key=API_KEY,
        merchant_auth_private_key=keys["merchant_auth"]["privateKeyPem"],
        platform_auth_public_key=keys["platform_auth"]["publicKeyPem"],
        platform_enc_public_key=keys["platform_enc"]["publicKeyPem"],
        merchant_enc_private_key=keys["merchant_enc"]["privateKeyPem"],
    )


@pytest.fixture()
def client(config: PlutusConfig, session: _FakeSession) -> PlutusClient:
    return PlutusClient(config, session=session)  # type: ignore[arg-type]


def test_get_assembles_headers_and_verifies_response(
    client: PlutusClient, session: _FakeSession, public_keys
) -> None:
    response = client.get("/card-products/cards/page", query={"pageSize": 20, "cursor": ""})
    call = session.calls[0]
    headers = call["headers"]
    assert call["method"] == "GET"
    assert call["url"] == BASE_URL + "/card-products/cards/page?cursor=&pageSize=20"
    assert call["body"] is None
    assert headers["X-Api-Key"] == API_KEY
    assert headers["X-API-VERSION"] == "1"
    assert headers["X-Signature-Algorithm"] == "RSA-SHA256"
    assert headers["X-Timestamp"].isdigit() and len(headers["X-Timestamp"]) == 13
    assert NONCE_PATTERN.match(headers["X-Nonce"])
    assert base64.b64decode(headers["X-Signature"])
    assert "X-Idempotency-Key" not in headers
    assert "Content-Type" not in headers
    assert response.status_code == 200
    assert response.signature_verified is True
    assert response.code == "2000"
    assert response.success_flag is True
    assert response.is_success is True
    assert response.is_error is False
    assert response.version == "2.0.0"
    assert response.timestamp_ms == 1755600000123
    assert response.message == "Success"
    assert response.data == {"ok": True}
    assert response.request_id == "req_fake_0001"
    assert response.signed_request.canonical_query == "cursor=&pageSize=20"


def test_post_serializes_body_once(client: PlutusClient, session: _FakeSession) -> None:
    payload = {"platformCardProductBizId": "pcp_example_001", "quantity": 2}
    session.status_code = 201
    session.operation_id = "op_fake_0001"
    response = client.post(
        "/card-products/10010106/shared/cards/create",
        json_body=payload,
        idempotency_key="idem-local-0000000001",
    )
    call = session.calls[0]
    assert call["body"] == b'{"platformCardProductBizId":"pcp_example_001","quantity":2}'
    assert call["headers"]["Content-Type"] == "application/json"
    assert call["headers"]["X-Idempotency-Key"] == "idem-local-0000000001"
    # 规范串第 8 行是实际发送字节的摘要
    assert call["headers"]["X-Idempotency-Key"] in response.signed_request.canonical_string
    assert response.signed_request.body_hash == hashlib.sha256(call["body"]).hexdigest()
    assert response.operation_id == "op_fake_0001"
    assert response.signature_verified is True


def test_signed_bytes_are_the_wire_bytes(
    client: PlutusClient, session: _FakeSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """不变量:参与签名的 body 字节与实际发往传输层的字节是同一份,且只序列化一次。"""
    import slaunchx_plutus_sdk.client as client_module

    calls: List[Any] = []
    original = client_module.serialize_json

    def _counting(payload: Any) -> bytes:
        calls.append(payload)
        return original(payload)

    monkeypatch.setattr(client_module, "serialize_json", _counting)

    payload = {"note": "中文测试", "quantity": 2}
    response = client.post("/card-products/cards/remark/update", json_body=payload)

    assert len(calls) == 1, "json_body 必须只序列化一次"
    wire_body = session.calls[0]["body"]
    signed_body = response.signed_request.body
    # 同一个 bytes 对象,不只是逐字节相等
    assert wire_body is signed_body
    assert wire_body == signed_body
    assert response.signed_request.body_hash == hashlib.sha256(wire_body).hexdigest()
    # 规范串第 8 行就是这份字节的摘要
    assert response.signed_request.canonical_string.split("\n")[7] == (
        hashlib.sha256(wire_body).hexdigest()
    )


def test_encrypted_signed_bytes_are_the_wire_bytes(
    client: PlutusClient, session: _FakeSession
) -> None:
    """加密端点同样满足:签名的信封字节就是发送的字节。"""
    response = client.post(
        "/card-products/10010106/shared/cards/create",
        json_body={"platformCardProductBizId": "pcp_example_001"},
        encrypt=True,
    )
    assert session.calls[0]["body"] is response.signed_request.body


def test_delete_forces_empty_body(client: PlutusClient, session: _FakeSession) -> None:
    response = client.delete(
        "/card-products/cards/cancel",
        query="reason=CLOSED_BY_MERCHANT",
        json_body={"ignored": True},
    )
    assert session.calls[0]["body"] is None
    assert response.signed_request.body_hash.startswith("e3b0c442")


def test_unicode_body_is_utf8(client: PlutusClient, session: _FakeSession) -> None:
    client.post("/card-products/cards/remark/update", json_body={"note": "中文测试"})
    assert session.calls[0]["body"] == '{"note":"中文测试"}'.encode("utf-8")


def test_encrypted_endpoint(client: PlutusClient, session: _FakeSession, private_keys, keys) -> None:
    path = "/card-products/10010106/shared/cards/create"
    response = client.post(
        path, json_body={"platformCardProductBizId": "pcp_example_001"}, encrypt=True
    )
    call = session.calls[0]
    headers = call["headers"]
    fingerprint = keys["platform_enc"]["fingerprint"]
    assert headers["X-Platform-Encryption-Key-Id"] == fingerprint
    assert headers["X-Request-Id"].startswith("req_")
    envelope = json.loads(call["body"])
    assert envelope["algorithm"] == "RSA-OAEP-AES-256-GCM"
    assert envelope["encryptedPayload"] == envelope["ciphertext"]
    aad = build_aad(headers["X-Request-Id"], path, headers["X-Timestamp"], fingerprint)
    assert base64.b64decode(envelope["aad"]) == aad
    plaintext = decrypt_envelope(private_keys["platform_enc"], envelope, aad)
    assert json.loads(plaintext) == {"platformCardProductBizId": "pcp_example_001"}
    # 签名的 body 摘要是信封 JSON 字节的摘要
    assert response.signed_request.body_hash == hashlib.sha256(call["body"]).hexdigest()


def test_decrypt_sensitive_response_through_client(client: PlutusClient, vectors) -> None:
    case = [
        c
        for c in vectors["vectors"]["encryptedEnvelope"]
        if c["direction"] == "sensitive_response"
    ][0]
    plaintext = client.decrypt_sensitive(case["envelope"])
    assert plaintext.decode("utf-8") == case["expectedPlaintext"]


def test_response_signature_failure_is_fatal(
    client: PlutusClient, session: _FakeSession
) -> None:
    original = session.request

    def _tamper(**kwargs):
        raw = original(**kwargs)
        return _FakeResponse(raw.status_code, raw.headers, raw.content + b" ")

    session.request = _tamper  # type: ignore[assignment]
    with pytest.raises(ResponseSignatureError):
        client.get("/card-products/cards/page")


def test_unsigned_2xx_response_is_rejected(
    client: PlutusClient, session: _FakeSession
) -> None:
    """HTTP 2xx 缺签名头必须抛验签异常(默认配置)。"""
    session.sign_response = False
    with pytest.raises(ResponseSignatureError):
        client.get("/card-products/cards/page")


def test_unsigned_non_2xx_response_is_allowed(
    config: PlutusConfig, session: _FakeSession
) -> None:
    """非 2xx 缺签名头默认放行,但 signature_verified 必须为 False。"""
    config.raise_on_http_error = False
    config.raise_on_business_error = False
    session.sign_response = False
    session.status_code = 401
    session.response_body = envelope_bytes(
        success=False, code="API.SIGNATURE_INVALID", message="bad signature", data=None
    )
    client = PlutusClient(config, session=session)  # type: ignore[arg-type]
    response = client.get("/card-products/cards/page")
    assert response.signature_verified is False
    assert response.is_error is True
    assert response.code == "API.SIGNATURE_INVALID"


def test_unsigned_non_2xx_response_surfaces_typed_error(
    client: PlutusClient, session: _FakeSession
) -> None:
    """非 2xx 缺签名头放行后,仍按类型化 API 错误抛出,且响应未验签。"""
    session.sign_response = False
    session.status_code = 401
    session.response_body = envelope_bytes(
        success=False, code="API.SIGNATURE_INVALID", message="bad signature", data=None
    )
    with pytest.raises(AuthenticationError) as excinfo:
        client.get("/card-products/cards/page")
    assert excinfo.value.response.signature_verified is False


def test_unsigned_non_2xx_rejected_when_strict_switch_on(
    config: PlutusConfig, session: _FakeSession
) -> None:
    """严格开关打开后,非 2xx 缺签名头也抛验签异常。"""
    config.require_signature_on_error_responses = True
    session.sign_response = False
    session.status_code = 401
    session.response_body = envelope_bytes(
        success=False, code="API.SIGNATURE_INVALID", message="bad signature", data=None
    )
    client = PlutusClient(config, session=session)  # type: ignore[arg-type]
    with pytest.raises(ResponseSignatureError):
        client.get("/card-products/cards/page")


def test_verification_can_be_disabled(config: PlutusConfig, session: _FakeSession) -> None:
    config.verify_response_signature = False
    session.sign_response = False
    client = PlutusClient(config, session=session)  # type: ignore[arg-type]
    assert client.get("/card-products/cards/page").signature_verified is False


@pytest.mark.parametrize(
    "status,code,expected",
    [
        (401, "API.SIGNATURE_INVALID", AuthenticationError),
        (401, "API.TIMESTAMP_EXPIRED", TimestampExpiredError),
        (403, "ACCESS.PERMISSION_DENIED", ApiError),
        (404, "RESOURCE.NOT_FOUND", NotFoundError),
        (409, "REQUEST.CONFLICT", ConflictError),
        (429, "REQUEST.RATE_LIMITED", RateLimitedError),
        (400, "SECURE_CHANNEL.INVALID_PAYLOAD", SecureChannelError),
        (400, "VALIDATION.INVALID_PARAMETER", ValidationError),
        (500, "SYSTEM.INTERNAL_ERROR", ApiError),
    ],
)
def test_error_mapping(
    client: PlutusClient,
    session: _FakeSession,
    status: int,
    code: str,
    expected: type,
) -> None:
    session.status_code = status
    session.response_body = envelope_bytes(
        success=False, code=code, message="boom", data=None
    )
    with pytest.raises(expected) as excinfo:
        client.get("/card-products/cards/page")
    error = excinfo.value
    assert isinstance(error, ApiError)
    assert error.status_code == status
    assert error.code == code
    assert error.error_code is PublicErrorCode(code)
    assert error.message == "boom"
    assert error.request_id == "req_fake_0001"
    assert isinstance(error.response, ApiResponse)
    # 错误响应同样带签名,必须先验签再抛错
    assert error.response.signature_verified is True


def test_rate_limited_retry_after(client: PlutusClient, session: _FakeSession) -> None:
    session.status_code = 429
    session.response_body = envelope_bytes(
        success=False, code="REQUEST.RATE_LIMITED", message="slow down", data=None
    )
    with pytest.raises(RateLimitedError) as excinfo:
        client.get("/card-products/cards/page")
    assert excinfo.value.retryable is True
    assert excinfo.value.retry_after is None


def test_business_error_code_on_http_200(client: PlutusClient, session: _FakeSession) -> None:
    session.response_body = envelope_bytes(
        success=False, code="VALIDATION.INVALID_PARAMETER", message="bad", data=None
    )
    with pytest.raises(ValidationError):
        client.get("/card-products/cards/page")


def test_numeric_business_error_on_http_200(
    client: PlutusClient, session: _FakeSession
) -> None:
    """HTTP 200 + success:false 的数字业务错误码同样抛 ApiError,错误码不被丢弃。"""
    session.response_body = envelope_bytes(
        success=False, code="4022", message="Validation Error", data=None
    )
    with pytest.raises(ApiError) as excinfo:
        client.get("/card-products/cards/page")
    assert excinfo.value.status_code == 200
    assert excinfo.value.code == "4022"
    assert excinfo.value.message == "Validation Error"


def test_business_error_can_be_disabled(
    config: PlutusConfig, session: _FakeSession
) -> None:
    config.raise_on_business_error = False
    session.response_body = envelope_bytes(
        success=False, code="VALIDATION.INVALID_PARAMETER", message="bad", data=None
    )
    client = PlutusClient(config, session=session)  # type: ignore[arg-type]
    response = client.get("/card-products/cards/page")
    assert response.is_error is True
    assert response.is_success is False
    assert response.success_flag is False
    assert response.code == "VALIDATION.INVALID_PARAMETER"


def test_transport_error_is_wrapped(client: PlutusClient, session: _FakeSession) -> None:
    session.raise_exception = requests.ConnectionError("boom")
    with pytest.raises(TransportError):
        client.get("/card-products/cards/page")


def test_context_manager_and_defaults(config: PlutusConfig, session: _FakeSession) -> None:
    config.default_headers = {"X-Tenant": "demo"}
    with PlutusClient(config, session=session) as client:  # type: ignore[arg-type]
        client.get("/card-products/cards/page")
    headers = session.calls[0]["headers"]
    assert headers["X-Tenant"] == "demo"
    assert headers["Accept"] == "application/json"
    assert headers["User-Agent"] == "slaunchx-plutus-sdk-python"
    assert session.calls[0]["timeout"] == 30.0


def test_base_url_trailing_slash_normalized(config: PlutusConfig) -> None:
    assert config.base_url == BASE_URL


def test_webhook_receiver_from_client(client: PlutusClient, vectors) -> None:
    case = vectors["vectors"]["webhook"][0]
    receiver = client.webhook_receiver()
    event = receiver.handle(case["body"].encode("utf-8"), case["headers"])
    assert event.plaintext.decode("utf-8") == case["expectedPlaintext"]


def test_illegal_query_raises_before_sending(
    client: PlutusClient, session: _FakeSession
) -> None:
    from slaunchx_plutus_sdk import CanonicalQueryError

    with pytest.raises(CanonicalQueryError):
        client.get("/card-products/cards/page", query="q=a+b")
    assert session.calls == []


def test_json_body_and_body_are_exclusive(client: PlutusClient) -> None:
    from slaunchx_plutus_sdk import ConfigurationError

    with pytest.raises(ConfigurationError):
        client.post("/x", json_body={"a": 1}, body=b"{}")


def test_known_encrypted_route_does_not_warn(client: PlutusClient, session: _FakeSession) -> None:
    """已知加密端点默认模式下不发出任何警告。"""
    known_route = ENCRYPTED_ROUTE_TEMPLATES[0]
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        response = client.post(
            known_route, json_body={"platformCardProductBizId": "pcp_example_001"}, encrypt=True
        )
    assert response.status_code == 200
    assert session.calls[0]["url"] == BASE_URL + known_route


def test_unknown_encrypted_route_warns_but_completes(
    client: PlutusClient, session: _FakeSession
) -> None:
    """默认(非严格)模式下,未知加密路由只发出警告,请求仍正常完成。"""
    with pytest.warns(UnknownEncryptedRouteWarning):
        response = client.post(
            UNKNOWN_ENCRYPTED_ROUTE,
            json_body={"platformCardProductBizId": "pcp_example_001"},
            encrypt=True,
        )
    assert response.status_code == 200
    assert len(session.calls) == 1
    assert session.calls[0]["url"] == BASE_URL + UNKNOWN_ENCRYPTED_ROUTE


def test_unknown_encrypted_route_raises_in_strict_mode(
    config: PlutusConfig, session: _FakeSession
) -> None:
    """严格模式下,未知加密路由直接抛 ConfigurationError,请求不会发出。"""
    config.strict_encrypted_route_validation = True
    client = PlutusClient(config, session=session)  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError):
        client.post(
            UNKNOWN_ENCRYPTED_ROUTE,
            json_body={"platformCardProductBizId": "pcp_example_001"},
            encrypt=True,
        )
    assert session.calls == []


def test_known_encrypted_route_unaffected_by_strict_mode(
    config: PlutusConfig, session: _FakeSession
) -> None:
    """严格模式下,已知加密端点不受影响,既不抛异常也不发警告。"""
    config.strict_encrypted_route_validation = True
    client = PlutusClient(config, session=session)  # type: ignore[arg-type]
    known_route = ENCRYPTED_ROUTE_TEMPLATES[0]
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        response = client.post(
            known_route, json_body={"platformCardProductBizId": "pcp_example_001"}, encrypt=True
        )
    assert response.status_code == 200
