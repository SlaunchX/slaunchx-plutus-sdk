"""通用 HTTP 客户端:一次序列化、同一份字节签名并发送,响应强制验签。

本模块只实现传输层,不建立任何业务端点模型:调用方给出外部路径与明文对象即可。
"""

from __future__ import annotations

import json
import uuid
import warnings
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Dict, Mapping, Optional, Type

import requests

from .config import PlutusConfig
from .envelope import decrypt_sensitive_response, encrypt_request_payload
from .errors import (
    ApiError,
    ConfigurationError,
    TransportError,
    error_for_response,
)
from .result_codes import (
    ACCOUNT_PENDING_APPROVAL,
    SUCCESS_CODES,
    is_success_code,
)
from .routes import ENCRYPTED_ROUTE_TEMPLATES, is_known_encrypted_route
from .signer import (
    FORCED_EMPTY_BODY_METHODS,
    QueryInput,
    RequestSigner,
    SignedRequest,
    canonicalize_query,
    current_timestamp_ms,
    encode_query,
)
from .verifier import ResponseVerifier
from .webhook import WebhookReceiver

__all__ = [
    "serialize_json",
    "generate_request_id",
    "ApiResponse",
    "PlutusClient",
    "UnknownEncryptedRouteWarning",
    "SUCCESS_CODES",
    "ACCOUNT_PENDING_APPROVAL",
    "is_success_code",
]


class UnknownEncryptedRouteWarning(UserWarning):
    """加密请求的 ``route_template`` 不在 :data:`~slaunchx_plutus_sdk.routes.ENCRYPTED_ROUTE_TEMPLATES` 中。

    默认(非严格)模式下仅发出本警告,不阻断请求 —— 平台可能已上线尚未收录进 SDK 常量表的
    新加密端点。需要强校验时把 :attr:`PlutusConfig.strict_encrypted_route_validation`
    置为 ``True``,未知路由会改为抛出 :class:`~slaunchx_plutus_sdk.errors.ConfigurationError`。
    """


def serialize_json(payload: Any) -> bytes:
    """把对象序列化为紧凑 UTF-8 JSON 字节。

    全流程只调用一次:同一份字节既用于计算 body 摘要,也用于实际发送。
    """
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def generate_request_id() -> str:
    """生成 ``X-Request-Id``(加密端点必填,参与信封 AAD)。"""
    return "req_" + uuid.uuid4().hex


#: 统一响应包络中被单独提取的键,不再进入 :attr:`ApiResponse.extras`
_ENVELOPE_KEYS = ("version", "timestamp", "success", "code", "message", "data")


def _as_code_string(value: Any) -> Optional[str]:
    """把结果码归一化为字符串。数字码字符串化,``bool`` 与其他类型一律丢弃。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return None


def _parse_envelope(parsed: Any) -> Dict[str, Any]:
    """从已解析的响应体中抽取统一包络字段。

    主路径是权威结构的 ``code`` / ``message``;``errorCode`` / ``error.code`` / ``msg``
    等历史形态仅作次级回退。
    """
    result: Dict[str, Any] = {
        "version": None,
        "timestamp_ms": None,
        "success_flag": None,
        "code": None,
        "message": None,
        "data": None,
        "extras": {},
    }
    if not isinstance(parsed, dict):
        return result

    version = parsed.get("version")
    if isinstance(version, str) and version:
        result["version"] = version

    timestamp = parsed.get("timestamp")
    # ``isinstance(True, int)`` 为真,必须先排除 bool
    if isinstance(timestamp, int) and not isinstance(timestamp, bool):
        result["timestamp_ms"] = timestamp

    success = parsed.get("success")
    # 只有**布尔类型**才是权威 success;字符串 "true" / 数字 1 一律不算
    if isinstance(success, bool):
        result["success_flag"] = success

    code = _as_code_string(parsed.get("code"))
    message = parsed.get("message") if isinstance(parsed.get("message"), str) else None
    nested = parsed.get("error") if isinstance(parsed.get("error"), dict) else {}
    if code is None:  # 次级回退
        code = _as_code_string(parsed.get("errorCode")) or _as_code_string(
            nested.get("code")
        )
    if message is None:  # 次级回退
        for candidate in (parsed.get("msg"), nested.get("message")):
            if isinstance(candidate, str):
                message = candidate
                break
    result["code"] = code
    result["message"] = message
    result["data"] = parsed.get("data")
    result["extras"] = {k: v for k, v in parsed.items() if k not in _ENVELOPE_KEYS}
    return result


@dataclass(frozen=True)
class ApiResponse:
    """统一响应包络。

    平台包络形如::

        {"version":"2.0.0","timestamp":1755600000123,
         "success":true,"code":"2000","message":"Success","data":{}}

    成功判定只看 :attr:`success_flag`(布尔类型的 ``success``);缺失或非布尔时回退到
    HTTP 2xx。结果码常量见 :mod:`slaunchx_plutus_sdk.result_codes`,**不参与**判定。

    ``signature_verified`` 为 ``False`` 说明响应未带签名头且按策略被放行
    (只可能是非 2xx 响应),此时数据不具备平台来源证明。
    """

    status_code: int
    headers: Mapping[str, str]
    content: bytes
    signature_verified: bool
    signed_request: SignedRequest
    json_body: Any = None
    #: 权威结果码,字符串;数字码已字符串化。原值保留在 :attr:`json_body`
    code: Optional[str] = None
    message: Optional[str] = None
    data: Any = None
    #: 包络 ``version``,如 ``"2.0.0"``
    version: Optional[str] = None
    #: 包络 ``timestamp``,Unix 毫秒;非整数时为 ``None``
    timestamp_ms: Optional[int] = None
    #: 权威 ``success`` 布尔。仅当响应体中该键存在**且是布尔类型**时非 ``None``
    success_flag: Optional[bool] = None
    extras: Dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        """响应体文本(UTF-8 解码,非法字节以替换符呈现)。"""
        return self.content.decode("utf-8", errors="replace")

    @property
    def request_id(self) -> Optional[str]:
        """响应头 ``X-Request-Id`` 回显。"""
        return self._header("X-Request-Id")

    @property
    def operation_id(self) -> Optional[str]:
        """响应头 ``X-Operation-Id``(幂等写操作的业务恢复身份)。"""
        return self._header("X-Operation-Id")

    @property
    def response_timestamp(self) -> Optional[str]:
        """响应头 ``X-Response-Timestamp``。"""
        return self._header("X-Response-Timestamp")

    @property
    def is_success(self) -> bool:
        """成功判定。

        响应体是 JSON 对象且 ``success`` 存在并为**布尔类型**时,直接返回该布尔值;
        否则回退到 ``200 <= status_code < 300``。

        不看 ``code``:``"2101"``(账号待审批)是成功码,``"4022"`` 之类业务错误码
        在 HTTP 200 下同样出现,只有 ``success`` 能区分。
        """
        if self.success_flag is not None:
            return self.success_flag
        return 200 <= self.status_code < 300

    @property
    def is_error(self) -> bool:
        """:attr:`is_success` 的反面。"""
        return not self.is_success

    def _header(self, name: str) -> Optional[str]:
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return None


class PlutusClient:
    """SlaunchX Plutus 商户 API 客户端。

    :param config: :class:`~slaunchx_plutus_sdk.config.PlutusConfig`
    :param session: 复用的 ``requests.Session``;不传则内部新建
    """

    def __init__(
        self, config: PlutusConfig, session: Optional[requests.Session] = None
    ) -> None:
        self.config = config
        self._owns_session = session is None
        self._session = session or requests.Session()
        self._signer = RequestSigner(
            config.require_merchant_auth_private(), config.api_key, config.api_version
        )
        self._verifier: Optional[ResponseVerifier] = None
        if config.verify_response_signature and config.platform_auth_public_key is not None:
            self._verifier = ResponseVerifier(config.require_platform_auth_public())

    # -- 生命周期 -----------------------------------------------------------

    def close(self) -> None:
        """关闭内部创建的 ``requests.Session``。"""
        if self._owns_session:
            self._session.close()

    def __enter__(self) -> "PlutusClient":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    # -- 请求 ---------------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        query: QueryInput = None,
        json_body: Any = None,
        body: Optional[bytes] = None,
        content_type: str = "application/json",
        idempotency_key: Optional[str] = None,
        request_id: Optional[str] = None,
        encrypt: bool = False,
        route_template: Optional[str] = None,
        timestamp: Optional[str] = None,
        nonce: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[Any] = None,
    ) -> ApiResponse:
        """签名并发送一次请求。

        :param method: HTTP 方法
        :param path: **外部路径**,以 ``/`` 开头,不含 ``/api`` ``/v1`` ``/consumer`` 前缀
        :param query: 原始 query 串,或映射/键值对序列;实际发出的是规范化结果
        :param json_body: 明文业务对象,内部只序列化一次
        :param body: 直接给定的请求体字节,与 ``json_body`` 互斥
        :param idempotency_key: ``X-Idempotency-Key``;发送即参与签名
        :param request_id: ``X-Request-Id``;``encrypt=True`` 时缺省自动生成
        :param encrypt: 是否按加密端点封装请求体
        :param route_template: 信封 AAD 的 ``routeTemplate``,默认取 ``path``
        :param timestamp: Unix 毫秒字符串,默认取当前时间
        :param nonce: 一次性随机数,默认自动生成
        :raises ApiError: 平台返回错误(可按配置关闭)
        :raises ResponseSignatureError: 响应验签失败
        :raises TransportError: 网络层失败
        """
        method_upper = method.upper()
        if json_body is not None and body is not None:
            raise ConfigurationError("json_body 与 body 不能同时提供")

        raw_query = encode_query(query)
        canonical_query = canonicalize_query(raw_query)
        ts = timestamp or current_timestamp_ms()
        extra_headers: Dict[str, str] = dict(self.config.default_headers)
        if headers:
            extra_headers.update(headers)

        payload_bytes: Optional[bytes]
        if encrypt:
            resolved_route_template = route_template or path
            if not is_known_encrypted_route(resolved_route_template):
                if self.config.strict_encrypted_route_validation:
                    raise ConfigurationError(
                        "route_template 不在已知加密端点表中: %r;已知端点见 "
                        "slaunchx_plutus_sdk.routes.ENCRYPTED_ROUTE_TEMPLATES %r"
                        % (resolved_route_template, ENCRYPTED_ROUTE_TEMPLATES)
                    )
                warnings.warn(
                    "route_template %r 不在已知加密端点表中(可能是平台新增端点,"
                    "SDK 常量表尚未收录);请求不受影响,仍会正常发出。"
                    "如需强校验,设置 PlutusConfig.strict_encrypted_route_validation=True"
                    % resolved_route_template,
                    UnknownEncryptedRouteWarning,
                    stacklevel=2,
                )
            plaintext = body if body is not None else serialize_json(json_body or {})
            request_id = request_id or generate_request_id()
            envelope = encrypt_request_payload(
                self.config.require_platform_enc_public(),
                plaintext,
                request_id=request_id,
                route_template=resolved_route_template,
                timestamp=ts,
                key_id=self.config.platform_encryption_key_id,
            )
            payload_bytes = serialize_json(envelope)
        elif json_body is not None:
            payload_bytes = serialize_json(json_body)
        else:
            payload_bytes = body

        if method_upper in FORCED_EMPTY_BODY_METHODS:
            payload_bytes = None

        signed = self._signer.sign(
            method_upper,
            path,
            query=canonical_query or None,
            body=payload_bytes,
            idempotency_key=idempotency_key,
            timestamp=ts,
            nonce=nonce,
            request_id=request_id,
            platform_encryption_key_id=(
                self.config.platform_encryption_key_id if encrypt else None
            ),
        )

        wire_headers: Dict[str, str] = dict(extra_headers)
        wire_headers.update(signed.headers)
        wire_headers.setdefault("Accept", "application/json")
        wire_headers.setdefault("User-Agent", self.config.user_agent)
        if payload_bytes is not None:
            wire_headers["Content-Type"] = content_type

        url = self.config.base_url + path
        if canonical_query:
            url = url + "?" + canonical_query

        try:
            raw = self._session.request(
                method=method_upper,
                url=url,
                headers=wire_headers,
                data=payload_bytes,
                timeout=timeout if timeout is not None else self.config.timeout,
            )
        except requests.RequestException as exc:
            raise TransportError("HTTP 请求失败: %s" % exc) from exc

        return self._build_response(signed, path, raw)

    def get(self, path: str, **kwargs: Any) -> ApiResponse:
        """发送 ``GET`` 请求(强制空 body 摘要)。"""
        return self.request("GET", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> ApiResponse:
        """发送 ``DELETE`` 请求(强制空 body 摘要)。"""
        return self.request("DELETE", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> ApiResponse:
        """发送 ``POST`` 请求。"""
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> ApiResponse:
        """发送 ``PUT`` 请求。"""
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> ApiResponse:
        """发送 ``PATCH`` 请求。"""
        return self.request("PATCH", path, **kwargs)

    # -- 敏感响应 / Webhook -------------------------------------------------

    def decrypt_sensitive(
        self,
        envelope: Mapping[str, Any],
        *,
        request_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> bytes:
        """解密响应体中的敏感信封,返回明文字节。"""
        return decrypt_sensitive_response(
            self.config.require_merchant_enc_private(),
            envelope,
            request_id=request_id,
            timestamp=timestamp,
            key_id=self.config.merchant_encryption_key_id,
            max_plaintext_bytes=self.config.max_plaintext_bytes,
        )

    def webhook_receiver(self, **kwargs: Any) -> WebhookReceiver:
        """按当前配置构造 :class:`~slaunchx_plutus_sdk.webhook.WebhookReceiver`。"""
        kwargs.setdefault("api_key", self.config.api_key)
        kwargs.setdefault("max_plaintext_bytes", self.config.max_plaintext_bytes)
        return WebhookReceiver(
            self.config.require_platform_auth_public(),
            self.config.require_merchant_enc_private(),
            **kwargs,
        )

    # -- 内部 ---------------------------------------------------------------

    def _build_response(
        self, signed: SignedRequest, path: str, raw: Any
    ) -> ApiResponse:
        content: bytes = raw.content or b""
        headers: Mapping[str, str] = raw.headers
        verified = False
        if self._verifier is not None:
            verified = self._verifier.verify(
                request_canonical_sha256=signed.canonical_sha256,
                api_version=self.config.api_version,
                external_path=path,
                http_status=raw.status_code,
                headers=headers,
                body=content,
                require_signature_on_error=(
                    self.config.require_signature_on_error_responses
                ),
            )
        elif self.config.require_signature_on_error_responses:
            raise ConfigurationError(
                "require_signature_on_error_responses=True 但未配置 platform_auth_public_key"
            )

        parsed: Any = None
        if content:
            try:
                parsed = json.loads(content.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                parsed = None

        envelope = _parse_envelope(parsed)
        response = ApiResponse(
            status_code=raw.status_code,
            headers=headers,
            content=content,
            signature_verified=verified,
            signed_request=signed,
            json_body=parsed,
            code=envelope["code"],
            message=envelope["message"],
            data=envelope["data"],
            version=envelope["version"],
            timestamp_ms=envelope["timestamp_ms"],
            success_flag=envelope["success_flag"],
            extras=envelope["extras"],
        )

        http_failed = raw.status_code >= 400 and self.config.raise_on_http_error
        # 业务失败:包络 success 明确为 False(HTTP 200 + success:false 也算)
        business_failed = (
            response.success_flag is False and self.config.raise_on_business_error
        )
        if http_failed or business_failed:
            raise self._to_error(response)
        return response

    @staticmethod
    def _to_error(response: ApiResponse) -> ApiError:
        code = response.code
        message = response.message or code or ("HTTP %d" % response.status_code)
        return error_for_response(
            response.status_code,
            code,
            message,
            data=response.data,
            response=response,
            headers=response.headers,
        )
