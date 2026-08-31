"""异常体系与平台错误码。

所有 SDK 抛出的异常都继承自 :class:`PlutusError`。协议层错误(签名、信封、Webhook)
在本地抛出,不发出必然被拒的请求;平台返回的错误按 ``PublicErrorCode`` 映射为类型化异常。
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Mapping, Optional, Type

__all__ = [
    "PlutusError",
    "ConfigurationError",
    "CanonicalQueryError",
    "SignatureError",
    "ResponseSignatureError",
    "EnvelopeError",
    "WebhookError",
    "WebhookSignatureError",
    "WebhookEnvelopeError",
    "WebhookPayloadError",
    "TransportError",
    "ApiError",
    "AuthenticationError",
    "PermissionDeniedError",
    "ValidationError",
    "NotFoundError",
    "ConflictError",
    "RateLimitedError",
    "SecureChannelError",
    "EndpointRetiredError",
    "ServerError",
    "PublicErrorCode",
    "error_for_response",
]


class PlutusError(Exception):
    """SDK 所有异常的基类。"""


class ConfigurationError(PlutusError):
    """配置缺失或非法(如未提供解密所需的私钥)。"""


class CanonicalQueryError(PlutusError, ValueError):
    """query 串不满足 RFC 3986 规范化要求,无法参与签名。"""


class SignatureError(PlutusError):
    """签名相关错误。"""


class ResponseSignatureError(SignatureError):
    """响应验签失败或缺失签名头。响应体必须丢弃,不得交给业务代码。"""


class EnvelopeError(PlutusError):
    """混合加密信封结构非法、AAD 不匹配或 GCM 认证失败。"""


class WebhookError(PlutusError):
    """Webhook 处理错误。"""


class WebhookSignatureError(WebhookError, SignatureError):
    """Webhook 验签失败。验签失败即丢弃,不要尝试解密。"""


class WebhookEnvelopeError(WebhookError, EnvelopeError):
    """Webhook 信封结构非法或解密失败。"""


class WebhookPayloadError(WebhookError):
    """Webhook 明文载荷与传输头交叉校验不一致。"""


class TransportError(PlutusError):
    """网络传输层错误(连接失败、超时等)。"""


class PublicErrorCode(str, Enum):
    """平台对外错误码(``域.名称`` 形式)。"""

    KEY_MISSING = "API.KEY_MISSING"
    KEY_INVALID = "API.KEY_INVALID"
    KEY_DISABLED = "API.KEY_DISABLED"
    KEY_LOCKED = "API.KEY_LOCKED"
    TIMESTAMP_REQUIRED = "API.TIMESTAMP_REQUIRED"
    TIMESTAMP_INVALID = "API.TIMESTAMP_INVALID"
    TIMESTAMP_EXPIRED = "API.TIMESTAMP_EXPIRED"
    VERSION_REQUIRED = "API.VERSION_REQUIRED"
    VERSION_UNSUPPORTED = "API.VERSION_UNSUPPORTED"
    ENDPOINT_RETIRED = "API.ENDPOINT_RETIRED"
    NONCE_REQUIRED = "API.NONCE_REQUIRED"
    NONCE_INVALID = "API.NONCE_INVALID"
    NONCE_REUSED = "API.NONCE_REUSED"
    SIGNATURE_REQUIRED = "API.SIGNATURE_REQUIRED"
    SIGNATURE_ALGORITHM_INVALID = "API.SIGNATURE_ALGORITHM_INVALID"
    SIGNATURE_INVALID = "API.SIGNATURE_INVALID"
    IP_NOT_ALLOWED = "API.IP_NOT_ALLOWED"
    WORKSPACE_REQUIRED = "API.WORKSPACE_REQUIRED"
    WORKSPACE_UNAVAILABLE = "API.WORKSPACE_UNAVAILABLE"
    PERMISSION_DENIED = "ACCESS.PERMISSION_DENIED"
    SECURE_CHANNEL_INVALID_PAYLOAD = "SECURE_CHANNEL.INVALID_PAYLOAD"
    RATE_LIMITED = "REQUEST.RATE_LIMITED"
    CONFLICT = "REQUEST.CONFLICT"
    STALE_VERSION = "REQUEST.STALE_VERSION"
    INVALID_PARAMETER = "VALIDATION.INVALID_PARAMETER"
    NOT_FOUND = "RESOURCE.NOT_FOUND"
    INTERNAL_ERROR = "SYSTEM.INTERNAL_ERROR"

    @classmethod
    def parse(cls, value: Any) -> "Optional[PublicErrorCode]":
        """把任意值解析为已知错误码;未知码返回 ``None``。"""
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls(value)
            except ValueError:
                return None
        return None


class ApiError(PlutusError):
    """平台返回的业务/协议错误。

    :param message: 错误消息
    :param status_code: HTTP 状态码
    :param code: 平台错误码原值(``域.名称`` 字符串)
    :param response: 触发本异常的 :class:`~slaunchx_plutus_sdk.client.ApiResponse`
    """

    #: 建议的重试策略(见 SPEC 第 13 节)
    retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        code: Optional[str] = None,
        data: Any = None,
        response: Any = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.error_code = PublicErrorCode.parse(code)
        self.data = data
        self.response = response
        self.headers: Mapping[str, str] = headers or {}

    @property
    def request_id(self) -> Optional[str]:
        """平台回显的 ``X-Request-Id``,用于工单排查。"""
        for name, value in self.headers.items():
            if name.lower() == "x-request-id":
                return value
        return None

    def __str__(self) -> str:
        parts = [self.message]
        if self.code:
            parts.append("code=%s" % self.code)
        if self.status_code is not None:
            parts.append("status=%s" % self.status_code)
        rid = self.request_id
        if rid:
            parts.append("requestId=%s" % rid)
        return " ".join(parts)


class AuthenticationError(ApiError):
    """认证失败:密钥、签名、时间戳或 nonce 不被接受。"""


class TimestampExpiredError(AuthenticationError):
    """签名时间戳超出 ±60 秒窗口。校正时钟后重新签名可重试一次。"""

    retryable = True


class NonceReusedError(AuthenticationError):
    """nonce 重放。换新 nonce 重新签名后可重试。"""

    retryable = True


class PermissionDeniedError(ApiError):
    """权限不足、门户不匹配或源 IP 不在白名单。"""


class ValidationError(ApiError):
    """参数或协议头校验失败。"""


class NotFoundError(ApiError):
    """资源不存在。"""


class ConflictError(ApiError):
    """幂等冲突、业务冲突或乐观锁版本过期。"""


class RateLimitedError(ApiError):
    """触发限流,按 ``Retry-After`` 退避重试。"""

    retryable = True

    @property
    def retry_after(self) -> Optional[float]:
        """``Retry-After`` 响应头(秒);缺失或非法时返回 ``None``。"""
        for name, value in self.headers.items():
            if name.lower() == "retry-after":
                try:
                    return float(value)
                except (TypeError, ValueError):
                    return None
        return None


class SecureChannelError(ApiError):
    """加密信封被平台拒绝:AAD 不匹配 / GCM 认证失败 / 明文超限。"""


class EndpointRetiredError(ApiError):
    """端点已下线。"""


class ServerError(ApiError):
    """平台内部错误。写操作重试必须携带 ``X-Idempotency-Key``。"""

    retryable = True


_CODE_TO_ERROR: Dict[str, Type[ApiError]] = {
    PublicErrorCode.KEY_MISSING.value: AuthenticationError,
    PublicErrorCode.KEY_INVALID.value: AuthenticationError,
    PublicErrorCode.KEY_DISABLED.value: AuthenticationError,
    PublicErrorCode.KEY_LOCKED.value: AuthenticationError,
    PublicErrorCode.SIGNATURE_INVALID.value: AuthenticationError,
    PublicErrorCode.TIMESTAMP_EXPIRED.value: TimestampExpiredError,
    PublicErrorCode.NONCE_REUSED.value: NonceReusedError,
    PublicErrorCode.TIMESTAMP_REQUIRED.value: ValidationError,
    PublicErrorCode.TIMESTAMP_INVALID.value: ValidationError,
    PublicErrorCode.VERSION_REQUIRED.value: ValidationError,
    PublicErrorCode.VERSION_UNSUPPORTED.value: ValidationError,
    PublicErrorCode.NONCE_REQUIRED.value: ValidationError,
    PublicErrorCode.NONCE_INVALID.value: ValidationError,
    PublicErrorCode.SIGNATURE_REQUIRED.value: ValidationError,
    PublicErrorCode.SIGNATURE_ALGORITHM_INVALID.value: ValidationError,
    PublicErrorCode.WORKSPACE_REQUIRED.value: ValidationError,
    PublicErrorCode.INVALID_PARAMETER.value: ValidationError,
    PublicErrorCode.IP_NOT_ALLOWED.value: PermissionDeniedError,
    PublicErrorCode.WORKSPACE_UNAVAILABLE.value: PermissionDeniedError,
    PublicErrorCode.PERMISSION_DENIED.value: PermissionDeniedError,
    PublicErrorCode.SECURE_CHANNEL_INVALID_PAYLOAD.value: SecureChannelError,
    PublicErrorCode.RATE_LIMITED.value: RateLimitedError,
    PublicErrorCode.CONFLICT.value: ConflictError,
    PublicErrorCode.STALE_VERSION.value: ConflictError,
    PublicErrorCode.NOT_FOUND.value: NotFoundError,
    PublicErrorCode.ENDPOINT_RETIRED.value: EndpointRetiredError,
    PublicErrorCode.INTERNAL_ERROR.value: ServerError,
}

_STATUS_TO_ERROR: Dict[int, Type[ApiError]] = {
    400: ValidationError,
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    410: EndpointRetiredError,
    422: ValidationError,
    429: RateLimitedError,
}


def error_for_response(
    status_code: int,
    code: Optional[str],
    message: str,
    *,
    data: Any = None,
    response: Any = None,
    headers: Optional[Mapping[str, str]] = None,
) -> ApiError:
    """按错误码优先、HTTP 状态兜底的规则构造类型化异常。"""
    cls: Optional[Type[ApiError]] = _CODE_TO_ERROR.get(code) if code else None
    if cls is None:
        cls = _STATUS_TO_ERROR.get(status_code)
    if cls is None:
        cls = ServerError if status_code >= 500 else ApiError
    return cls(
        message,
        status_code=status_code,
        code=code,
        data=data,
        response=response,
        headers=headers,
    )
