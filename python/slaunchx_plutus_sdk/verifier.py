"""响应验签:SLAUNCHX-API-RESPONSE-V1 规范串与 RSA-SHA256 校验。"""

from __future__ import annotations

import base64
import hashlib
from typing import Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .errors import ResponseSignatureError
from .signer import EMPTY_BODY_SHA256

__all__ = [
    "RESPONSE_CANONICAL_PREFIX",
    "response_body_sha256_hex",
    "build_response_canonical_string",
    "verify_signature",
    "ResponseVerifier",
]

#: 响应规范串第 1 行的固定字面量
RESPONSE_CANONICAL_PREFIX = "SLAUNCHX-API-RESPONSE-V1"


def _header(headers: Mapping[str, str], name: str) -> Optional[str]:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def response_body_sha256_hex(body: Optional[bytes]) -> str:
    """响应体摘要,64 位小写 hex;空体使用空体摘要。"""
    if not body:
        return EMPTY_BODY_SHA256
    return hashlib.sha256(body).hexdigest()


def build_response_canonical_string(
    request_canonical_sha256: str,
    api_version: str,
    external_path: str,
    operation_id: Optional[str],
    request_id: Optional[str],
    http_status: int,
    content_type: Optional[str],
    response_timestamp: Optional[str],
    response_body_hash: str,
) -> str:
    """按 10 行结构拼接响应规范串(LF 连接,无尾换行)。

    ``request_canonical_sha256`` 必须由 SDK 本地计算,绝不能从响应头读取;
    ``content_type`` 必须使用响应头原值,不做归一化。
    """
    return "\n".join(
        [
            RESPONSE_CANONICAL_PREFIX,
            request_canonical_sha256,
            api_version,
            external_path,
            operation_id or "",
            request_id or "",
            str(http_status),
            content_type or "",
            response_timestamp or "",
            response_body_hash,
        ]
    )


def verify_signature(
    public_key: rsa.RSAPublicKey, canonical_string: str, signature_b64: str
) -> bool:
    """用 RSASSA-PKCS#1 v1.5 + SHA-256 验证 Base64 签名。"""
    try:
        raw = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    try:
        public_key.verify(
            raw, canonical_string.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError):
        return False


class ResponseVerifier:
    """响应验签器。验签失败按安全事故处理:丢弃响应体。"""

    def __init__(self, public_key: rsa.RSAPublicKey) -> None:
        """:param public_key: 平台认证公钥 ``platform_auth``"""
        self._public_key = public_key

    def verify(
        self,
        *,
        request_canonical_sha256: str,
        api_version: str,
        external_path: str,
        http_status: int,
        headers: Mapping[str, str],
        body: Optional[bytes],
        require_signature_on_error: bool = False,
    ) -> bool:
        """验证一次响应的签名。

        缺签名头的处理策略(SPEC「SDK 约定(非平台契约)」一节;平台契约并未穷举
        哪些状态码不带响应签名,故本策略由 SDK 侧统一约定):

        - HTTP 2xx 缺签名头:抛 :class:`ResponseSignatureError`。成功响应必须可证明来源。
        - 非 2xx 缺签名头:放行,返回 ``False``,由调用方按类型化 API 错误处理。
        - 非 2xx 缺签名头且 ``require_signature_on_error=True``:抛
          :class:`ResponseSignatureError`。

        :param request_canonical_sha256: 本次请求规范串的 SHA-256,由 SDK 本地计算
        :param http_status: 响应 HTTP 状态码,决定缺签名头时的放行策略
        :param headers: 响应头,大小写不敏感查找
        :param body: 原始响应体字节
        :param require_signature_on_error: 非 2xx 响应缺签名头时是否也报错,默认 ``False``
        :returns: 是否实际执行了验签(缺签名头且被放行时返回 ``False``)
        :raises ResponseSignatureError: 验签失败,或缺签名头且按策略不予放行
        """
        signature = _header(headers, "X-Response-Signature")
        if not signature:
            if 200 <= http_status < 300:
                raise ResponseSignatureError(
                    "HTTP %d 成功响应缺少 X-Response-Signature" % http_status
                )
            if require_signature_on_error:
                raise ResponseSignatureError(
                    "HTTP %d 错误响应缺少 X-Response-Signature" % http_status
                )
            return False
        canonical = build_response_canonical_string(
            request_canonical_sha256,
            api_version,
            external_path,
            _header(headers, "X-Operation-Id"),
            _header(headers, "X-Request-Id"),
            http_status,
            _header(headers, "Content-Type"),
            _header(headers, "X-Response-Timestamp"),
            response_body_sha256_hex(body),
        )
        if not verify_signature(self._public_key, canonical, signature):
            raise ResponseSignatureError(
                "响应验签失败,响应体已丢弃;规范串首尾: %r" % (canonical[:80] + "...")
            )
        return True
