"""请求签名:query 规范化、body 摘要、8 行规范串与 RSA-SHA256 签名。"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .config import DEFAULT_API_VERSION
from .protocol import ProtocolProfile, resolve_profile, product_canonical_query, product_request_id
from .errors import CanonicalQueryError, ConfigurationError

__all__ = [
    "EMPTY_BODY_SHA256",
    "FORCED_EMPTY_BODY_METHODS",
    "SIGNATURE_ALGORITHM",
    "NONCE_PATTERN",
    "canonicalize_component",
    "canonicalize_query",
    "encode_query",
    "body_sha256_hex",
    "build_request_canonical_string",
    "canonical_sha256",
    "sign_canonical_string",
    "generate_nonce",
    "validate_nonce",
    "current_timestamp_ms",
    "SignedRequest",
    "RequestSigner",
]

#: 空 body 的 SHA-256 小写 hex
EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

#: 这些方法一律使用空 body 摘要,即使请求实际携带 body
FORCED_EMPTY_BODY_METHODS = frozenset({"GET", "HEAD", "DELETE"})

#: ``X-Signature-Algorithm`` 的字面量值,不参与签名
SIGNATURE_ALGORITHM = "RSA-SHA256"

#: ``X-Nonce`` 约束
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{16,128}$")

_UNRESERVED = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_HEX_DIGITS = "0123456789abcdefABCDEF"

QueryInput = Union[
    None,
    str,
    Mapping[str, object],
    Sequence[Tuple[str, object]],
]


def _percent_decode_strict(component: str) -> bytes:
    """严格 percent-decode:只接受 unreserved 字面量与合法 ``%XX``,结果必须是合法 UTF-8。"""
    out = bytearray()
    i = 0
    n = len(component)
    while i < n:
        ch = component[i]
        if ch == "%":
            if i + 2 >= n:
                raise CanonicalQueryError("query component contains incomplete percent encoding")
            hi, lo = component[i + 1], component[i + 2]
            if hi not in _HEX_DIGITS or lo not in _HEX_DIGITS:
                raise CanonicalQueryError("query component contains invalid percent encoding")
            out.append(int(hi, 16) * 16 + int(lo, 16))
            i += 3
            continue
        code = ord(ch)
        if code > 0x7F or code not in _UNRESERVED:
            raise CanonicalQueryError(
                "query component must use RFC 3986 percent encoding for reserved characters"
            )
        out.append(code)
        i += 1
    try:
        out.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalQueryError("query component contains invalid UTF-8") from exc
    return bytes(out)


def _percent_encode(raw: bytes) -> str:
    parts = []
    for byte in raw:
        if byte in _UNRESERVED:
            parts.append(chr(byte))
        else:
            parts.append("%%%02X" % byte)
    return "".join(parts)


def canonicalize_component(component: str) -> str:
    """对单个 query 分量执行「严格解码 → RFC 3986 重编码」。

    :raises CanonicalQueryError: 分量含裸保留字符、裸非 ASCII、非法或截断的 ``%XX``,
        或解码后不是合法 UTF-8。
    """
    return _percent_encode(_percent_decode_strict(component))


def canonicalize_query(query: Optional[str], protocol_profile=ProtocolProfile.REQUEST_BOUND_V1) -> str:
    """把原始 query 串规范化为签名规范串第 3 行。

    算法为「严格解码 → RFC 3986 重编码 → 按 (key, value) 字节序排序 → 重组」。
    ``None``、空串与全空白串均返回空串。SDK 不做任何回退:不合法的输入一律抛异常,
    而不是发出必然被平台拒绝的请求。

    :raises CanonicalQueryError: 任一分量不满足 RFC 3986 要求。
    """
    if resolve_profile(protocol_profile) == ProtocolProfile.PRODUCT_V1:
        return product_canonical_query(query)
    if query is None or query.strip() == "":
        return ""
    pairs = []
    for segment in query.split("&"):
        idx = segment.find("=")
        raw_key = segment if idx < 0 else segment[:idx]
        raw_value = "" if idx < 0 else segment[idx + 1 :]
        pairs.append((canonicalize_component(raw_key), canonicalize_component(raw_value)))
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    return "&".join("%s=%s" % kv for kv in pairs)


def _stringify(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value if isinstance(value, str) else str(value)


def encode_query(query: QueryInput) -> Optional[str]:
    """把映射或键值对序列编码为可直接参与规范化的 query 串。

    分量按 RFC 3986 unreserved 集合 percent-encode(空格编成 ``%20``,不是 ``+``)。
    传入字符串时原样返回,传入 ``None`` 返回 ``None``。
    """
    if query is None:
        return None
    if isinstance(query, str):
        return query
    items: Iterable[Tuple[str, object]]
    items = query.items() if isinstance(query, Mapping) else query
    segments = []
    for key, value in items:
        if isinstance(value, (list, tuple, set)):
            for item in value:
                segments.append(
                    "%s=%s"
                    % (
                        _percent_encode(_stringify(key).encode("utf-8")),
                        _percent_encode(_stringify(item).encode("utf-8")),
                    )
                )
        else:
            segments.append(
                "%s=%s"
                % (
                    _percent_encode(_stringify(key).encode("utf-8")),
                    _percent_encode(_stringify(value).encode("utf-8")),
                )
            )
    return "&".join(segments)


def body_sha256_hex(body: Optional[bytes], method: Optional[str] = None) -> str:
    """计算规范串第 8 行的 body 摘要(64 位小写 hex)。

    :param body: 实际发送的**原始字节**,不做任何规整。
    :param method: HTTP 方法;``GET`` / ``HEAD`` / ``DELETE`` 强制使用空 body 摘要。
    """
    if method is not None and method.upper() in FORCED_EMPTY_BODY_METHODS:
        return EMPTY_BODY_SHA256
    if not body:
        return EMPTY_BODY_SHA256
    return hashlib.sha256(body).hexdigest()


def build_request_canonical_string(
    method: str,
    external_path: str,
    canonical_query: str,
    timestamp: str,
    nonce: str,
    api_version: str,
    idempotency_key: Optional[str],
    body_hash: str,
    protocol_profile=ProtocolProfile.REQUEST_BOUND_V1,
) -> str:
    """按 8 行结构拼接请求规范串(LF 连接,无尾换行)。

    ``canonical_query`` 必须是 :func:`canonicalize_query` 的输出。
    """
    if not method:
        raise ConfigurationError("method 不能为空")
    if not external_path.startswith("/"):
        raise ConfigurationError("external_path 必须以 / 开头,且不含链/版本/门户前缀")
    if not api_version or not api_version.strip():
        raise ConfigurationError("api_version 不能为空")
    return "\n".join(
        [
            method.upper(),
            external_path,
            canonical_query,
            timestamp,
            nonce,
            api_version,
            *([] if resolve_profile(protocol_profile) == ProtocolProfile.PRODUCT_V1 else [idempotency_key or ""]),
            body_hash,
        ]
    )


def canonical_sha256(canonical_string: str) -> str:
    """对规范串本身求 SHA-256,得到响应规范串第 2 行的绑定摘要。"""
    return hashlib.sha256(canonical_string.encode("utf-8")).hexdigest()


def sign_canonical_string(private_key: rsa.RSAPrivateKey, canonical_string: str) -> str:
    """用 RSASSA-PKCS#1 v1.5 + SHA-256 对规范串签名,返回标准 Base64。"""
    signature = private_key.sign(
        canonical_string.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
    )
    return base64.b64encode(signature).decode("ascii")


def generate_nonce(num_bytes: int = 24) -> str:
    """生成满足 ``^[A-Za-z0-9._~-]{16,128}$`` 的一次性 nonce。

    使用 Base64URL 无填充字符集,不含 ``+`` ``/`` ``=``。
    """
    if num_bytes < 12:
        raise ConfigurationError("nonce 熵不足,num_bytes 至少为 12")
    nonce = secrets.token_urlsafe(num_bytes)
    return nonce[:128]


def validate_nonce(nonce: str) -> str:
    """校验 nonce 字符集与长度,返回原值。"""
    if not NONCE_PATTERN.match(nonce or ""):
        raise ConfigurationError(
            "nonce 必须匹配 ^[A-Za-z0-9._~-]{16,128}$;Base64 输出含 + / = 不合法"
        )
    return nonce


def current_timestamp_ms() -> str:
    """当前 Unix **毫秒**时间戳的十进制字符串。"""
    return str(int(time.time() * 1000))


@dataclass(frozen=True)
class SignedRequest:
    """一次签名的完整产物。``body`` 是唯一一份将被发送的字节。"""

    method: str
    external_path: str
    canonical_query: str
    timestamp: str
    nonce: str
    api_version: str
    idempotency_key: Optional[str]
    body: Optional[bytes]
    body_hash: str
    canonical_string: str
    canonical_sha256: str
    signature: str
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def url_query(self) -> str:
        """建议实际发出的 query 串(规范化结果与原始串对平台等价)。"""
        return self.canonical_query


class RequestSigner:
    """请求签名器:产出规范串、签名与全部协议头。"""

    def __init__(
        self,
        private_key: rsa.RSAPrivateKey,
        api_key: str,
        api_version: str = DEFAULT_API_VERSION,
        protocol_profile=ProtocolProfile.REQUEST_BOUND_V1,
    ) -> None:
        """
        :param private_key: 商户认证私钥 ``merchant_auth``
        :param api_key: API Key 业务 ID
        :param api_version: 契约主版本,填入 ``X-API-VERSION``
        """
        self._private_key = private_key
        self._api_key = api_key
        self._api_version = api_version
        self._protocol_profile = resolve_profile(protocol_profile)

    def sign(
        self,
        method: str,
        external_path: str,
        *,
        query: QueryInput = None,
        body: Optional[bytes] = None,
        idempotency_key: Optional[str] = None,
        timestamp: Optional[str] = None,
        nonce: Optional[str] = None,
        request_id: Optional[str] = None,
        platform_encryption_key_id: Optional[str] = None,
    ) -> SignedRequest:
        """对一次请求签名。

        :param method: HTTP 方法
        :param external_path: 外部路径,如 ``/card-products/cards/page``
        :param query: 原始 query 串,或将被 percent-encode 的映射/键值对序列
        :param body: **已序列化**的请求体字节;同一份字节既用于摘要也用于发送
        :param idempotency_key: 发送则参与签名第 7 行,不发送则该行为空
        :param timestamp: Unix 毫秒字符串,默认取当前时间
        :param nonce: 一次性随机数,默认自动生成
        :param request_id: ``X-Request-Id``,不参与请求签名,但参与加密信封 AAD 与响应规范串
        :param platform_encryption_key_id: 加密请求必填,平台加密公钥指纹
        """
        method_upper = method.upper()
        raw_query = encode_query(query)
        canonical_query = canonicalize_query(raw_query, self._protocol_profile)
        ts = timestamp or current_timestamp_ms()
        nonce_value = validate_nonce(nonce) if nonce else generate_nonce()
        digest = body_sha256_hex(body, method_upper)
        canonical = build_request_canonical_string(
            method_upper,
            external_path,
            canonical_query,
            ts,
            nonce_value,
            self._api_version,
            idempotency_key,
            digest,
            self._protocol_profile,
        )
        signature = sign_canonical_string(self._private_key, canonical)
        headers: Dict[str, str] = {
            "X-Api-Key": self._api_key,
            "X-API-VERSION": self._api_version,
            "X-Timestamp": ts,
            "X-Nonce": nonce_value,
            "X-Signature": signature,
            "X-Signature-Algorithm": SIGNATURE_ALGORITHM,
        }
        if idempotency_key:
            headers["X-Idempotency-Key"] = idempotency_key
        if self._protocol_profile == ProtocolProfile.PRODUCT_V1:
            request_id = product_request_id(request_id)
        if request_id:
            headers["X-Request-Id"] = request_id
        if platform_encryption_key_id:
            headers["X-Platform-Encryption-Key-Id"] = platform_encryption_key_id
        return SignedRequest(
            method=method_upper,
            external_path=external_path,
            canonical_query=canonical_query,
            timestamp=ts,
            nonce=nonce_value,
            api_version=self._api_version,
            idempotency_key=idempotency_key,
            body=body,
            body_hash=digest,
            canonical_string=canonical,
            canonical_sha256=canonical_sha256(canonical),
            signature=signature,
            headers=headers,
        )
