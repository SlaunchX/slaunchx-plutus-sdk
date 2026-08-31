"""混合加密信封:RSA-OAEP-SHA256 包装 AES-256-GCM 一次性密钥。

请求加密、敏感响应解密、Webhook 解密共用本模块的原语,差别只在 AAD 四元组的取值。
"""

from __future__ import annotations

import base64
import hmac
import os
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import MAX_PLAINTEXT_BYTES, spki_fingerprint
from .errors import EnvelopeError

__all__ = [
    "ENVELOPE_ALGORITHM",
    "IV_LENGTH",
    "GCM_TAG_LENGTH",
    "AES_KEY_LENGTH",
    "build_aad",
    "parse_aad",
    "encrypt_envelope",
    "decrypt_envelope",
    "encrypt_request_payload",
    "decrypt_sensitive_response",
]

#: 信封 ``algorithm`` 字段的唯一合法值
ENVELOPE_ALGORITHM = "RSA-OAEP-AES-256-GCM"

#: GCM IV 长度,前置在密文之前
IV_LENGTH = 12

#: GCM 认证标签长度,附在密文之后
GCM_TAG_LENGTH = 16

#: 一次性 AES 密钥长度
AES_KEY_LENGTH = 32

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

_API_REQUIRED_FIELDS = ("algorithm", "keyFingerprint", "encryptedKey", "ciphertext", "aad")
_WEBHOOK_FIELDS = frozenset(
    {"envelopeVersion", "algorithm", "keyFingerprint", "encryptedKey", "ciphertext", "aad"}
)


def build_aad(
    request_id: Optional[str],
    route_template: Optional[str],
    timestamp: Optional[str],
    key_id: Optional[str],
) -> bytes:
    """拼接 AAD:``requestId|routeTemplate|timestamp|keyId`` 的 UTF-8 字节。

    任一分量为 ``None`` 按空串处理,分隔符仍然保留。
    """
    return "|".join(
        [request_id or "", route_template or "", timestamp or "", key_id or ""]
    ).encode("utf-8")


def parse_aad(aad: bytes) -> Dict[str, str]:
    """把 AAD 字节拆回四个分量。

    :raises EnvelopeError: 不是合法 UTF-8,或分隔符数量不是 3。
    """
    try:
        text = aad.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvelopeError("信封 aad 不是合法 UTF-8") from exc
    parts = text.split("|")
    if len(parts) != 4:
        raise EnvelopeError("信封 aad 分量数不是 4: %d" % len(parts))
    return {
        "requestId": parts[0],
        "routeTemplate": parts[1],
        "timestamp": parts[2],
        "keyId": parts[3],
    }


def _b64decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise EnvelopeError("信封字段 %s 缺失或不是字符串" % field)
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise EnvelopeError("信封字段 %s 不是合法 Base64" % field) from exc


def encrypt_envelope(
    public_key: rsa.RSAPublicKey,
    plaintext: bytes,
    aad: bytes,
    *,
    key_fingerprint: Optional[str] = None,
    include_encrypted_payload: bool = True,
    envelope_version: Optional[int] = None,
) -> Dict[str, Any]:
    """用接收方公钥生成混合加密信封。

    :param public_key: 接收方公钥(请求加密用 ``platform_enc``)
    :param plaintext: 明文字节
    :param aad: 由 :func:`build_aad` 构造的附加认证数据
    :param key_fingerprint: 信封 ``keyFingerprint``,默认由 ``public_key`` 推导
    :param include_encrypted_payload: 是否填充历史兼容字段 ``encryptedPayload``(值等于 ``ciphertext``)
    :param envelope_version: 填入 ``envelopeVersion``,仅 Webhook 形状使用
    """
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise EnvelopeError("明文超过 %d 字节上限" % MAX_PLAINTEXT_BYTES)
    aes_key = os.urandom(AES_KEY_LENGTH)
    iv = os.urandom(IV_LENGTH)
    sealed = AESGCM(aes_key).encrypt(iv, plaintext, aad)
    ciphertext = base64.b64encode(iv + sealed).decode("ascii")
    encrypted_key = base64.b64encode(public_key.encrypt(aes_key, _OAEP)).decode("ascii")
    envelope: Dict[str, Any] = {}
    if envelope_version is not None:
        envelope["envelopeVersion"] = envelope_version
    envelope["algorithm"] = ENVELOPE_ALGORITHM
    envelope["keyFingerprint"] = key_fingerprint or spki_fingerprint(public_key)
    envelope["encryptedKey"] = encrypted_key
    envelope["ciphertext"] = ciphertext
    envelope["aad"] = base64.b64encode(aad).decode("ascii")
    if include_encrypted_payload:
        envelope["encryptedPayload"] = ciphertext
    return envelope


def _validate_shape(envelope: Mapping[str, Any], webhook: bool) -> None:
    if not isinstance(envelope, Mapping):
        raise EnvelopeError("信封必须是 JSON 对象")
    if webhook:
        keys = set(envelope)
        if keys != _WEBHOOK_FIELDS:
            raise EnvelopeError(
                "Webhook 信封字段集不符 (additionalProperties=false): %s" % sorted(keys)
            )
        if envelope.get("envelopeVersion") != 1:
            raise EnvelopeError("Webhook envelopeVersion 必须恰为 1")
    else:
        for name in _API_REQUIRED_FIELDS:
            if name not in envelope:
                raise EnvelopeError("信封缺少必填字段 %s" % name)
    if envelope.get("algorithm") != ENVELOPE_ALGORITHM:
        raise EnvelopeError("信封 algorithm 必须是 %s" % ENVELOPE_ALGORITHM)


def decrypt_envelope(
    private_key: rsa.RSAPrivateKey,
    envelope: Mapping[str, Any],
    expected_aad: bytes,
    *,
    expected_fingerprint: Optional[str] = None,
    webhook_shape: bool = False,
    max_plaintext_bytes: int = MAX_PLAINTEXT_BYTES,
) -> bytes:
    """校验信封结构与 AAD 绑定后解密,返回明文字节。

    AAD 由调用方重建后传入,并与信封回显的 ``aad`` 做常量时间比较;
    比较通过后用**重建的** AAD 做 GCM 解密,信封里的 ``aad`` 只作回显。

    :param private_key: 接收方私钥
    :param envelope: 信封 JSON 对象
    :param expected_aad: 本地重建的 AAD 字节
    :param expected_fingerprint: 期望的 ``keyFingerprint``,不等则拒绝
    :param webhook_shape: 是否按 Webhook 严格字段集校验
    :raises EnvelopeError: 结构非法、AAD 不匹配、密钥长度异常、GCM 认证失败或明文超限
    """
    _validate_shape(envelope, webhook_shape)
    if expected_fingerprint is not None:
        actual_fingerprint = envelope.get("keyFingerprint")
        if not isinstance(actual_fingerprint, str) or not hmac.compare_digest(
            actual_fingerprint, expected_fingerprint
        ):
            raise EnvelopeError(
                "信封 keyFingerprint 与本地密钥不一致: %r != %r"
                % (actual_fingerprint, expected_fingerprint)
            )
    echoed_aad = _b64decode(envelope.get("aad"), "aad")
    if not hmac.compare_digest(echoed_aad, expected_aad):
        raise EnvelopeError(
            "重建的 AAD 与信封回显的 aad 不一致: 期望 %r,回显 %r"
            % (expected_aad, echoed_aad)
        )
    encrypted_key = _b64decode(envelope.get("encryptedKey"), "encryptedKey")
    blob = _b64decode(envelope.get("ciphertext"), "ciphertext")
    if len(blob) < IV_LENGTH + GCM_TAG_LENGTH:
        raise EnvelopeError("ciphertext 长度不足以容纳 IV 与认证标签")
    if len(blob) - IV_LENGTH - GCM_TAG_LENGTH > max_plaintext_bytes:
        raise EnvelopeError("密文长度超过明文上限 %d 字节" % max_plaintext_bytes)
    try:
        aes_key = private_key.decrypt(encrypted_key, _OAEP)
    except Exception as exc:
        raise EnvelopeError("RSA-OAEP 解开 encryptedKey 失败") from exc
    if len(aes_key) != AES_KEY_LENGTH:
        raise EnvelopeError("解出的 AES 密钥不是 %d 字节" % AES_KEY_LENGTH)
    iv, sealed = blob[:IV_LENGTH], blob[IV_LENGTH:]
    try:
        plaintext = AESGCM(aes_key).decrypt(iv, sealed, expected_aad)
    except InvalidTag as exc:
        raise EnvelopeError("AES-GCM 认证失败") from exc
    if len(plaintext) > max_plaintext_bytes:
        raise EnvelopeError("解密后明文超过 %d 字节上限" % max_plaintext_bytes)
    return plaintext


def encrypt_request_payload(
    platform_enc_public_key: rsa.RSAPublicKey,
    plaintext: bytes,
    *,
    request_id: str,
    route_template: str,
    timestamp: str,
    key_id: Optional[str] = None,
) -> Dict[str, Any]:
    """为加密端点构造请求信封(API 链形状,含兼容字段 ``encryptedPayload``)。

    AAD 为 ``requestId|routeTemplate|timestamp|platformEncKeyFingerprint``,
    其中 ``routeTemplate`` 是该端点的外部路径。

    :param request_id: ``X-Request-Id``,必填非空
    :param route_template: 端点外部路径
    :param timestamp: ``X-Timestamp``,与签名使用同一个值
    :param key_id: 平台加密公钥指纹,默认由公钥推导;同时用作 ``X-Platform-Encryption-Key-Id``
    """
    if not request_id:
        raise EnvelopeError("加密请求的 X-Request-Id 必填且非空")
    if not timestamp:
        raise EnvelopeError("加密请求的 X-Timestamp 必填且非空")
    fingerprint = key_id or spki_fingerprint(platform_enc_public_key)
    aad = build_aad(request_id, route_template, timestamp, fingerprint)
    return encrypt_envelope(
        platform_enc_public_key,
        plaintext,
        aad,
        key_fingerprint=fingerprint,
        include_encrypted_payload=True,
    )


def decrypt_sensitive_response(
    merchant_enc_private_key: rsa.RSAPrivateKey,
    envelope: Mapping[str, Any],
    *,
    request_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    key_id: Optional[str] = None,
    max_plaintext_bytes: int = MAX_PLAINTEXT_BYTES,
) -> bytes:
    """解密敏感响应信封。

    敏感响应的 AAD ``routeTemplate`` 分量固定为空串,``keyId`` 是商户加密公钥指纹。
    平台生成的 ``timestamp``(以及无关联上下文时可能为空串的 ``requestId``)只能从信封
    回显的 ``aad`` 取得:SDK 先解析回显值,再用「固定空 routeTemplate + 本地指纹 +
    调用方已知值」重建 AAD 并与回显做常量时间比较,比对通过后才用重建值解密。

    :param request_id: 已知的请求关联 ID;提供后与回显值逐字节比对,不一致即拒绝
    :param timestamp: 已知的平台毫秒时间戳;提供后与回显值比对
    :param key_id: 期望的商户加密公钥指纹,默认由私钥推导
    """
    fingerprint = key_id or spki_fingerprint(merchant_enc_private_key)
    echoed = _b64decode(envelope.get("aad"), "aad")
    parts = parse_aad(echoed)
    if parts["routeTemplate"] != "":
        raise EnvelopeError("敏感响应 AAD 的 routeTemplate 必须是空串")
    if request_id is not None and parts["requestId"] != request_id:
        raise EnvelopeError(
            "敏感响应 AAD 的 requestId 与本次请求不一致: %r != %r"
            % (parts["requestId"], request_id)
        )
    if timestamp is not None and parts["timestamp"] != timestamp:
        raise EnvelopeError(
            "敏感响应 AAD 的 timestamp 与预期不一致: %r != %r"
            % (parts["timestamp"], timestamp)
        )
    rebuilt = build_aad(parts["requestId"], "", parts["timestamp"], fingerprint)
    return decrypt_envelope(
        merchant_enc_private_key,
        envelope,
        rebuilt,
        expected_fingerprint=fingerprint,
        webhook_shape=False,
        max_plaintext_bytes=max_plaintext_bytes,
    )
