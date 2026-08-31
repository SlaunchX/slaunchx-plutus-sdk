"""Webhook 接收:先验签、后解密,再与传输头交叉校验。"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric import rsa

from .config import MAX_PLAINTEXT_BYTES, spki_fingerprint
from .envelope import build_aad, decrypt_envelope
from .errors import (
    ConfigurationError,
    EnvelopeError,
    WebhookEnvelopeError,
    WebhookPayloadError,
    WebhookSignatureError,
)
from .verifier import verify_signature

__all__ = [
    "WEBHOOK_ROUTE_TEMPLATE",
    "HEADER_DELIVERY_ID",
    "HEADER_EVENT_TYPE",
    "HEADER_TIMESTAMP",
    "HEADER_KEY_ID",
    "HEADER_SIGNATURE",
    "webhook_body_digest_base64",
    "build_webhook_canonical_string",
    "WebhookEvent",
    "WebhookReceiver",
]

#: Webhook AAD 第 2 分量的固定字面量
WEBHOOK_ROUTE_TEMPLATE = "webhook"

HEADER_DELIVERY_ID = "X-SlaunchX-Delivery-Id"
HEADER_EVENT_TYPE = "X-SlaunchX-Event-Type"
HEADER_TIMESTAMP = "X-SlaunchX-Timestamp"
HEADER_KEY_ID = "X-SlaunchX-Key-Id"
HEADER_SIGNATURE = "X-SlaunchX-Signature"


def _header(headers: Mapping[str, str], name: str) -> Optional[str]:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def _require_header(headers: Mapping[str, str], name: str) -> str:
    value = _header(headers, name)
    if not value:
        raise WebhookSignatureError("Webhook 缺少必填头 %s" % name)
    return value


def webhook_body_digest_base64(body: bytes) -> str:
    """Webhook body 摘要:SHA-256 后 **Base64**(不是 hex)。"""
    return base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")


def build_webhook_canonical_string(
    delivery_id: str, event_type: str, timestamp: str, body_digest_base64: str
) -> str:
    """拼接 4 行 Webhook 签名规范串(LF 连接,无尾换行)。"""
    return "\n".join([delivery_id, event_type, timestamp, body_digest_base64])


@dataclass(frozen=True)
class WebhookEvent:
    """一次通过验签与解密的 Webhook 投递。"""

    #: 去重键,自动重试与人工重放共用同一个值
    delivery_id: str
    #: 事件类型,如 ``card.issuance``
    event_type: str
    #: 传输头中的 Unix 毫秒时间戳
    timestamp: str
    #: 接收方 API Key 业务 ID
    key_id: str
    #: 解密后的明文字节
    plaintext: bytes
    #: 解析后的通知载荷
    payload: Dict[str, Any]

    @property
    def event_id(self) -> Optional[str]:
        """业务事件稳定标识;同一 ``eventId`` 可能投递到多个 endpoint。"""
        value = self.payload.get("eventId")
        return value if isinstance(value, str) else None

    @property
    def data(self) -> Any:
        """载荷 ``data`` 成员。"""
        return self.payload.get("data")


class WebhookReceiver:
    """Webhook 验签与解密。

    使用顺序固定:对**原始 HTTP body 字节**验签 → 校验信封形状 → 重建 AAD 并解密 →
    与传输头交叉校验。验签失败即丢弃,不要尝试解密。
    """

    def __init__(
        self,
        platform_auth_public_key: rsa.RSAPublicKey,
        merchant_enc_private_key: Optional[rsa.RSAPrivateKey] = None,
        *,
        api_key: Optional[str] = None,
        timestamp_tolerance_ms: Optional[int] = None,
        max_plaintext_bytes: int = MAX_PLAINTEXT_BYTES,
    ) -> None:
        """
        :param platform_auth_public_key: 平台认证公钥,验证 ``X-SlaunchX-Signature``
        :param merchant_enc_private_key: 商户加密私钥,解密信封
        :param api_key: 本商户 API Key 业务 ID;提供后校验 ``X-SlaunchX-Key-Id`` 与之相等
        :param timestamp_tolerance_ms: 时间戳容差(毫秒)。协议未规定该窗口,默认 ``None`` 表示关闭
        :param max_plaintext_bytes: 解密明文上限
        """
        self._public_key = platform_auth_public_key
        self._private_key = merchant_enc_private_key
        self._api_key = api_key
        self._tolerance_ms = timestamp_tolerance_ms
        self._max_plaintext_bytes = max_plaintext_bytes

    def verify(self, body: bytes, headers: Mapping[str, str]) -> Dict[str, str]:
        """仅验签,返回规范化后的传输头分量。

        :param body: **原始** HTTP body 字节,不能是重新序列化的 JSON
        :raises WebhookSignatureError: 缺头、签名不匹配或时间戳超出容差
        """
        if not isinstance(body, (bytes, bytearray)):
            raise ConfigurationError("Webhook body 必须是原始字节,不能是已解析的对象")
        delivery_id = _require_header(headers, HEADER_DELIVERY_ID)
        event_type = _require_header(headers, HEADER_EVENT_TYPE)
        timestamp = _require_header(headers, HEADER_TIMESTAMP)
        signature = _require_header(headers, HEADER_SIGNATURE)
        key_id = _header(headers, HEADER_KEY_ID) or ""
        if self._api_key is not None and key_id != self._api_key:
            raise WebhookSignatureError(
                "X-SlaunchX-Key-Id 与本商户 API Key 不一致: %r" % key_id
            )
        if self._tolerance_ms is not None:
            try:
                delta = abs(int(time.time() * 1000) - int(timestamp))
            except ValueError as exc:
                raise WebhookSignatureError("X-SlaunchX-Timestamp 不是毫秒数字") from exc
            if delta > self._tolerance_ms:
                raise WebhookSignatureError(
                    "X-SlaunchX-Timestamp 偏差 %d ms 超过容差 %d ms"
                    % (delta, self._tolerance_ms)
                )
        digest = webhook_body_digest_base64(bytes(body))
        canonical = build_webhook_canonical_string(delivery_id, event_type, timestamp, digest)
        if not verify_signature(self._public_key, canonical, signature):
            raise WebhookSignatureError("Webhook 验签失败,请求已丢弃")
        return {
            "deliveryId": delivery_id,
            "eventType": event_type,
            "timestamp": timestamp,
            "keyId": key_id,
            "bodyDigestBase64": digest,
        }

    def decrypt(self, body: bytes, parts: Mapping[str, str]) -> bytes:
        """解密已验签的 Webhook body,返回明文字节。

        :param parts: :meth:`verify` 的返回值
        :raises WebhookEnvelopeError: 信封形状非法、AAD 不匹配或 GCM 认证失败
        """
        if self._private_key is None:
            raise ConfigurationError("未配置 merchant_enc_private_key,无法解密 Webhook")
        try:
            envelope = json.loads(bytes(body).decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise WebhookEnvelopeError("Webhook body 不是合法 JSON") from exc
        aad = build_aad(
            parts["deliveryId"],
            WEBHOOK_ROUTE_TEMPLATE,
            parts["timestamp"],
            parts["keyId"],
        )
        try:
            return decrypt_envelope(
                self._private_key,
                envelope,
                aad,
                expected_fingerprint=spki_fingerprint(self._private_key),
                webhook_shape=True,
                max_plaintext_bytes=self._max_plaintext_bytes,
            )
        except EnvelopeError as exc:
            raise WebhookEnvelopeError(str(exc)) from exc

    def handle(self, body: bytes, headers: Mapping[str, str]) -> WebhookEvent:
        """完整流程:验签 → 解密 → 交叉校验,返回 :class:`WebhookEvent`。

        调用方仍需**按 ``delivery_id`` 去重**:自动重试与人工重放共用同一个投递 ID。
        """
        parts = self.verify(body, headers)
        plaintext = self.decrypt(body, parts)
        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise WebhookPayloadError("Webhook 明文不是合法 JSON") from exc
        if not isinstance(payload, dict):
            raise WebhookPayloadError("Webhook 明文顶层必须是 JSON 对象")
        if payload.get("deliveryBizId") != parts["deliveryId"]:
            raise WebhookPayloadError("明文 deliveryBizId 与传输头不一致")
        if payload.get("eventType") != parts["eventType"]:
            raise WebhookPayloadError("明文 eventType 与传输头不一致")
        if payload.get("payloadSchemaVersion") != 1:
            raise WebhookPayloadError(
                "payloadSchemaVersion 不是 1: %r" % payload.get("payloadSchemaVersion")
            )
        return WebhookEvent(
            delivery_id=parts["deliveryId"],
            event_type=parts["eventType"],
            timestamp=parts["timestamp"],
            key_id=parts["keyId"],
            plaintext=plaintext,
            payload=payload,
        )
