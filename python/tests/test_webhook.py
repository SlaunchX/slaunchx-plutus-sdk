"""webhook 向量组:2 例,验签 + 信封形状 + 解密比对明文 + 负向。"""

from __future__ import annotations

import base64
import copy
import json
from typing import Any, Dict

import pytest

from slaunchx_plutus_sdk import (
    WEBHOOK_ROUTE_TEMPLATE,
    WebhookEnvelopeError,
    WebhookPayloadError,
    WebhookReceiver,
    WebhookSignatureError,
    build_aad,
    build_webhook_canonical_string,
    serialize_json,
    webhook_body_digest_base64,
)

from conftest import group_params, load_group


def _receiver(public_keys, private_keys, **kwargs: Any) -> WebhookReceiver:
    return WebhookReceiver(
        public_keys["platform_auth"], private_keys["merchant_enc"], **kwargs
    )


def test_group_size() -> None:
    assert len(load_group("webhook")) == 2


@group_params("webhook")
def test_body_digest_is_base64_not_hex(case: Dict[str, Any]) -> None:
    body = case["body"].encode("utf-8")
    digest = webhook_body_digest_base64(body)
    assert digest == case["bodyDigestBase64"]
    assert digest.endswith("=") or len(digest) == 44
    assert len(base64.b64decode(digest)) == 32


@group_params("webhook")
def test_signature_canonical_string(case: Dict[str, Any]) -> None:
    headers = {k.lower(): v for k, v in case["headers"].items()}
    canonical = build_webhook_canonical_string(
        headers["x-slaunchx-delivery-id"],
        headers["x-slaunchx-event-type"],
        headers["x-slaunchx-timestamp"],
        case["bodyDigestBase64"],
    )
    assert canonical == case["signatureCanonicalString"]
    assert len(canonical.split("\n")) == 4


@group_params("webhook")
def test_verify_and_decrypt(case: Dict[str, Any], public_keys, private_keys) -> None:
    receiver = _receiver(public_keys, private_keys, api_key=case["headers"]["X-SlaunchX-Key-Id"])
    body = case["body"].encode("utf-8")
    parts = receiver.verify(body, case["headers"])
    assert parts["bodyDigestBase64"] == case["bodyDigestBase64"]
    assert parts["deliveryId"] == case["aadComponents"]["requestId"]
    assert receiver.decrypt(body, parts).decode("utf-8") == case["expectedPlaintext"]

    event = receiver.handle(body, case["headers"])
    assert event.plaintext.decode("utf-8") == case["expectedPlaintext"]
    assert event.payload == json.loads(case["expectedPlaintext"])
    assert event.delivery_id == case["headers"]["X-SlaunchX-Delivery-Id"]
    assert event.event_type == case["headers"]["X-SlaunchX-Event-Type"]
    assert event.timestamp == case["headers"]["X-SlaunchX-Timestamp"]
    assert event.key_id == case["headers"]["X-SlaunchX-Key-Id"]
    assert event.event_id == event.payload["eventId"]
    assert event.data == event.payload["data"]


@group_params("webhook")
def test_aad_shape(case: Dict[str, Any]) -> None:
    parts = case["aadComponents"]
    headers = case["headers"]
    assert parts["routeTemplate"] == WEBHOOK_ROUTE_TEMPLATE
    assert parts["requestId"] == headers["X-SlaunchX-Delivery-Id"]
    assert parts["timestamp"] == headers["X-SlaunchX-Timestamp"]
    # keyId 位是 API Key 业务 ID,不是指纹
    assert parts["keyId"] == headers["X-SlaunchX-Key-Id"]
    assert not parts["keyId"].startswith("SHA256:")
    aad = build_aad(
        parts["requestId"], parts["routeTemplate"], parts["timestamp"], parts["keyId"]
    )
    assert aad.decode("utf-8") == case["aadString"]
    assert base64.b64encode(aad).decode("ascii") == case["aadBase64"]
    assert json.loads(case["body"])["aad"] == case["aadBase64"]


@group_params("webhook")
def test_envelope_shape_has_version_and_no_encrypted_payload(case: Dict[str, Any]) -> None:
    envelope = json.loads(case["body"])
    assert set(envelope) == {
        "envelopeVersion",
        "algorithm",
        "keyFingerprint",
        "encryptedKey",
        "ciphertext",
        "aad",
    }
    assert envelope["envelopeVersion"] == 1
    assert "encryptedPayload" not in envelope


@group_params("webhook")
def test_tampered_body_fails_signature(case: Dict[str, Any], public_keys, private_keys) -> None:
    receiver = _receiver(public_keys, private_keys)
    with pytest.raises(WebhookSignatureError):
        receiver.verify(case["body"].encode("utf-8") + b" ", case["headers"])


@group_params("webhook")
def test_reserialized_body_fails_signature(
    case: Dict[str, Any], public_keys, private_keys
) -> None:
    """签名覆盖的是原始字节:重新序列化 JSON 会改变摘要。"""
    receiver = _receiver(public_keys, private_keys)
    reserialized = json.dumps(json.loads(case["body"]), indent=2).encode("utf-8")
    with pytest.raises(WebhookSignatureError):
        receiver.verify(reserialized, case["headers"])


@group_params("webhook")
@pytest.mark.parametrize(
    "header",
    [
        "X-SlaunchX-Delivery-Id",
        "X-SlaunchX-Event-Type",
        "X-SlaunchX-Timestamp",
    ],
)
def test_tampered_header_fails_signature(
    case: Dict[str, Any], header: str, public_keys, private_keys
) -> None:
    receiver = _receiver(public_keys, private_keys)
    headers = dict(case["headers"])
    headers[header] = headers[header] + "9"
    with pytest.raises(WebhookSignatureError):
        receiver.verify(case["body"].encode("utf-8"), headers)


@group_params("webhook")
def test_missing_header_rejected(case: Dict[str, Any], public_keys, private_keys) -> None:
    receiver = _receiver(public_keys, private_keys)
    for header in (
        "X-SlaunchX-Delivery-Id",
        "X-SlaunchX-Event-Type",
        "X-SlaunchX-Timestamp",
        "X-SlaunchX-Signature",
    ):
        headers = {k: v for k, v in case["headers"].items() if k != header}
        with pytest.raises(WebhookSignatureError):
            receiver.verify(case["body"].encode("utf-8"), headers)


@group_params("webhook")
def test_key_id_mismatch_rejected(case: Dict[str, Any], public_keys, private_keys) -> None:
    receiver = _receiver(public_keys, private_keys, api_key="apk_other_0002")
    with pytest.raises(WebhookSignatureError):
        receiver.verify(case["body"].encode("utf-8"), case["headers"])


@group_params("webhook")
def test_tampered_aad_fails_decryption(
    case: Dict[str, Any], public_keys, private_keys
) -> None:
    receiver = _receiver(public_keys, private_keys)
    body = case["body"].encode("utf-8")
    parts = receiver.verify(body, case["headers"])
    for field in ("deliveryId", "timestamp", "keyId"):
        mutated = dict(parts)
        mutated[field] = mutated[field] + "x"
        with pytest.raises(WebhookEnvelopeError):
            receiver.decrypt(body, mutated)


@group_params("webhook")
def test_envelope_with_encrypted_payload_field_rejected(
    case: Dict[str, Any], public_keys, private_keys
) -> None:
    """Webhook schema 声明 additionalProperties: false。"""
    receiver = _receiver(public_keys, private_keys)
    envelope = json.loads(case["body"])
    parts = receiver.verify(case["body"].encode("utf-8"), case["headers"])
    mutated = copy.deepcopy(envelope)
    mutated["encryptedPayload"] = mutated["ciphertext"]
    with pytest.raises(WebhookEnvelopeError):
        receiver.decrypt(serialize_json(mutated), parts)
    without_version = copy.deepcopy(envelope)
    without_version.pop("envelopeVersion")
    with pytest.raises(WebhookEnvelopeError):
        receiver.decrypt(serialize_json(without_version), parts)
    wrong_version = copy.deepcopy(envelope)
    wrong_version["envelopeVersion"] = 2
    with pytest.raises(WebhookEnvelopeError):
        receiver.decrypt(serialize_json(wrong_version), parts)


@group_params("webhook")
def test_timestamp_tolerance_is_opt_in(
    case: Dict[str, Any], public_keys, private_keys
) -> None:
    body = case["body"].encode("utf-8")
    # 默认关闭:协议未规定 Webhook 时间戳容差
    assert _receiver(public_keys, private_keys).verify(body, case["headers"])
    strict = _receiver(public_keys, private_keys, timestamp_tolerance_ms=60_000)
    with pytest.raises(WebhookSignatureError):
        strict.verify(body, case["headers"])


def test_payload_cross_check(public_keys, private_keys) -> None:
    """明文与传输头不一致必须拒绝(此处用篡改的头触发验签前置失败之后的分支)。"""
    case = load_group("webhook")[0]
    receiver = _receiver(public_keys, private_keys)
    body = case["body"].encode("utf-8")
    parts = receiver.verify(body, case["headers"])
    plaintext = receiver.decrypt(body, parts)
    payload = json.loads(plaintext)
    assert payload["deliveryBizId"] == parts["deliveryId"]
    assert payload["eventType"] == parts["eventType"]
    assert payload["payloadSchemaVersion"] == 1

    class _Forged(WebhookReceiver):
        def decrypt(self, body: bytes, parts):  # type: ignore[override]
            forged = dict(payload)
            forged["eventType"] = "card.transaction"
            return serialize_json(forged)

    forged = _Forged(public_keys["platform_auth"], private_keys["merchant_enc"])
    with pytest.raises(WebhookPayloadError):
        forged.handle(body, case["headers"])


def test_body_must_be_raw_bytes(public_keys, private_keys) -> None:
    from slaunchx_plutus_sdk import ConfigurationError

    case = load_group("webhook")[0]
    receiver = _receiver(public_keys, private_keys)
    with pytest.raises(ConfigurationError):
        receiver.verify(case["body"], case["headers"])  # type: ignore[arg-type]


def test_amount_stays_decimal_string() -> None:
    """金额是十进制字符串,SDK 不得解析成 float。"""
    payload = json.loads('{"amount":{"currency":"USD","amount":"25.80"}}')
    assert isinstance(payload["amount"]["amount"], str)
