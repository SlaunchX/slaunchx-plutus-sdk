"""encryptedEnvelope 向量组:3 例解密比对 + 加密方向 round-trip + AAD 负向。"""

from __future__ import annotations

import base64
import copy
import os
from typing import Any, Dict

import pytest

from slaunchx_plutus_sdk import (
    ENVELOPE_ALGORITHM,
    EnvelopeError,
    build_aad,
    decrypt_envelope,
    decrypt_sensitive_response,
    encrypt_envelope,
    encrypt_request_payload,
    parse_aad,
    spki_fingerprint,
)

from conftest import group_params, load_group


def _aad(case: Dict[str, Any]) -> bytes:
    parts = case["aadComponents"]
    return build_aad(
        parts["requestId"], parts["routeTemplate"], parts["timestamp"], parts["keyId"]
    )


def test_group_size() -> None:
    cases = load_group("encryptedEnvelope")
    assert len(cases) == 3
    directions = {case["direction"] for case in cases}
    assert directions == {"request", "sensitive_response"}


@group_params("encryptedEnvelope")
def test_aad_reconstruction(case: Dict[str, Any]) -> None:
    aad = _aad(case)
    assert aad.decode("utf-8") == case["aadString"]
    assert base64.b64encode(aad).decode("ascii") == case["aadBase64"]
    assert case["aadBase64"] == case["envelope"]["aad"]
    assert parse_aad(aad) == case["aadComponents"]


@group_params("encryptedEnvelope")
def test_decrypt_matches_expected_plaintext(case: Dict[str, Any], private_keys, keys) -> None:
    name = case["decryptionKey"]
    plaintext = decrypt_envelope(
        private_keys[name],
        case["envelope"],
        _aad(case),
        expected_fingerprint=keys[name]["fingerprint"],
    )
    assert plaintext.decode("utf-8") == case["expectedPlaintext"]
    assert case["envelope"]["keyFingerprint"] == keys[name]["fingerprint"]
    assert case["envelope"]["algorithm"] == ENVELOPE_ALGORITHM
    assert case["envelope"]["encryptedPayload"] == case["envelope"]["ciphertext"]


@group_params("encryptedEnvelope")
def test_tampered_aad_is_rejected(case: Dict[str, Any], private_keys) -> None:
    parts = case["aadComponents"]
    private_key = private_keys[case["decryptionKey"]]
    mutations = [
        (parts["requestId"] + "x", parts["routeTemplate"], parts["timestamp"], parts["keyId"]),
        (parts["requestId"], parts["routeTemplate"] + "x", parts["timestamp"], parts["keyId"]),
        (parts["requestId"], parts["routeTemplate"], parts["timestamp"] + "0", parts["keyId"]),
        (parts["requestId"], parts["routeTemplate"], parts["timestamp"], parts["keyId"] + "x"),
    ]
    for mutated in mutations:
        with pytest.raises(EnvelopeError):
            decrypt_envelope(private_key, case["envelope"], build_aad(*mutated))


@group_params("encryptedEnvelope")
def test_tampered_ciphertext_is_rejected(case: Dict[str, Any], private_keys) -> None:
    envelope = copy.deepcopy(case["envelope"])
    blob = bytearray(base64.b64decode(envelope["ciphertext"]))
    blob[-1] ^= 0x01
    envelope["ciphertext"] = base64.b64encode(bytes(blob)).decode("ascii")
    with pytest.raises(EnvelopeError):
        decrypt_envelope(private_keys[case["decryptionKey"]], envelope, _aad(case))


@group_params("encryptedEnvelope")
def test_echoed_aad_alone_is_not_authoritative(case: Dict[str, Any], private_keys) -> None:
    """信封里的 aad 只是回显:即使回显值与密文自洽,与本地重建值不符也必须拒绝。"""
    envelope = copy.deepcopy(case["envelope"])
    wrong = build_aad("attacker", "webhook", "0", "SHA256:" + "0" * 64)
    envelope["aad"] = base64.b64encode(wrong).decode("ascii")
    with pytest.raises(EnvelopeError):
        decrypt_envelope(private_keys[case["decryptionKey"]], envelope, _aad(case))


@pytest.mark.parametrize(
    "mutation",
    [
        {"algorithm": "AES-256-GCM"},
        {"algorithm": None},
        {"encryptedKey": ""},
        {"ciphertext": "not-base64!!"},
        {"ciphertext": base64.b64encode(b"short").decode("ascii")},
    ],
)
def test_envelope_shape_validation(mutation: Dict[str, Any], private_keys) -> None:
    case = load_group("encryptedEnvelope")[0]
    envelope = copy.deepcopy(case["envelope"])
    envelope.update(mutation)
    with pytest.raises(EnvelopeError):
        decrypt_envelope(private_keys[case["decryptionKey"]], envelope, _aad(case))


def test_missing_required_field(private_keys) -> None:
    case = load_group("encryptedEnvelope")[0]
    for field in ("algorithm", "keyFingerprint", "encryptedKey", "ciphertext", "aad"):
        envelope = copy.deepcopy(case["envelope"])
        del envelope[field]
        with pytest.raises(EnvelopeError):
            decrypt_envelope(private_keys[case["decryptionKey"]], envelope, _aad(case))


def test_fingerprint_mismatch_rejected(private_keys) -> None:
    case = load_group("encryptedEnvelope")[0]
    with pytest.raises(EnvelopeError):
        decrypt_envelope(
            private_keys[case["decryptionKey"]],
            case["envelope"],
            _aad(case),
            expected_fingerprint="SHA256:" + "0" * 64,
        )


# -- 加密方向 round-trip(GCM 随机 IV,无法静态比对密文) ---------------------


def test_encrypt_request_payload_round_trip(private_keys, public_keys, keys) -> None:
    plaintext = '{"platformCardProductBizId":"pcp_example_001","quantity":2}'.encode("utf-8")
    route = "/card-products/10010106/shared/cards/create"
    envelope = encrypt_request_payload(
        public_keys["platform_enc"],
        plaintext,
        request_id="req_local_0001",
        route_template=route,
        timestamp="1755600010000",
    )
    assert envelope["algorithm"] == ENVELOPE_ALGORITHM
    assert envelope["keyFingerprint"] == keys["platform_enc"]["fingerprint"]
    assert envelope["encryptedPayload"] == envelope["ciphertext"]
    assert set(envelope) == {
        "algorithm",
        "keyFingerprint",
        "encryptedKey",
        "ciphertext",
        "aad",
        "encryptedPayload",
    }
    expected_aad = build_aad(
        "req_local_0001", route, "1755600010000", keys["platform_enc"]["fingerprint"]
    )
    assert base64.b64decode(envelope["aad"]) == expected_aad
    # 平台侧用平台加密私钥解开
    assert (
        decrypt_envelope(private_keys["platform_enc"], envelope, expected_aad) == plaintext
    )
    # IV 12 字节 + 标签 16 字节
    assert len(base64.b64decode(envelope["ciphertext"])) == len(plaintext) + 12 + 16


def test_two_encryptions_differ(public_keys) -> None:
    kwargs = dict(
        request_id="req_local_0002",
        route_template="/card-products/10010105/cards/create",
        timestamp="1755600010000",
    )
    first = encrypt_request_payload(public_keys["platform_enc"], b"{}", **kwargs)
    second = encrypt_request_payload(public_keys["platform_enc"], b"{}", **kwargs)
    assert first["ciphertext"] != second["ciphertext"]
    assert first["aad"] == second["aad"]


def test_encrypt_request_requires_request_id_and_timestamp(public_keys) -> None:
    with pytest.raises(EnvelopeError):
        encrypt_request_payload(
            public_keys["platform_enc"], b"{}", request_id="", route_template="/x", timestamp="1"
        )
    with pytest.raises(EnvelopeError):
        encrypt_request_payload(
            public_keys["platform_enc"], b"{}", request_id="r", route_template="/x", timestamp=""
        )


def test_sensitive_response_round_trip(private_keys, public_keys, keys) -> None:
    plaintext = b'{"cardNumber":"4111111111111111"}'
    fingerprint = keys["merchant_enc"]["fingerprint"]
    aad = build_aad("req_local_0003", "", "1755600011000", fingerprint)
    envelope = encrypt_envelope(public_keys["merchant_enc"], plaintext, aad)
    assert (
        decrypt_sensitive_response(
            private_keys["merchant_enc"],
            envelope,
            request_id="req_local_0003",
            timestamp="1755600011000",
        )
        == plaintext
    )


@group_params("encryptedEnvelope")
def test_decrypt_sensitive_response_helper(case: Dict[str, Any], private_keys) -> None:
    if case["direction"] != "sensitive_response":
        pytest.skip("仅适用于敏感响应方向")
    parts = case["aadComponents"]
    # timestamp 与 requestId 从信封回显的 aad 解析重建
    plaintext = decrypt_sensitive_response(private_keys["merchant_enc"], case["envelope"])
    assert plaintext.decode("utf-8") == case["expectedPlaintext"]
    # 提供已知值时逐字节比对
    assert (
        decrypt_sensitive_response(
            private_keys["merchant_enc"],
            case["envelope"],
            request_id=parts["requestId"],
            timestamp=parts["timestamp"],
        )
        == plaintext
    )
    with pytest.raises(EnvelopeError):
        decrypt_sensitive_response(
            private_keys["merchant_enc"], case["envelope"], timestamp="1"
        )
    with pytest.raises(EnvelopeError):
        decrypt_sensitive_response(
            private_keys["merchant_enc"], case["envelope"], request_id="someone-else"
        )


def test_decrypt_sensitive_response_rejects_non_empty_route(private_keys) -> None:
    case = [c for c in load_group("encryptedEnvelope") if c["direction"] == "request"][0]
    with pytest.raises(EnvelopeError):
        decrypt_sensitive_response(private_keys["platform_enc"], case["envelope"])


def test_spki_fingerprint_matches_vectors(public_keys, private_keys, keys) -> None:
    for name, key in keys.items():
        assert spki_fingerprint(public_keys[name]) == key["fingerprint"]
        assert spki_fingerprint(private_keys[name]) == key["fingerprint"]


def test_plaintext_size_limit(public_keys, private_keys) -> None:
    aad = build_aad("r", "/x", "1", "k")
    envelope = encrypt_envelope(public_keys["merchant_enc"], os.urandom(64), aad)
    with pytest.raises(EnvelopeError):
        decrypt_envelope(
            private_keys["merchant_enc"], envelope, aad, max_plaintext_bytes=8
        )
