"""requestSignature 向量组:7 例,规范串逐行比对 + 签名比对 + 篡改必失败。"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from slaunchx_plutus_sdk import (
    RequestSigner,
    body_sha256_hex,
    build_request_canonical_string,
    canonical_sha256,
    canonicalize_query,
    generate_nonce,
    sign_canonical_string,
    validate_nonce,
    verify_signature,
)
from slaunchx_plutus_sdk.errors import ConfigurationError
from slaunchx_plutus_sdk.signer import NONCE_PATTERN, SIGNATURE_ALGORITHM

from conftest import group_params, load_group


def _rebuild(case: Dict[str, Any]) -> str:
    req = case["request"]
    digest = body_sha256_hex(
        None if req["body"] is None else req["body"].encode("utf-8"), req["method"]
    )
    assert digest == case["bodyHash"]
    canonical_query = canonicalize_query(req["queryString"])
    assert canonical_query == case["canonicalQuery"]
    return build_request_canonical_string(
        req["method"],
        req["externalPath"],
        canonical_query,
        req["timestamp"],
        req["nonce"],
        req["apiVersion"],
        req["idempotencyKey"],
        digest,
    )


def test_group_size() -> None:
    assert len(load_group("requestSignature")) == 7


@group_params("requestSignature")
def test_canonical_string_and_lines(case: Dict[str, Any]) -> None:
    canonical = _rebuild(case)
    assert canonical == case["canonicalString"]
    assert canonical.split("\n") == case["canonicalStringLines"]
    assert len(case["canonicalStringLines"]) == 8
    assert canonical_sha256(canonical) == case["requestCanonicalSha256"]


@group_params("requestSignature")
def test_signature_matches_vector(case: Dict[str, Any], private_keys, public_keys) -> None:
    canonical = _rebuild(case)
    key_name = case["signingKey"]
    # PKCS#1 v1.5 是确定性的: 重新签名必须逐字节等于向量
    assert sign_canonical_string(private_keys[key_name], canonical) == case["signature"]
    assert verify_signature(public_keys[key_name], canonical, case["signature"])


@group_params("requestSignature")
def test_tampered_canonical_fails_verification(case: Dict[str, Any], public_keys) -> None:
    canonical = _rebuild(case)
    key = public_keys[case["signingKey"]]
    lines = canonical.split("\n")
    for index in range(len(lines)):
        tampered = list(lines)
        tampered[index] = tampered[index] + "x"
        assert not verify_signature(key, "\n".join(tampered), case["signature"])


@group_params("requestSignature")
def test_signer_reproduces_vector_headers(case: Dict[str, Any], private_keys) -> None:
    req = case["request"]
    expected_headers = case["headers"]
    signer = RequestSigner(
        private_keys[case["signingKey"]], expected_headers["X-Api-Key"], req["apiVersion"]
    )
    signed = signer.sign(
        req["method"],
        req["externalPath"],
        query=req["queryString"],
        body=None if req["body"] is None else req["body"].encode("utf-8"),
        idempotency_key=req["idempotencyKey"],
        timestamp=req["timestamp"],
        nonce=req["nonce"],
    )
    assert signed.canonical_string == case["canonicalString"]
    assert signed.canonical_sha256 == case["requestCanonicalSha256"]
    assert signed.signature == case["signature"]
    assert signed.headers == expected_headers
    assert signed.headers["X-Signature-Algorithm"] == SIGNATURE_ALGORITHM


def test_encrypted_request_headers(private_keys) -> None:
    signer = RequestSigner(private_keys["merchant_auth"], "apk_vector_0001", api_version="1")
    signed = signer.sign(
        "POST",
        "/card-products/10010106/shared/cards/create",
        body=b"{}",
        request_id="req_1",
        platform_encryption_key_id="SHA256:" + "0" * 64,
    )
    assert signed.headers["X-Request-Id"] == "req_1"
    assert signed.headers["X-Platform-Encryption-Key-Id"] == "SHA256:" + "0" * 64
    # X-Request-Id 与 X-Platform-Encryption-Key-Id 不参与请求签名
    assert "req_1" not in signed.canonical_string


def test_external_path_must_not_carry_version_prefix(private_keys) -> None:
    signer = RequestSigner(private_keys["merchant_auth"], "apk_vector_0001", api_version="1")
    with pytest.raises(ConfigurationError):
        signer.sign("GET", "card-products/cards/page")


def test_generated_nonce_is_valid() -> None:
    for _ in range(64):
        nonce = generate_nonce()
        assert NONCE_PATTERN.match(nonce), nonce
        assert validate_nonce(nonce) == nonce


@pytest.mark.parametrize(
    "nonce",
    ["short", "AAAA+AAAA/AAAA==", "abc def ghi jkl mno", "a" * 129, ""],
)
def test_invalid_nonce_rejected(nonce: str) -> None:
    with pytest.raises(ConfigurationError):
        validate_nonce(nonce)
