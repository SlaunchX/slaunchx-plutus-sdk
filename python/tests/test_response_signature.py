"""responseSignature 向量组:3 例,10 行规范串 + 验签 + 负向。"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from slaunchx_plutus_sdk import (
    ResponseSignatureError,
    ResponseVerifier,
    build_response_canonical_string,
    response_body_sha256_hex,
    verify_signature,
)
from slaunchx_plutus_sdk.verifier import RESPONSE_CANONICAL_PREFIX

from conftest import group_params, load_group


def _rebuild(case: Dict[str, Any]) -> str:
    body = case["responseBody"].encode("utf-8")
    digest = response_body_sha256_hex(body)
    assert digest == case["responseBodyHash"]
    return build_response_canonical_string(
        case["requestCanonicalSha256"],
        case["apiVersion"],
        case["externalPath"],
        case["operationId"],
        case["requestId"],
        case["httpStatus"],
        case["contentType"],
        case["responseTimestamp"],
        digest,
    )


def _headers(case: Dict[str, Any]) -> Dict[str, str]:
    headers = {
        "Content-Type": case["contentType"],
        "X-Response-Timestamp": case["responseTimestamp"],
        "X-Response-Signature": case["signature"],
        "X-Response-Signature-Algorithm": "RSA-SHA256",
    }
    if case["requestId"]:
        headers["X-Request-Id"] = case["requestId"]
    if case["operationId"]:
        headers["X-Operation-Id"] = case["operationId"]
    return headers


def test_group_size() -> None:
    assert len(load_group("responseSignature")) == 3


@group_params("responseSignature")
def test_response_canonical_and_signature(case: Dict[str, Any], public_keys) -> None:
    canonical = _rebuild(case)
    assert canonical == case["canonicalString"]
    assert canonical.split("\n") == case["canonicalStringLines"]
    assert canonical.split("\n")[0] == RESPONSE_CANONICAL_PREFIX
    assert len(case["canonicalStringLines"]) == 10
    assert verify_signature(public_keys[case["signingKey"]], canonical, case["signature"])


@group_params("responseSignature")
def test_response_binding_matches_request_vector(case: Dict[str, Any]) -> None:
    linked = {c["id"]: c for c in load_group("requestSignature")}[case["requestVectorId"]]
    assert linked["requestCanonicalSha256"] == case["requestCanonicalSha256"]


@group_params("responseSignature")
def test_verifier_accepts_vector_headers(case: Dict[str, Any], public_keys) -> None:
    verifier = ResponseVerifier(public_keys[case["signingKey"]])
    assert verifier.verify(
        request_canonical_sha256=case["requestCanonicalSha256"],
        api_version=case["apiVersion"],
        external_path=case["externalPath"],
        http_status=case["httpStatus"],
        headers=_headers(case),
        body=case["responseBody"].encode("utf-8"),
        require_signature_on_error=True,
    )


@group_params("responseSignature")
def test_verifier_headers_are_case_insensitive(case: Dict[str, Any], public_keys) -> None:
    verifier = ResponseVerifier(public_keys[case["signingKey"]])
    lowered = {k.lower(): v for k, v in _headers(case).items()}
    assert verifier.verify(
        request_canonical_sha256=case["requestCanonicalSha256"],
        api_version=case["apiVersion"],
        external_path=case["externalPath"],
        http_status=case["httpStatus"],
        headers=lowered,
        body=case["responseBody"].encode("utf-8"),
    )


@group_params("responseSignature")
def test_tampered_response_fails(case: Dict[str, Any], public_keys) -> None:
    verifier = ResponseVerifier(public_keys[case["signingKey"]])
    base = dict(
        request_canonical_sha256=case["requestCanonicalSha256"],
        api_version=case["apiVersion"],
        external_path=case["externalPath"],
        http_status=case["httpStatus"],
        headers=_headers(case),
        body=case["responseBody"].encode("utf-8"),
    )
    # 响应体被改动
    with pytest.raises(ResponseSignatureError):
        verifier.verify(**{**base, "body": case["responseBody"].encode("utf-8") + b" "})
    # 请求绑定摘要被替换(把一个合法响应挪用到另一个请求上)
    with pytest.raises(ResponseSignatureError):
        verifier.verify(**{**base, "request_canonical_sha256": "0" * 64})
    # 外部路径被改动
    with pytest.raises(ResponseSignatureError):
        verifier.verify(**{**base, "external_path": case["externalPath"] + "x"})
    # 状态码被改动
    with pytest.raises(ResponseSignatureError):
        verifier.verify(**{**base, "http_status": case["httpStatus"] + 1})


@group_params("responseSignature")
def test_content_type_must_not_be_normalized(case: Dict[str, Any], public_keys) -> None:
    verifier = ResponseVerifier(public_keys[case["signingKey"]])
    headers = _headers(case)
    headers["Content-Type"] = case["contentType"].split(";")[0] + ";charset=utf-8"
    if headers["Content-Type"] == case["contentType"]:
        pytest.skip("该向量的 Content-Type 无 charset 参数可供改写")
    with pytest.raises(ResponseSignatureError):
        verifier.verify(
            request_canonical_sha256=case["requestCanonicalSha256"],
            api_version=case["apiVersion"],
            external_path=case["externalPath"],
            http_status=case["httpStatus"],
            headers=headers,
            body=case["responseBody"].encode("utf-8"),
        )


def _missing_signature_kwargs(http_status: int) -> Dict[str, Any]:
    return dict(
        request_canonical_sha256="0" * 64,
        api_version="1",
        external_path="/card-products/cards/page",
        http_status=http_status,
        headers={"Content-Type": "application/json"},
        body=b"{}",
    )


@pytest.mark.parametrize("http_status", [200, 201, 204, 299])
def test_missing_signature_on_2xx_always_raises(public_keys, http_status: int) -> None:
    verifier = ResponseVerifier(public_keys["platform_auth"])
    kwargs = _missing_signature_kwargs(http_status)
    with pytest.raises(ResponseSignatureError):
        verifier.verify(**kwargs)
    # 严格开关只影响非 2xx,2xx 无论如何都要签名
    with pytest.raises(ResponseSignatureError):
        verifier.verify(**kwargs, require_signature_on_error=True)


@pytest.mark.parametrize("http_status", [301, 400, 401, 403, 500])
def test_missing_signature_on_non_2xx(public_keys, http_status: int) -> None:
    verifier = ResponseVerifier(public_keys["platform_auth"])
    kwargs = _missing_signature_kwargs(http_status)
    assert verifier.verify(**kwargs) is False
    with pytest.raises(ResponseSignatureError):
        verifier.verify(**kwargs, require_signature_on_error=True)


def test_wrong_public_key_rejected(public_keys) -> None:
    case = load_group("responseSignature")[0]
    verifier = ResponseVerifier(public_keys["merchant_auth"])
    with pytest.raises(ResponseSignatureError):
        verifier.verify(
            request_canonical_sha256=case["requestCanonicalSha256"],
            api_version=case["apiVersion"],
            external_path=case["externalPath"],
            http_status=case["httpStatus"],
            headers=_headers(case),
            body=case["responseBody"].encode("utf-8"),
        )
