import json
import hashlib
from pathlib import Path
from types import SimpleNamespace
import pytest
from slaunchx_plutus_sdk import PlutusConfig, PlutusClient, ProtocolProfile, RequestSigner, ResponseSignatureError, ConfigurationError
from slaunchx_plutus_sdk.signer import canonicalize_query, sign_canonical_string
from slaunchx_plutus_sdk.verifier import ResponseVerifier
from slaunchx_plutus_sdk.errors import CanonicalQueryError

PROFILE = ProtocolProfile.PRODUCT_V1
QUERIES = json.loads((Path(__file__).parents[2] / "shared/product-query-vectors.json").read_text())

@pytest.mark.parametrize("raw,expected", QUERIES["valid"])
def test_product_query(raw, expected):
    assert canonicalize_query(raw, PROFILE) == expected

@pytest.mark.parametrize("raw", QUERIES["invalid"])
def test_product_rejects_invalid_query(raw):
    with pytest.raises(CanonicalQueryError):
        canonicalize_query(raw, PROFILE)

@pytest.mark.parametrize("mode", ["missing", "present", "wrong", "empty", "tamper", "other", "alpha", "unsigned"])
def test_client_product_response(private_keys, public_keys, mode):
    calls = []
    body = b'{"success":true,"data":[]}'
    def send(**req):
        calls.append(req)
        h = req["headers"]
        assert h["X-Idempotency-Key"] == "operation-1"
        assert req["url"].endswith("?q=a%20b&star=*&tilde=%7E")
        from slaunchx_plutus_sdk.verifier import verify_signature
        canonical = "\n".join([req["method"], "/test", "q=a%20b&star=*&tilde=%7E", h["X-Timestamp"], h["X-Nonce"], "1", hashlib.sha256(req["data"] or b"").hexdigest()])
        assert verify_signature(public_keys["merchant_auth"], canonical, h["X-Signature"])
        request_id = "another-id" if mode == "other" else h["X-Request-Id"]
        lines = [request_id, "200", "application/json", "1788836400000", hashlib.sha256(body).hexdigest()]
        if mode == "alpha":
            lines = ["SLAUNCHX-API-RESPONSE-V1", hashlib.sha256(canonical.encode()).hexdigest(), "1", "/test", ""] + lines
        headers = {"Content-Type":"application/json", "X-Response-Timestamp":"1788836400000", "X-Response-Signature":sign_canonical_string(private_keys["platform_auth"], "\n".join(lines))}
        if mode in ("present", "wrong", "empty"):
            headers["X-Request-Id"] = {"present":request_id,"wrong":"wrong-id","empty":""}[mode]
        if mode == "unsigned": del headers["X-Response-Signature"]
        return SimpleNamespace(status_code=200, headers=headers, content=body + (b" " if mode == "tamper" else b""))
    config = PlutusConfig("https://example.test", "test-key", merchant_auth_private_key=private_keys["merchant_auth"], platform_auth_public_key=public_keys["platform_auth"], protocol_profile=PROFILE)
    client = PlutusClient(config, session=SimpleNamespace(request=send))
    def invoke(): return client.post("/test", query="q=a+b&tilde=~&star=%2A", json_body={"ok":True}, idempotency_key="operation-1")
    if mode in ("missing","present"):
        assert invoke().signature_verified
        assert invoke().signature_verified
        assert calls[0]["headers"]["X-Request-Id"] != calls[1]["headers"]["X-Request-Id"]
    else:
        with pytest.raises(ResponseSignatureError): invoke()

@pytest.mark.parametrize("headers,request_id", [({"x-request-id":"a","X-Request-Id":"b"},None), ({"x-request-id":"a"},"b"), ({"x-request-id":"a\nb"},None)])
def test_product_rejects_ambiguous_ids(private_keys, headers, request_id):
    config = PlutusConfig("https://example.test", "key", merchant_auth_private_key=private_keys["merchant_auth"], verify_response_signature=False, protocol_profile=PROFILE)
    with pytest.raises(ConfigurationError):
        PlutusClient(config).get("/test", headers=headers, request_id=request_id)

def test_profiles_do_not_fall_back(private_keys, public_keys):
    signed = RequestSigner(private_keys["merchant_auth"], "key").sign("GET", "/test")
    assert len(signed.canonical_string.split("\n")) == 8
    body = b"{}"
    canonical = "\n".join(["id", "200", "application/json", "1788836400000", hashlib.sha256(body).hexdigest()])
    with pytest.raises(ResponseSignatureError):
        ResponseVerifier(public_keys["platform_auth"]).verify(request_canonical_sha256=signed.canonical_sha256, api_version="1", external_path="/test", http_status=200, headers={"X-Request-Id":"id", "Content-Type":"application/json", "X-Response-Timestamp":"1788836400000", "X-Response-Signature":sign_canonical_string(private_keys["platform_auth"], canonical)}, body=body, sent_request_id="id")
    with pytest.raises(ConfigurationError): PlutusConfig("https://example.test", "key", protocol_profile="unknown")
