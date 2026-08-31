#!/usr/bin/env python3
"""SlaunchX Plutus 商户 SDK 黄金向量独立校验器.

本脚本按 SPEC.md 重新实现协议 (不依赖服务端 Java 代码, 也不依赖任何 SlaunchX SDK),
再逐条比对 shared/test-vectors.json. 用途:

1. 证明向量不是自我循环 —— 由 Java 生成, 由 Python 独立复算校验;
2. 作为五个语言 SDK 的通用回归工具: 任何语言实现完成后, 用同一份向量 + 同一套断言。

依赖: cryptography>=3.4 (pip install cryptography)

用法:
    python3 shared/tools/verify_vectors.py [--vectors shared/test-vectors.json] [--verbose]
退出码: 0 全部通过; 1 存在失败。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
UNRESERVED = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
FORCED_EMPTY_BODY_METHODS = {"GET", "HEAD", "DELETE"}


class CanonicalError(ValueError):
    """规范化查询串被拒绝."""


# --------------------------------------------------------------------------
# 协议原语 (独立实现, 与服务端代码无共享)
# --------------------------------------------------------------------------


def _percent_decode_strict(component: str) -> bytes:
    """严格 percent-decode: 只接受 unreserved 字面量与合法 %XX; 结果必须是合法 UTF-8."""
    out = bytearray()
    i = 0
    n = len(component)
    while i < n:
        ch = component[i]
        if ch == "%":
            if i + 2 >= n:
                raise CanonicalError("incomplete percent encoding")
            hi, lo = component[i + 1], component[i + 2]
            if hi not in "0123456789abcdefABCDEF" or lo not in "0123456789abcdefABCDEF":
                raise CanonicalError("invalid percent encoding")
            out.append(int(hi, 16) * 16 + int(lo, 16))
            i += 3
            continue
        code = ord(ch)
        if code > 0x7F or code not in UNRESERVED:
            raise CanonicalError("reserved or non-ASCII character must be percent-encoded")
        out.append(code)
        i += 1
    try:
        out.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalError("percent-decoded bytes are not valid UTF-8") from exc
    return bytes(out)


def _percent_encode(raw: bytes) -> str:
    parts = []
    for byte in raw:
        if byte in UNRESERVED:
            parts.append(chr(byte))
        else:
            parts.append("%%%02X" % byte)
    return "".join(parts)


def canonicalize_component(component: str) -> str:
    return _percent_encode(_percent_decode_strict(component))


def canonicalize_query(query: str | None) -> str:
    if query is None or query.strip() == "":
        return ""
    pairs = []
    for pair in query.split("&"):
        idx = pair.find("=")
        raw_key = pair if idx < 0 else pair[:idx]
        raw_value = "" if idx < 0 else pair[idx + 1 :]
        pairs.append((canonicalize_component(raw_key), canonicalize_component(raw_value)))
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    return "&".join("%s=%s" % kv for kv in pairs)


def body_hash(body: bytes | None) -> str:
    if not body:
        return EMPTY_BODY_SHA256
    return hashlib.sha256(body).hexdigest()


def request_canonical(
    method: str,
    external_path: str,
    query: str | None,
    timestamp: str,
    nonce: str,
    api_version: str,
    idempotency_key: str | None,
    digest: str,
) -> str:
    if not api_version or not api_version.strip():
        raise ValueError("apiVersion is required")
    return "\n".join(
        [
            method,
            external_path,
            canonicalize_query(query),
            timestamp,
            nonce,
            api_version,
            idempotency_key or "",
            digest,
        ]
    )


def response_canonical(
    request_canonical_sha256: str,
    api_version: str,
    external_path: str,
    operation_id: str | None,
    request_id: str | None,
    http_status: int,
    content_type: str | None,
    response_timestamp: str | None,
    response_body_hash: str | None,
) -> str:
    return "\n".join(
        [
            "SLAUNCHX-API-RESPONSE-V1",
            request_canonical_sha256,
            api_version,
            external_path,
            operation_id or "",
            request_id or "",
            str(http_status),
            content_type or "",
            response_timestamp or "",
            response_body_hash or "",
        ]
    )


def build_aad(request_id: str, route_template: str, timestamp: str, key_id: str) -> bytes:
    return "|".join(
        [request_id or "", route_template or "", timestamp or "", key_id or ""]
    ).encode("utf-8")


def load_public(pem: str):
    return serialization.load_pem_public_key(pem.encode("ascii"))


def load_private(pem: str):
    return serialization.load_pem_private_key(pem.encode("ascii"), password=None)


def rsa_verify(public_pem: str, canonical: str, signature_b64: str) -> bool:
    try:
        load_public(public_pem).verify(
            base64.b64decode(signature_b64),
            canonical.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def open_envelope(private_pem: str, encrypted_key_b64: str, ciphertext_b64: str, aad: bytes) -> str:
    aes_key = load_private(private_pem).decrypt(
        base64.b64decode(encrypted_key_b64),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(aes_key) != 32:
        raise ValueError("unwrapped AES key must be 32 bytes")
    blob = base64.b64decode(ciphertext_b64)
    iv, sealed = blob[:12], blob[12:]
    return AESGCM(aes_key).decrypt(iv, sealed, aad).decode("utf-8")


def spki_fingerprint(public_pem: str) -> str:
    der = load_public(public_pem).public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "SHA256:" + hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------------
# 校验驱动
# --------------------------------------------------------------------------


class Report:
    def __init__(self, verbose: bool) -> None:
        self.verbose = verbose
        self.passed = 0
        self.failures: list[str] = []

    def check(self, group: str, case_id: str, ok: bool, detail: str = "") -> None:
        if ok:
            self.passed += 1
            if self.verbose:
                print(f"  PASS {group}/{case_id}")
        else:
            self.failures.append(f"{group}/{case_id}: {detail}")
            print(f"  FAIL {group}/{case_id}: {detail}")


def verify_keys(data: dict[str, Any], report: Report) -> None:
    for name, key in data["keys"].items():
        pub = load_public(key["publicKeyPem"])
        priv = load_private(key["privateKeyPem"])
        report.check(
            "keys",
            f"{name}/modulus-bits",
            pub.key_size == key["modulusBits"] == 2048,
            f"key_size={pub.key_size}",
        )
        report.check(
            "keys",
            f"{name}/public-exponent",
            pub.public_numbers().e == 65537,
            f"e={pub.public_numbers().e}",
        )
        report.check(
            "keys",
            f"{name}/pair-matches",
            priv.public_key().public_numbers() == pub.public_numbers(),
            "private key does not match the published public key",
        )
        report.check(
            "keys",
            f"{name}/fingerprint",
            spki_fingerprint(key["publicKeyPem"]) == key["fingerprint"],
            f"expected {key['fingerprint']}, recomputed {spki_fingerprint(key['publicKeyPem'])}",
        )


def verify_canonical_query(data: dict[str, Any], report: Report) -> None:
    for case in data["vectors"]["canonicalQuery"]:
        try:
            actual = canonicalize_query(case["input"])
            rejected = False
        except CanonicalError:
            actual = None
            rejected = True
        if case["expectError"]:
            report.check(
                "canonicalQuery", case["id"], rejected, f"expected rejection, produced {actual!r}"
            )
        else:
            report.check(
                "canonicalQuery",
                case["id"],
                (not rejected) and actual == case["expected"],
                f"expected {case['expected']!r}, got {actual!r}",
            )


def verify_body_hash(data: dict[str, Any], report: Report) -> None:
    for case in data["vectors"]["bodyHash"]:
        method = case.get("method")
        forced = method is not None and method.upper() in FORCED_EMPTY_BODY_METHODS
        report.check(
            "bodyHash",
            case["id"] + "/forced-flag",
            forced == case["forcedEmptyBody"],
            "forced-empty-body flag mismatch",
        )
        raw = None if case["body"] is None else case["body"].encode("utf-8")
        actual = EMPTY_BODY_SHA256 if forced else body_hash(raw)
        report.check(
            "bodyHash",
            case["id"],
            actual == case["expected"],
            f"expected {case['expected']}, got {actual}",
        )


def verify_request_signature(data: dict[str, Any], report: Report) -> None:
    keys = data["keys"]
    for case in data["vectors"]["requestSignature"]:
        req = case["request"]
        forced = req["method"].upper() in FORCED_EMPTY_BODY_METHODS
        raw = None if req["body"] is None else req["body"].encode("utf-8")
        digest = EMPTY_BODY_SHA256 if forced else body_hash(raw)
        report.check(
            "requestSignature",
            case["id"] + "/body-hash",
            digest == case["bodyHash"],
            f"expected {case['bodyHash']}, got {digest}",
        )
        canonical = request_canonical(
            req["method"],
            req["externalPath"],
            req["queryString"],
            req["timestamp"],
            req["nonce"],
            req["apiVersion"],
            req["idempotencyKey"],
            digest,
        )
        report.check(
            "requestSignature",
            case["id"] + "/canonical",
            canonical == case["canonicalString"],
            f"rebuilt canonical differs:\n    expected={case['canonicalString']!r}\n    actual  ={canonical!r}",
        )
        report.check(
            "requestSignature",
            case["id"] + "/canonical-lines",
            canonical.split("\n") == case["canonicalStringLines"],
            "canonical line split mismatch",
        )
        sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        report.check(
            "requestSignature",
            case["id"] + "/canonical-sha256",
            sha == case["requestCanonicalSha256"],
            f"expected {case['requestCanonicalSha256']}, got {sha}",
        )
        report.check(
            "requestSignature",
            case["id"] + "/signature",
            rsa_verify(keys[case["signingKey"]]["publicKeyPem"], canonical, case["signature"]),
            "RSA-SHA256 verification failed against the merchant authentication public key",
        )
        # 负向: 篡改一个字节后必须验签失败
        tampered = canonical.replace(req["nonce"], req["nonce"] + "x", 1)
        report.check(
            "requestSignature",
            case["id"] + "/tamper-rejected",
            not rsa_verify(keys[case["signingKey"]]["publicKeyPem"], tampered, case["signature"]),
            "a tampered canonical string still verified",
        )


def verify_response_signature(data: dict[str, Any], report: Report) -> None:
    keys = data["keys"]
    by_id = {c["id"]: c for c in data["vectors"]["requestSignature"]}
    for case in data["vectors"]["responseSignature"]:
        linked = by_id[case["requestVectorId"]]
        report.check(
            "responseSignature",
            case["id"] + "/request-binding",
            linked["requestCanonicalSha256"] == case["requestCanonicalSha256"],
            "response is not bound to the referenced request canonical digest",
        )
        digest = hashlib.sha256(case["responseBody"].encode("utf-8")).hexdigest()
        report.check(
            "responseSignature",
            case["id"] + "/body-hash",
            digest == case["responseBodyHash"],
            f"expected {case['responseBodyHash']}, got {digest}",
        )
        canonical = response_canonical(
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
        report.check(
            "responseSignature",
            case["id"] + "/canonical",
            canonical == case["canonicalString"],
            f"rebuilt canonical differs:\n    expected={case['canonicalString']!r}\n    actual  ={canonical!r}",
        )
        report.check(
            "responseSignature",
            case["id"] + "/signature",
            rsa_verify(keys[case["signingKey"]]["publicKeyPem"], canonical, case["signature"]),
            "RSA-SHA256 verification failed against the platform authentication public key",
        )


def verify_envelopes(data: dict[str, Any], report: Report) -> None:
    keys = data["keys"]
    for case in data["vectors"]["encryptedEnvelope"]:
        parts = case["aadComponents"]
        aad = build_aad(parts["requestId"], parts["routeTemplate"], parts["timestamp"], parts["keyId"])
        report.check(
            "encryptedEnvelope",
            case["id"] + "/aad",
            base64.b64encode(aad).decode("ascii") == case["aadBase64"] == case["envelope"]["aad"],
            "rebuilt AAD does not match the envelope's declared AAD",
        )
        priv = keys[case["decryptionKey"]]["privateKeyPem"]
        try:
            plaintext = open_envelope(
                priv, case["envelope"]["encryptedKey"], case["envelope"]["ciphertext"], aad
            )
            ok = plaintext == case["expectedPlaintext"]
            detail = f"decrypted {plaintext!r}"
        except Exception as exc:  # noqa: BLE001 - report any failure verbatim
            ok, detail = False, f"decryption raised {exc!r}"
        report.check("encryptedEnvelope", case["id"] + "/decrypt", ok, detail)
        # 负向: AAD 被改动后 GCM 必须拒绝
        bad_aad = build_aad(parts["requestId"], parts["routeTemplate"] + "x", parts["timestamp"], parts["keyId"])
        try:
            open_envelope(priv, case["envelope"]["encryptedKey"], case["envelope"]["ciphertext"], bad_aad)
            aad_rejected = False
        except Exception:  # noqa: BLE001
            aad_rejected = True
        report.check(
            "encryptedEnvelope",
            case["id"] + "/aad-tamper-rejected",
            aad_rejected,
            "AES-GCM accepted a modified AAD",
        )
        report.check(
            "encryptedEnvelope",
            case["id"] + "/fingerprint",
            case["envelope"]["keyFingerprint"] == keys[case["decryptionKey"]]["fingerprint"],
            "envelope keyFingerprint does not identify the expected recipient key",
        )


def verify_webhooks(data: dict[str, Any], report: Report) -> None:
    keys = data["keys"]
    for case in data["vectors"]["webhook"]:
        headers = {k.lower(): v for k, v in case["headers"].items()}
        body = case["body"]
        digest_b64 = base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")
        report.check(
            "webhook",
            case["id"] + "/body-digest-base64",
            digest_b64 == case["bodyDigestBase64"],
            f"expected {case['bodyDigestBase64']}, got {digest_b64}",
        )
        canonical = "\n".join(
            [
                headers["x-slaunchx-delivery-id"],
                headers["x-slaunchx-event-type"],
                headers["x-slaunchx-timestamp"],
                digest_b64,
            ]
        )
        report.check(
            "webhook",
            case["id"] + "/canonical",
            canonical == case["signatureCanonicalString"],
            f"rebuilt canonical differs:\n    expected={case['signatureCanonicalString']!r}\n    actual  ={canonical!r}",
        )
        report.check(
            "webhook",
            case["id"] + "/signature",
            rsa_verify(
                keys[case["signatureVerificationKey"]]["publicKeyPem"],
                canonical,
                headers["x-slaunchx-signature"],
            ),
            "SHA256withRSA verification failed against the platform authentication public key",
        )
        envelope = json.loads(body)
        report.check(
            "webhook",
            case["id"] + "/envelope-shape",
            envelope["envelopeVersion"] == 1
            and envelope["algorithm"] == "RSA-OAEP-AES-256-GCM"
            and set(envelope) == {
                "envelopeVersion",
                "algorithm",
                "keyFingerprint",
                "encryptedKey",
                "ciphertext",
                "aad",
            },
            f"unexpected envelope shape: {sorted(envelope)}",
        )
        parts = case["aadComponents"]
        aad = build_aad(parts["requestId"], parts["routeTemplate"], parts["timestamp"], parts["keyId"])
        report.check(
            "webhook",
            case["id"] + "/aad",
            base64.b64encode(aad).decode("ascii") == envelope["aad"],
            "rebuilt webhook AAD does not match the envelope's declared AAD",
        )
        report.check(
            "webhook",
            case["id"] + "/aad-uses-delivery-id",
            parts["requestId"] == headers["x-slaunchx-delivery-id"]
            and parts["routeTemplate"] == "webhook"
            and parts["timestamp"] == headers["x-slaunchx-timestamp"]
            and parts["keyId"] == headers["x-slaunchx-key-id"],
            "webhook AAD components are not the documented header projection",
        )
        try:
            plaintext = open_envelope(
                keys[case["decryptionKey"]]["privateKeyPem"],
                envelope["encryptedKey"],
                envelope["ciphertext"],
                aad,
            )
            ok = plaintext == case["expectedPlaintext"]
            detail = f"decrypted {plaintext!r}"
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"decryption raised {exc!r}"
        report.check("webhook", case["id"] + "/decrypt", ok, detail)
        if ok:
            payload = json.loads(plaintext)
            report.check(
                "webhook",
                case["id"] + "/payload-identity",
                payload["deliveryBizId"] == headers["x-slaunchx-delivery-id"]
                and payload["eventType"] == headers["x-slaunchx-event-type"]
                and payload["payloadSchemaVersion"] == 1,
                "decrypted payload identity does not match the transport headers",
            )


def main() -> int:
    default_vectors = Path(__file__).resolve().parents[1] / "test-vectors.json"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path, default=default_vectors)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    data = json.loads(args.vectors.read_text(encoding="utf-8"))
    report = Report(args.verbose)

    print(f"vectors: {args.vectors}")
    meta = data["meta"]
    print(f"protocol={meta['protocol']} generatedAt={meta['generatedAt']} sourceCommit={meta['sourceCommit']}")
    print(f"counts: {json.dumps(meta['counts'])}")
    print("-" * 72)

    for name, fn in (
        ("keys", verify_keys),
        ("canonicalQuery", verify_canonical_query),
        ("bodyHash", verify_body_hash),
        ("requestSignature", verify_request_signature),
        ("responseSignature", verify_response_signature),
        ("encryptedEnvelope", verify_envelopes),
        ("webhook", verify_webhooks),
    ):
        print(f"[{name}]")
        fn(data, report)

    print("-" * 72)
    print(f"assertions passed: {report.passed}")
    print(f"assertions failed: {len(report.failures)}")
    if report.failures:
        for failure in report.failures:
            print(f"  - {failure}")
        return 1
    print("ALL VECTORS VERIFIED INDEPENDENTLY (python3 + cryptography, no Java involved)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
