package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.slaunchx.plutus.sdk.crypto.Digests;
import com.slaunchx.plutus.sdk.crypto.RsaSignatures;
import com.slaunchx.plutus.sdk.signing.CanonicalQuery;
import com.slaunchx.plutus.sdk.signing.RequestSigner;
import com.slaunchx.plutus.sdk.signing.SignedRequest;
import com.slaunchx.plutus.sdk.signing.SigningInput;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 向量组 requestSignature:7 例,逐行比对规范串并复算签名。 */
class RequestSignatureVectorTest {

    static List<JsonNode> vectors() {
        return TestVectors.group("requestSignature");
    }

    @Test
    @DisplayName("向量条数与 meta.counts 一致")
    void countMatchesMeta() {
        assertEquals(TestVectors.declaredCount("requestSignature"), vectors().size());
        assertEquals(7, vectors().size());
    }

    static List<org.junit.jupiter.params.provider.Arguments> cases() {
        return vectors().stream()
                .map(v -> org.junit.jupiter.params.provider.Arguments.of(v.get("id").asText(), v))
                .toList();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void matchesVector(String id, JsonNode vector) {
        JsonNode request = vector.get("request");
        SigningInput input = new SigningInput(
                request.get("method").asText(),
                request.get("externalPath").asText(),
                TestVectors.text(request, "queryString"),
                request.get("timestamp").asText(),
                request.get("nonce").asText(),
                request.get("apiVersion").asText(),
                TestVectors.text(request, "idempotencyKey"),
                TestVectors.bytes(request, "body"));

        assertEquals(vector.get("canonicalQuery").asText(),
                CanonicalQuery.canonicalize(TestVectors.text(request, "queryString")), id + " canonicalQuery");
        assertEquals(vector.get("bodyHash").asText(),
                Digests.bodySha256Hex(input.method(), input.body()), id + " bodyHash");
        assertEquals(vector.path("forcedEmptyBody").asBoolean(false),
                Digests.forcesEmptyBody(input.method()), id + " forcedEmptyBody");

        List<String> lines = RequestSigner.canonicalStringLines(input, vector.get("bodyHash").asText());
        JsonNode expectedLines = vector.get("canonicalStringLines");
        assertEquals(expectedLines.size(), lines.size(), id + " 规范串行数");
        assertEquals(8, lines.size(), id + " 请求规范串必须是 8 行");
        for (int i = 0; i < lines.size(); i++) {
            assertEquals(expectedLines.get(i).asText(), lines.get(i), id + " 规范串第 " + (i + 1) + " 行");
        }

        RequestSigner signer = new RequestSigner(TestVectors.privateKey(vector.get("signingKey").asText()));
        SignedRequest signed = signer.sign(input);

        assertEquals(vector.get("canonicalString").asText(), signed.canonicalString(), id + " 规范串");
        assertEquals(vector.get("requestCanonicalSha256").asText(),
                signed.requestCanonicalSha256(), id + " 绑定摘要");
        assertEquals(vector.get("signature").asText(), signed.signatureBase64(),
                id + " 签名 (PKCS#1 v1.5 确定性)");
        assertTrue(RsaSignatures.verify(TestVectors.publicKey(vector.get("signingKey").asText()),
                signed.canonicalString(), vector.get("signature").asText()), id + " 验签");

        JsonNode headers = vector.get("headers");
        assertEquals(headers.get(PlutusHeaders.TIMESTAMP).asText(), input.timestamp(), id + " 头 X-Timestamp");
        assertEquals(headers.get(PlutusHeaders.NONCE).asText(), input.nonce(), id + " 头 X-Nonce");
        assertEquals(headers.get(PlutusHeaders.API_VERSION).asText(), input.apiVersion(), id + " 头 X-API-VERSION");
        assertEquals(RsaSignatures.ALGORITHM_HEADER_VALUE,
                headers.get(PlutusHeaders.SIGNATURE_ALGORITHM).asText(), id + " 头 X-Signature-Algorithm");
        assertEquals(headers.get(PlutusHeaders.SIGNATURE).asText(), signed.signatureBase64(), id + " 头 X-Signature");
        assertTrue(NonceGenerator.isValid(input.nonce()), id + " nonce 满足字符集约束");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    @DisplayName("负向: 篡改规范串任意一行, 验签必失败")
    void tamperedCanonicalFailsVerification(String id, JsonNode vector) {
        String canonical = vector.get("canonicalString").asText();
        String signature = vector.get("signature").asText();
        var publicKey = TestVectors.publicKey(vector.get("signingKey").asText());

        String[] lines = canonical.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String[] tampered = lines.clone();
            tampered[i] = tampered[i] + "x";
            assertFalse(RsaSignatures.verify(publicKey, String.join("\n", tampered), signature),
                    id + " 篡改第 " + (i + 1) + " 行后仍验签通过");
        }
        assertFalse(RsaSignatures.verify(publicKey, canonical + "\n", signature), id + " 追加尾换行后仍验签通过");
    }

    @Test
    @DisplayName("负向: 幂等键的发送与否是二元的, 会改变签名")
    void idempotencyKeyChangesSignature() {
        JsonNode vector = vectors().stream()
                .filter(v -> "rq-04-post-body-idempotency".equals(v.get("id").asText()))
                .findFirst().orElseThrow();
        JsonNode request = vector.get("request");
        RequestSigner signer = new RequestSigner(TestVectors.privateKey("merchant_auth"));
        SigningInput withoutKey = new SigningInput(
                request.get("method").asText(),
                request.get("externalPath").asText(),
                TestVectors.text(request, "queryString"),
                request.get("timestamp").asText(),
                request.get("nonce").asText(),
                request.get("apiVersion").asText(),
                null,
                TestVectors.bytes(request, "body"));
        assertFalse(vector.get("signature").asText().equals(signer.sign(withoutKey).signatureBase64()));
    }
}
