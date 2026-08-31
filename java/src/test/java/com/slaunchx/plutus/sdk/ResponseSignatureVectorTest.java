package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.slaunchx.plutus.sdk.crypto.Digests;
import com.slaunchx.plutus.sdk.exception.PlutusSignatureException;
import com.slaunchx.plutus.sdk.signing.RequestSigner;
import com.slaunchx.plutus.sdk.signing.ResponseSignatureContext;
import com.slaunchx.plutus.sdk.signing.ResponseVerifier;
import com.slaunchx.plutus.sdk.signing.SigningInput;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 向量组 responseSignature:3 例,规范串逐行比对并验签。 */
class ResponseSignatureVectorTest {

    static List<JsonNode> vectors() {
        return TestVectors.group("responseSignature");
    }

    @Test
    @DisplayName("向量条数与 meta.counts 一致")
    void countMatchesMeta() {
        assertEquals(TestVectors.declaredCount("responseSignature"), vectors().size());
        assertEquals(3, vectors().size());
    }

    static List<org.junit.jupiter.params.provider.Arguments> cases() {
        return vectors().stream()
                .map(v -> org.junit.jupiter.params.provider.Arguments.of(v.get("id").asText(), v))
                .toList();
    }

    private static ResponseSignatureContext contextOf(JsonNode vector) {
        return new ResponseSignatureContext(
                vector.get("requestCanonicalSha256").asText(),
                vector.get("apiVersion").asText(),
                vector.get("externalPath").asText(),
                TestVectors.text(vector, "operationId"),
                TestVectors.text(vector, "requestId"),
                vector.get("httpStatus").asInt(),
                TestVectors.text(vector, "contentType"),
                TestVectors.text(vector, "responseTimestamp"),
                vector.get("responseBodyHash").asText());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void matchesVector(String id, JsonNode vector) {
        byte[] body = TestVectors.bytes(vector, "responseBody");
        assertEquals(vector.get("responseBodyHash").asText(),
                Digests.sha256Hex(body == null ? new byte[0] : body), id + " 响应体摘要");

        ResponseSignatureContext context = contextOf(vector);
        List<String> lines = ResponseVerifier.canonicalStringLines(context);
        JsonNode expectedLines = vector.get("canonicalStringLines");
        assertEquals(10, lines.size(), id + " 响应规范串必须是 10 行");
        assertEquals(expectedLines.size(), lines.size(), id + " 规范串行数");
        for (int i = 0; i < lines.size(); i++) {
            assertEquals(expectedLines.get(i).asText(), lines.get(i), id + " 规范串第 " + (i + 1) + " 行");
        }
        assertEquals(vector.get("canonicalString").asText(),
                ResponseVerifier.canonicalString(context), id + " 规范串");
        assertEquals(ResponseVerifier.CANONICAL_PREFIX, lines.get(0), id + " 首行字面量");

        ResponseVerifier verifier = new ResponseVerifier(
                TestVectors.publicKey(vector.get("signingKey").asText()));
        assertTrue(verifier.verify(context, vector.get("signature").asText()), id + " 验签");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    @DisplayName("负向: Content-Type 归一化 / 绑定摘要取自响应 均导致验签失败")
    void tamperedContextFailsVerification(String id, JsonNode vector) {
        ResponseVerifier verifier = new ResponseVerifier(
                TestVectors.publicKey(vector.get("signingKey").asText()));
        String signature = vector.get("signature").asText();
        ResponseSignatureContext original = contextOf(vector);

        ResponseSignatureContext normalizedContentType = new ResponseSignatureContext(
                original.requestCanonicalSha256(), original.apiVersion(), original.externalPath(),
                original.operationId(), original.requestId(), original.httpStatus(),
                "application/json; charset=utf-8", original.responseTimestamp(),
                original.responseBodySha256Hex());
        assertFalse(verifier.verify(normalizedContentType, signature), id + " 归一化 Content-Type 后仍通过");

        ResponseSignatureContext wrongBinding = new ResponseSignatureContext(
                Digests.sha256Hex("other".getBytes(StandardCharsets.UTF_8)),
                original.apiVersion(), original.externalPath(), original.operationId(),
                original.requestId(), original.httpStatus(), original.contentType(),
                original.responseTimestamp(), original.responseBodySha256Hex());
        assertFalse(verifier.verify(wrongBinding, signature), id + " 绑定摘要被替换后仍通过");

        ResponseSignatureContext wrongStatus = new ResponseSignatureContext(
                original.requestCanonicalSha256(), original.apiVersion(), original.externalPath(),
                original.operationId(), original.requestId(), original.httpStatus() + 1,
                original.contentType(), original.responseTimestamp(), original.responseBodySha256Hex());
        assertThrows(PlutusSignatureException.class, () -> verifier.requireValid(wrongStatus, signature),
                id + " 状态码被替换后仍通过");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    @DisplayName("向量 body 的错误码 / 消息解析; 不在此断言成功与否")
    void apiResponseParsing(String id, JsonNode vector) {
        // 向量文件只为签名字节服务, 其 body 不是统一响应包络的样本;
        // 成功判定的覆盖见 UnifiedEnvelopeTest, 此处只断言错误码与消息的解析。
        byte[] body = TestVectors.bytes(vector, "responseBody");
        com.slaunchx.plutus.sdk.model.ApiResponse parsed = com.slaunchx.plutus.sdk.model.ApiResponse
                .parse(TestVectors.MAPPER, vector.get("httpStatus").asInt(), body);
        if (vector.get("httpStatus").asInt() < 300) {
            assertTrue(parsed.errorCode().isEmpty(), id + " 成功响应无网关错误码");
        } else {
            assertEquals(com.slaunchx.plutus.sdk.model.PublicErrorCode.API_SIGNATURE_INVALID,
                    parsed.errorCode().orElseThrow(), id + " 错误码");
            assertEquals("signature is invalid", parsed.message(), id + " 错误消息");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    @DisplayName("绑定摘要由本地请求规范串复算, 与关联的请求向量一致")
    void bindingDigestRecomputedLocally(String id, JsonNode vector) {
        String requestVectorId = vector.get("requestVectorId").asText();
        JsonNode requestVector = TestVectors.group("requestSignature").stream()
                .filter(v -> requestVectorId.equals(v.get("id").asText()))
                .findFirst().orElseThrow();
        JsonNode request = requestVector.get("request");
        SigningInput input = new SigningInput(
                request.get("method").asText(),
                request.get("externalPath").asText(),
                TestVectors.text(request, "queryString"),
                request.get("timestamp").asText(),
                request.get("nonce").asText(),
                request.get("apiVersion").asText(),
                TestVectors.text(request, "idempotencyKey"),
                TestVectors.bytes(request, "body"));
        String recomputed = new RequestSigner(TestVectors.privateKey("merchant_auth"))
                .sign(input).requestCanonicalSha256();
        assertEquals(vector.get("requestCanonicalSha256").asText(), recomputed, id + " 本地复算绑定摘要");
    }
}
