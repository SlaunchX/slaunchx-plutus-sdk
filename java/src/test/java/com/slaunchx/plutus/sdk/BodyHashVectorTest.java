package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.slaunchx.plutus.sdk.crypto.Digests;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 向量组 bodyHash:7 例,含 GET / DELETE 强制空体。 */
class BodyHashVectorTest {

    static List<JsonNode> vectors() {
        return TestVectors.group("bodyHash");
    }

    @Test
    @DisplayName("向量条数与 meta.counts 一致")
    void countMatchesMeta() {
        assertEquals(TestVectors.declaredCount("bodyHash"), vectors().size());
        assertEquals(7, vectors().size());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void matchesVector(String id, String method, String body, boolean forcedEmptyBody, String expected) {
        byte[] raw = body == null ? null : body.getBytes(StandardCharsets.UTF_8);
        assertEquals(expected, Digests.bodySha256Hex(method, raw), id);
        assertEquals(forcedEmptyBody, Digests.forcesEmptyBody(method), id + " forcedEmptyBody 标记");
    }

    static List<org.junit.jupiter.params.provider.Arguments> cases() {
        return vectors().stream()
                .map(v -> org.junit.jupiter.params.provider.Arguments.of(
                        v.get("id").asText(),
                        TestVectors.text(v, "method"),
                        TestVectors.text(v, "body"),
                        v.path("forcedEmptyBody").asBoolean(false),
                        v.get("expected").asText()))
                .toList();
    }

    @Test
    @DisplayName("HEAD 同样强制空体摘要")
    void headForcesEmptyBody() {
        assertTrue(Digests.forcesEmptyBody("head"));
        assertEquals(Digests.EMPTY_BODY_SHA256_HEX,
                Digests.bodySha256Hex("HEAD", "{\"ignored\":true}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    @DisplayName("POST 不强制空体, 空 body 摘要恰为空体摘要值")
    void postUsesActualBytes() {
        assertFalse(Digests.forcesEmptyBody("POST"));
        assertEquals(Digests.EMPTY_BODY_SHA256_HEX, Digests.bodySha256Hex("POST", new byte[0]));
    }

    @Test
    @DisplayName("Webhook body 摘要用 Base64, 与 API 链的小写 hex 不同")
    void webhookDigestIsBase64() {
        byte[] body = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
        String base64 = Digests.sha256Base64(body);
        String hex = Digests.sha256Hex(body);
        assertFalse(base64.equals(hex));
        assertEquals(hex, Digests.toHex(java.util.Base64.getDecoder().decode(base64)));
    }
}
