package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.slaunchx.plutus.sdk.crypto.Digests;
import com.slaunchx.plutus.sdk.crypto.EncryptionAad;
import com.slaunchx.plutus.sdk.crypto.Envelope;
import com.slaunchx.plutus.sdk.crypto.EnvelopeCodec;
import com.slaunchx.plutus.sdk.crypto.RsaSignatures;
import com.slaunchx.plutus.sdk.exception.PlutusWebhookException;
import com.slaunchx.plutus.sdk.webhook.WebhookHandler;
import com.slaunchx.plutus.sdk.webhook.WebhookHeaders;
import com.slaunchx.plutus.sdk.webhook.WebhookNotification;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 向量组 webhook:2 例,验签 + 信封形状 + AAD 重建 + 解密比对。 */
class WebhookVectorTest {
    @Test void localRecipientIsMandatory() {
        for (String id : new String[]{null, "", " ", "\t\n"}) {
            assertThrows(com.slaunchx.plutus.sdk.exception.PlutusConfigurationException.class,
                () -> WebhookHandler.builder().platformAuthPublicKeyPem(TestVectors.publicKeyPem("platform_auth"))
                    .merchantEncPrivateKeyPem(TestVectors.privateKeyPem("merchant_enc"))
                    .expectedApiKeyBizId(id).build());
        }
    }

    @Test void sharedEncryptionKeyDoesNotAllowOtherRecipient() {
        var vector = vectors().get(0);
        var headers = headersOf(vector);
        byte[] body = vector.get("body").asText().getBytes(StandardCharsets.UTF_8);
        assertEquals(vector.get("expectedPlaintext").asText(), HANDLER.handle(headers, body).plaintext());
        var other = WebhookHandler.builder().platformAuthPublicKeyPem(TestVectors.publicKeyPem("platform_auth"))
            .merchantEncPrivateKeyPem(TestVectors.privateKeyPem("merchant_enc"))
            .expectedApiKeyBizId("apk_other_recipient").build();
        assertEquals(true, other.verifySignature(headers, body));
        assertEquals("Webhook 接收方 API Key 不匹配", assertThrows(PlutusWebhookException.class, () -> other.handle(headers, body)).getMessage());
        var badSignature = new LinkedHashMap<>(headers);
        badSignature.put(WebhookHeaders.SIGNATURE, "invalid");
        assertEquals(true, assertThrows(PlutusWebhookException.class, () -> other.handle(badSignature, body)).getMessage().contains("验签失败"));
        var changedHeader = new LinkedHashMap<>(headers);
        changedHeader.put(WebhookHeaders.KEY_ID,"apk_other_recipient");
        assertThrows(PlutusWebhookException.class, () -> other.handle(changedHeader,body));
    }


    private static final WebhookHandler HANDLER = WebhookHandler.builder().expectedApiKeyBizId("apk_vector_0001")
            .platformAuthPublicKeyPem(TestVectors.publicKeyPem("platform_auth"))
            .merchantEncPrivateKeyPem(TestVectors.privateKeyPem("merchant_enc"))
            .expectedApiKeyBizId("apk_vector_0001")
            .build();

    static List<JsonNode> vectors() {
        return TestVectors.group("webhook");
    }

    @Test
    @DisplayName("向量条数与 meta.counts 一致")
    void countMatchesMeta() {
        assertEquals(TestVectors.declaredCount("webhook"), vectors().size());
        assertEquals(2, vectors().size());
    }

    static List<org.junit.jupiter.params.provider.Arguments> cases() {
        return vectors().stream()
                .map(v -> org.junit.jupiter.params.provider.Arguments.of(v.get("id").asText(), v))
                .toList();
    }

    private static Map<String, String> headersOf(JsonNode vector) {
        Map<String, String> headers = new LinkedHashMap<>();
        vector.get("headers").properties().forEach(e -> headers.put(e.getKey(), e.getValue().asText()));
        return headers;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void matchesVector(String id, JsonNode vector) {
        Map<String, String> headers = headersOf(vector);
        byte[] body = vector.get("body").asText().getBytes(StandardCharsets.UTF_8);

        assertEquals(vector.get("bodyDigestBase64").asText(), Digests.sha256Base64(body),
                id + " body 摘要必须是 Base64");
        String canonical = WebhookHandler.canonicalString(
                headers.get(WebhookHeaders.DELIVERY_ID),
                headers.get(WebhookHeaders.EVENT_TYPE),
                headers.get(WebhookHeaders.TIMESTAMP),
                body);
        assertEquals(vector.get("signatureCanonicalString").asText(), canonical, id + " 签名规范串");
        assertEquals(4, canonical.split("\n", -1).length, id + " Webhook 规范串必须是 4 行");
        assertTrue(RsaSignatures.verify(TestVectors.publicKey(vector.get("signatureVerificationKey").asText()),
                canonical, headers.get(WebhookHeaders.SIGNATURE)), id + " 验签");
        assertTrue(HANDLER.verifySignature(headers, body), id + " 处理器验签");

        Envelope envelope = Envelope.fromJson(parseBody(vector)).requireWebhookShape();
        assertEquals(Envelope.WEBHOOK_ENVELOPE_VERSION, envelope.envelopeVersion(), id + " envelopeVersion");
        assertNull(envelope.encryptedPayload(), id + " Webhook 信封无 encryptedPayload");
        assertEquals(TestVectors.fingerprint("merchant_enc"), envelope.keyFingerprint(), id + " keyFingerprint");

        EncryptionAad aad = EncryptionAad.forWebhook(
                headers.get(WebhookHeaders.DELIVERY_ID),
                headers.get(WebhookHeaders.TIMESTAMP),
                headers.get(WebhookHeaders.KEY_ID));
        assertEquals(vector.get("aadString").asText(), aad.asString(), id + " AAD 字符串");
        assertEquals(vector.get("aadBase64").asText(), aad.base64(), id + " AAD Base64");
        assertEquals(EncryptionAad.WEBHOOK_ROUTE_TEMPLATE, aad.routeTemplate(), id + " AAD 第 2 分量");
        assertEquals(headers.get(WebhookHeaders.KEY_ID), aad.keyId(), id + " AAD keyId 是 API Key 业务 ID");
        assertEquals(aad.base64(), envelope.aad(), id + " 信封 aad 回显");

        String plaintext = new EnvelopeCodec().openToString(
                envelope, TestVectors.privateKey(vector.get("decryptionKey").asText()), aad);
        assertEquals(vector.get("expectedPlaintext").asText(), plaintext, id + " 解密明文");

        WebhookNotification notification = HANDLER.handle(headers, body);
        assertEquals(vector.get("expectedPlaintext").asText(), notification.plaintext(), id + " 处理器明文");
        assertEquals(headers.get(WebhookHeaders.DELIVERY_ID), notification.deliveryBizId(), id + " 投递 ID");
        assertEquals(headers.get(WebhookHeaders.EVENT_TYPE), notification.eventType(), id + " 事件类型");
        assertEquals(1, notification.payloadSchemaVersion(), id + " payloadSchemaVersion");
        assertEquals(notification.deliveryBizId(), notification.payload().get("deliveryBizId").asText(),
                id + " 明文与传输头交叉校验");
    }

    private static JsonNode parseBody(JsonNode vector) {
        try {
            return TestVectors.MAPPER.readTree(vector.get("body").asText());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    @DisplayName("负向: body 被改动一个字节, 验签必失败")
    void tamperedBodyFailsVerification(String id, JsonNode vector) {
        Map<String, String> headers = headersOf(vector);
        byte[] body = (vector.get("body").asText() + " ").getBytes(StandardCharsets.UTF_8);
        assertFalse(HANDLER.verifySignature(headers, body), id + " 追加空白后仍验签通过");
        assertThrows(PlutusWebhookException.class, () -> HANDLER.handle(headers, body), id);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    @DisplayName("负向: 传输头分量被替换, 验签必失败")
    void tamperedHeadersFailVerification(String id, JsonNode vector) {
        byte[] body = vector.get("body").asText().getBytes(StandardCharsets.UTF_8);
        for (String name : List.of(WebhookHeaders.DELIVERY_ID, WebhookHeaders.EVENT_TYPE,
                WebhookHeaders.TIMESTAMP)) {
            Map<String, String> headers = headersOf(vector);
            headers.put(name, headers.get(name) + "x");
            assertFalse(HANDLER.verifySignature(headers, body), id + " 篡改 " + name + " 后仍验签通过");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    @DisplayName("负向: AAD 分量被篡改则解密失败")
    void tamperedAadFailsDecryption(String id, JsonNode vector) {
        Map<String, String> headers = headersOf(vector);
        Envelope envelope = Envelope.fromJson(parseBody(vector));
        var privateKey = TestVectors.privateKey("merchant_enc");
        EnvelopeCodec codec = new EnvelopeCodec();

        EncryptionAad wrongRoute = new EncryptionAad(headers.get(WebhookHeaders.DELIVERY_ID),
                "", headers.get(WebhookHeaders.TIMESTAMP), headers.get(WebhookHeaders.KEY_ID));
        assertThrows(RuntimeException.class, () -> codec.open(envelope, privateKey, wrongRoute),
                id + " routeTemplate 用空串仍解密成功");

        EncryptionAad wrongKeyId = EncryptionAad.forWebhook(headers.get(WebhookHeaders.DELIVERY_ID),
                headers.get(WebhookHeaders.TIMESTAMP), TestVectors.fingerprint("merchant_enc"));
        assertThrows(RuntimeException.class, () -> codec.open(envelope, privateKey, wrongKeyId),
                id + " keyId 用指纹仍解密成功");
    }

    @Test
    @DisplayName("负向: 缺少必需传输头 / API Key 不匹配")
    void missingHeadersRejected() {
        JsonNode vector = vectors().get(0);
        byte[] body = vector.get("body").asText().getBytes(StandardCharsets.UTF_8);

        Map<String, String> missing = headersOf(vector);
        missing.remove(WebhookHeaders.SIGNATURE);
        assertThrows(PlutusWebhookException.class, () -> HANDLER.handle(missing, body));

        Map<String, String> wrongKey = headersOf(vector);
        wrongKey.put(WebhookHeaders.KEY_ID, "apk_other_0002");
        assertThrows(PlutusWebhookException.class, () -> HANDLER.handle(wrongKey, body));
    }

    @Test
    @DisplayName("传输头名大小写不敏感")
    void headerLookupIsCaseInsensitive() {
        JsonNode vector = vectors().get(0);
        Map<String, String> headers = new LinkedHashMap<>();
        headersOf(vector).forEach((k, v) -> headers.put(k.toLowerCase(java.util.Locale.ROOT), v));
        assertTrue(HANDLER.verifySignature(headers, vector.get("body").asText()
                .getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    @DisplayName("时间戳容差默认关闭, 显式配置后过期投递被拒")
    void timestampToleranceIsOptional() {
        JsonNode vector = vectors().get(0);
        byte[] body = vector.get("body").asText().getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = headersOf(vector);

        WebhookHandler strict = WebhookHandler.builder().expectedApiKeyBizId("apk_vector_0001")
                .platformAuthPublicKeyPem(TestVectors.publicKeyPem("platform_auth"))
                .merchantEncPrivateKeyPem(TestVectors.privateKeyPem("merchant_enc"))
                .timestampTolerance(Duration.ofSeconds(60))
                .build();
        assertThrows(PlutusWebhookException.class, () -> strict.handle(headers, body));

        // 默认处理器不校验时间戳, 同一份投递可正常处理。
        assertEquals(vector.get("expectedPlaintext").asText(), HANDLER.handle(headers, body).plaintext());
    }

    @Test
    @DisplayName("信封形状: Webhook 信封出现 encryptedPayload 或版本不为 1 时拒绝")
    void webhookEnvelopeShapeEnforced() {
        Envelope withPayload = new Envelope(1, Envelope.ALGORITHM, "SHA256:x", "k", "c", "YQ==", "c");
        assertThrows(RuntimeException.class, withPayload::requireWebhookShape);
        Envelope wrongVersion = new Envelope(2, Envelope.ALGORITHM, "SHA256:x", "k", "c", "YQ==", null);
        assertThrows(RuntimeException.class, wrongVersion::requireWebhookShape);
        Envelope noVersion = new Envelope(null, Envelope.ALGORITHM, "SHA256:x", "k", "c", "YQ==", null);
        assertThrows(RuntimeException.class, noVersion::requireWebhookShape);
    }
}
