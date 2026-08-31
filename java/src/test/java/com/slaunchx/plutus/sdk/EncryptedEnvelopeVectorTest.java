package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.slaunchx.plutus.sdk.crypto.EncryptionAad;
import com.slaunchx.plutus.sdk.crypto.Envelope;
import com.slaunchx.plutus.sdk.crypto.EnvelopeCodec;
import com.slaunchx.plutus.sdk.crypto.PemKeys;
import com.slaunchx.plutus.sdk.exception.PlutusCryptoException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 向量组 encryptedEnvelope:3 例静态解密比对,外加加密方向 round-trip 自测。 */
class EncryptedEnvelopeVectorTest {

    private final EnvelopeCodec codec = new EnvelopeCodec();

    static List<JsonNode> vectors() {
        return TestVectors.group("encryptedEnvelope");
    }

    @Test
    @DisplayName("向量条数与 meta.counts 一致")
    void countMatchesMeta() {
        assertEquals(TestVectors.declaredCount("encryptedEnvelope"), vectors().size());
        assertEquals(3, vectors().size());
    }

    static List<org.junit.jupiter.params.provider.Arguments> cases() {
        return vectors().stream()
                .map(v -> org.junit.jupiter.params.provider.Arguments.of(v.get("id").asText(), v))
                .toList();
    }

    private static EncryptionAad aadOf(JsonNode vector) {
        JsonNode c = vector.get("aadComponents");
        return new EncryptionAad(
                TestVectors.text(c, "requestId"),
                TestVectors.text(c, "routeTemplate"),
                TestVectors.text(c, "timestamp"),
                TestVectors.text(c, "keyId"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void matchesVector(String id, JsonNode vector) {
        EncryptionAad aad = aadOf(vector);
        assertEquals(vector.get("aadString").asText(), aad.asString(), id + " AAD 字符串");
        assertEquals(vector.get("aadBase64").asText(), aad.base64(), id + " AAD Base64");

        Envelope envelope = Envelope.fromJson(vector.get("envelope")).requireApiShape();
        assertEquals(Envelope.ALGORITHM, envelope.algorithm(), id + " 算法标识");
        assertEquals(aad.base64(), envelope.aad(), id + " 信封 aad 回显与本地重建一致");
        assertEquals(envelope.ciphertext(), envelope.encryptedPayload(),
                id + " API 链信封 encryptedPayload 恒等于 ciphertext");
        assertNull(envelope.envelopeVersion(), id + " API 链信封不含 envelopeVersion");

        String keyName = vector.get("decryptionKey").asText();
        assertEquals(TestVectors.fingerprint(keyName), envelope.keyFingerprint(), id + " keyFingerprint");
        assertEquals(TestVectors.fingerprint(keyName), aad.keyId(), id + " AAD keyId 为接收方公钥指纹");

        String plaintext = codec.openToString(envelope, TestVectors.privateKey(keyName), aad);
        assertEquals(vector.get("expectedPlaintext").asText(), plaintext, id + " 解密明文");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    @DisplayName("负向: AAD 任一分量被篡改, 解密必失败")
    void tamperedAadFailsDecryption(String id, JsonNode vector) {
        Envelope envelope = Envelope.fromJson(vector.get("envelope"));
        var privateKey = TestVectors.privateKey(vector.get("decryptionKey").asText());
        EncryptionAad original = aadOf(vector);

        List<EncryptionAad> tampered = List.of(
                new EncryptionAad(original.requestId() + "x", original.routeTemplate(),
                        original.timestamp(), original.keyId()),
                new EncryptionAad(original.requestId(), original.routeTemplate() + "/x",
                        original.timestamp(), original.keyId()),
                new EncryptionAad(original.requestId(), original.routeTemplate(),
                        original.timestamp() + "1", original.keyId()),
                new EncryptionAad(original.requestId(), original.routeTemplate(),
                        original.timestamp(), original.keyId() + "0"));
        for (EncryptionAad bad : tampered) {
            assertThrows(PlutusCryptoException.class, () -> codec.open(envelope, privateKey, bad),
                    id + " 篡改 AAD 后仍解密成功: " + bad.asString());
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    @DisplayName("负向: 使用信封回显的 aad 但密文被篡改时 GCM 认证失败")
    void tamperedCiphertextFailsDecryption(String id, JsonNode vector) {
        Envelope original = Envelope.fromJson(vector.get("envelope"));
        byte[] blob = Base64.getDecoder().decode(original.ciphertext());
        blob[blob.length - 1] ^= 0x01;
        Envelope tampered = Envelope.apiEnvelope(original.keyFingerprint(), original.encryptedKey(),
                Base64.getEncoder().encodeToString(blob), original.aad());
        var privateKey = TestVectors.privateKey(vector.get("decryptionKey").asText());
        EncryptionAad aad = aadOf(vector);
        assertThrows(PlutusCryptoException.class, () -> codec.open(tampered, privateKey, aad),
                id + " 密文被篡改后仍解密成功");
    }

    @ParameterizedTest(name = "接收方 {0}")
    @ValueSource(strings = {"platform_enc", "merchant_enc"})
    @DisplayName("加密方向 round-trip: 封装后自解, 明文逐字节一致")
    void sealAndOpenRoundTrip(String keyName) {
        String plaintext = "{\"platformCardProductBizId\":\"pcp_example_001\",\"quantity\":2,\"note\":\"中文测试\"}";
        String fingerprint = PemKeys.fingerprint(TestVectors.publicKeyPem(keyName));
        assertEquals(TestVectors.fingerprint(keyName), fingerprint, "指纹复算");

        EncryptionAad aad = EncryptionAad.forEncryptedRequest(
                "req_roundtrip_0001", "/card-products/10010106/shared/cards/create",
                "1755600010000", fingerprint);
        Envelope envelope = codec.seal(plaintext, TestVectors.publicKey(keyName), fingerprint, aad);

        assertEquals(Envelope.ALGORITHM, envelope.algorithm());
        assertEquals(envelope.ciphertext(), envelope.encryptedPayload());
        assertEquals(aad.base64(), envelope.aad());
        assertNotNull(envelope.toMap().get("encryptedPayload"));
        int blobLength = Base64.getDecoder().decode(envelope.ciphertext()).length;
        assertEquals(EnvelopeCodec.IV_LENGTH + plaintext.getBytes(StandardCharsets.UTF_8).length
                + EnvelopeCodec.TAG_LENGTH_BITS / 8, blobLength, "IV(12) || 密文 || 标签(16) 布局");

        assertEquals(plaintext, codec.openToString(envelope, TestVectors.privateKey(keyName), aad));
        assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8),
                codec.open(envelope, TestVectors.privateKey(keyName), aad));
    }

    @Test
    @DisplayName("round-trip: 每次封装的密文都不同 (随机 IV 与一次性密钥)")
    void sealIsNonDeterministic() {
        String fingerprint = TestVectors.fingerprint("platform_enc");
        EncryptionAad aad = EncryptionAad.forEncryptedRequest("req_x", "/p", "1", fingerprint);
        Envelope a = codec.seal("{}", TestVectors.publicKey("platform_enc"), fingerprint, aad);
        Envelope b = codec.seal("{}", TestVectors.publicKey("platform_enc"), fingerprint, aad);
        assertEquals(false, a.ciphertext().equals(b.ciphertext()));
    }

    @Test
    @DisplayName("敏感响应 AAD 的 routeTemplate 是空串, 时间戳可从回显 aad 解析")
    void sensitiveResponseAadShape() {
        JsonNode vector = vectors().stream()
                .filter(v -> "en-02-sensitive-response".equals(v.get("id").asText()))
                .findFirst().orElseThrow();
        Envelope envelope = Envelope.fromJson(vector.get("envelope"));
        EncryptionAad parsed = EncryptionAad.parseBase64(envelope.aad());
        assertEquals("", parsed.routeTemplate());
        assertEquals("1755600011000", parsed.timestamp());

        EncryptionAad rebuilt = EncryptionAad.forSensitiveResponse(
                parsed.requestId(), parsed.timestamp(), TestVectors.fingerprint("merchant_enc"));
        assertEquals(vector.get("aadString").asText(), rebuilt.asString());
        assertEquals(vector.get("expectedPlaintext").asText(),
                codec.openToString(envelope, TestVectors.privateKey("merchant_enc"), rebuilt));
    }

    @Test
    @DisplayName("敏感响应 requestId 可退化为空串, AAD 仍逐字节一致")
    void emptyRequestIdAad() {
        JsonNode vector = vectors().stream()
                .filter(v -> "en-03-sensitive-response-empty-request-id".equals(v.get("id").asText()))
                .findFirst().orElseThrow();
        EncryptionAad aad = EncryptionAad.forSensitiveResponse(
                "", "1755600012000", TestVectors.fingerprint("merchant_enc"));
        assertEquals(vector.get("aadString").asText(), aad.asString());
        assertEquals(vector.get("expectedPlaintext").asText(),
                codec.openToString(Envelope.fromJson(vector.get("envelope")),
                        TestVectors.privateKey("merchant_enc"), aad));
    }

    @Test
    @DisplayName("负向: 算法标识不符或字段缺失时拒绝")
    void invalidEnvelopeShapeRejected() {
        Envelope wrongAlgorithm = new Envelope(null, "AES-256-GCM", "SHA256:x", "k", "c", "a", "c");
        assertThrows(PlutusCryptoException.class, wrongAlgorithm::requireApiShape);
        Envelope missingCiphertext = new Envelope(null, Envelope.ALGORITHM, "SHA256:x", "k", null, "a", null);
        assertThrows(PlutusCryptoException.class, missingCiphertext::requireApiShape);
    }
}
