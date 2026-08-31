package com.slaunchx.plutus.sdk;

import com.slaunchx.plutus.sdk.crypto.PemKeys;
import com.slaunchx.plutus.sdk.exception.PlutusConfigurationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 密钥体系:PEM 解析、SPKI 约束、指纹复算。 */
class KeyMaterialTest {

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"merchant_auth", "platform_auth", "merchant_enc", "platform_enc"})
    void keyPairAndFingerprint(String name) {
        var publicKey = TestVectors.publicKey(name);
        var privateKey = TestVectors.privateKey(name);

        assertEquals(2048, publicKey.getModulus().bitLength(), name + " 模数位长");
        assertEquals(BigInteger.valueOf(65537), publicKey.getPublicExponent(), name + " 公开指数");
        assertEquals(publicKey.getModulus(), privateKey.getModulus(), name + " 公私钥配对");
        assertEquals(TestVectors.fingerprint(name), PemKeys.fingerprint(publicKey), name + " 指纹");
        assertEquals(TestVectors.fingerprint(name),
                PemKeys.fingerprint(PemKeys.derivePublicKey(privateKey)), name + " 从私钥推导的指纹");
        assertTrue(TestVectors.fingerprint(name).startsWith("SHA256:"), name + " 指纹前缀");
        assertEquals(71, TestVectors.fingerprint(name).length(), name + " 指纹长度 = SHA256: + 64 位 hex");
        assertTrue(TestVectors.fingerprint(name).substring(7).matches("[0-9a-f]{64}"),
                name + " 指纹必须是小写十六进制, 不是 Base64");
    }

    @Test
    @DisplayName("负向: PKCS#1 公钥标记与损坏的 PEM 被拒绝")
    void invalidPemRejected() {
        assertThrows(PlutusConfigurationException.class,
                () -> PemKeys.parsePublicKey("-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----"));
        assertThrows(PlutusConfigurationException.class, () -> PemKeys.parsePublicKey(""));
        assertThrows(PlutusConfigurationException.class,
                () -> PemKeys.parsePrivateKey(TestVectors.publicKeyPem("merchant_auth")));
        assertThrows(PlutusConfigurationException.class,
                () -> PemKeys.parsePublicKey(TestVectors.privateKeyPem("merchant_auth")));
    }

    @Test
    @DisplayName("PEM 允许 CRLF 换行与首尾空白")
    void pemWhitespaceTolerated() {
        String pem = "\n  " + TestVectors.publicKeyPem("platform_auth").replace("\n", "\r\n") + "  \n";
        assertEquals(TestVectors.fingerprint("platform_auth"), PemKeys.fingerprint(pem));
    }

    @Test
    @DisplayName("nonce 生成器满足协议字符集与长度约束")
    void nonceGeneratorIsValid() {
        NonceGenerator generator = NonceGenerator.secureRandomHex();
        for (int i = 0; i < 64; i++) {
            assertTrue(NonceGenerator.isValid(generator.generate()));
        }
        assertTrue(NonceGenerator.isValid(java.util.UUID.randomUUID().toString()));
        assertEquals(false, NonceGenerator.isValid("short"));
        assertEquals(false, NonceGenerator.isValid("YWJjZGVmZ2hpamtsbW5vcA=="));
    }
}
