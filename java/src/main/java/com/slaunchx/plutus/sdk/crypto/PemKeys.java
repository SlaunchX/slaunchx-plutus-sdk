package com.slaunchx.plutus.sdk.crypto;

import com.slaunchx.plutus.sdk.exception.PlutusConfigurationException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * RSA 密钥 PEM 解析与指纹计算。
 *
 * <p>公钥必须是 PEM 编码的 SPKI({@code -----BEGIN PUBLIC KEY-----}),不接受 PKCS#1
 * ({@code BEGIN RSA PUBLIC KEY});私钥必须是 PKCS#8({@code -----BEGIN PRIVATE KEY-----})。
 */
public final class PemKeys {

    private static final String PUBLIC_BEGIN = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_END = "-----END PUBLIC KEY-----";
    private static final String PRIVATE_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_END = "-----END PRIVATE KEY-----";

    private static final int MIN_MODULUS_BITS = 2048;
    private static final int MAX_MODULUS_BITS = 4096;
    private static final BigInteger REQUIRED_EXPONENT = BigInteger.valueOf(65537L);

    private PemKeys() {
    }

    /**
     * 解析 SPKI 公钥并按 SPEC 2 节校验。
     *
     * <p>校验项:PEM 标记、Base64 正文字符集、模数位长 2048–4096、公开指数恰为 65537、
     * 重新编码的 DER 与原 DER 逐字节相等(拒绝非规范 DER)。
     *
     * @param pem PEM 文本
     * @return RSA 公钥
     * @throws PlutusConfigurationException 格式或参数不合规时抛出
     */
    public static RSAPublicKey parsePublicKey(String pem) {
        byte[] der = decodePem(pem, PUBLIC_BEGIN, PUBLIC_END, "SPKI 公钥");
        RSAPublicKey key;
        try {
            key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new PlutusConfigurationException("SPKI 公钥解析失败", e);
        }
        int bits = key.getModulus().bitLength();
        if (bits < MIN_MODULUS_BITS || bits > MAX_MODULUS_BITS) {
            throw new PlutusConfigurationException(
                    "RSA 公钥模数位长必须在 2048..4096 之间, 实际 " + bits);
        }
        if (!REQUIRED_EXPONENT.equals(key.getPublicExponent())) {
            throw new PlutusConfigurationException("RSA 公开指数必须恰为 65537");
        }
        if (!Arrays.equals(der, key.getEncoded())) {
            throw new PlutusConfigurationException("公钥 DER 编码非规范: 重新编码后与原字节不相等");
        }
        return key;
    }

    /**
     * 解析 PKCS#8 私钥。
     *
     * @param pem PEM 文本
     * @return RSA 私钥
     * @throws PlutusConfigurationException 格式不合规时抛出
     */
    public static RSAPrivateKey parsePrivateKey(String pem) {
        byte[] der = decodePem(pem, PRIVATE_BEGIN, PRIVATE_END, "PKCS#8 私钥");
        try {
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new PlutusConfigurationException("PKCS#8 私钥解析失败", e);
        }
    }

    /**
     * 从 RSA 私钥推导对应公钥。
     *
     * @param privateKey CRT 形式的 RSA 私钥(标准 PKCS#8 RSA 私钥均为此形式)
     * @return 对应公钥
     * @throws PlutusConfigurationException 私钥不含公开指数时抛出
     */
    public static RSAPublicKey derivePublicKey(RSAPrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateCrtKey crt)) {
            throw new PlutusConfigurationException("无法从该私钥推导公钥: 缺少 CRT 参数");
        }
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
        } catch (Exception e) {
            throw new PlutusConfigurationException("从私钥推导公钥失败", e);
        }
    }

    /**
     * 计算密钥指纹:{@code "SHA256:" + 小写hex(SHA256(SPKI DER))}。
     *
     * <p>用于 {@code X-Platform-Encryption-Key-Id}、{@code X-Platform-Signing-Key-Id}
     * 与信封的 {@code keyFingerprint} 字段。注意是小写十六进制,不是 Base64。
     *
     * @param publicKey RSA 公钥
     * @return 指纹字符串
     */
    public static String fingerprint(RSAPublicKey publicKey) {
        return "SHA256:" + Digests.toHex(Digests.sha256(publicKey.getEncoded()));
    }

    /**
     * 计算 PEM 公钥的指纹。
     *
     * @param publicKeyPem SPKI PEM 文本
     * @return 指纹字符串
     */
    public static String fingerprint(String publicKeyPem) {
        return fingerprint(parsePublicKey(publicKeyPem));
    }

    private static byte[] decodePem(String pem, String begin, String end, String what) {
        if (pem == null || pem.isBlank()) {
            throw new PlutusConfigurationException(what + " 为空");
        }
        String normalized = pem.replace("\r\n", "\n").replace('\r', '\n').trim();
        int beginIdx = normalized.indexOf(begin);
        int endIdx = normalized.indexOf(end);
        if (beginIdx < 0 || endIdx < 0 || endIdx < beginIdx) {
            throw new PlutusConfigurationException(what + " 缺少 " + begin + " / " + end + " 标记");
        }
        String body = normalized.substring(beginIdx + begin.length(), endIdx);
        StringBuilder base64 = new StringBuilder(body.length());
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (c == '\n' || c == ' ' || c == '\t') {
                continue;
            }
            boolean allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
            if (!allowed) {
                throw new PlutusConfigurationException(what + " 正文包含非法字符");
            }
            base64.append(c);
        }
        try {
            return Base64.getDecoder().decode(base64.toString().getBytes(StandardCharsets.US_ASCII));
        } catch (IllegalArgumentException e) {
            throw new PlutusConfigurationException(what + " 正文不是合法 Base64", e);
        }
    }
}
