package com.slaunchx.plutus.sdk.crypto;

import com.slaunchx.plutus.sdk.exception.PlutusSignatureException;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * RSASSA-PKCS#1 v1.5 + SHA-256 签名与验签。
 *
 * <p>JCA 算法名 {@code SHA256withRSA}。必须是 PKCS#1 v1.5,不是 PSS;
 * PSS 签名无法通过平台验签。PKCS#1 v1.5 是确定性的,同一规范串加同一私钥恒产生同一签名。
 */
public final class RsaSignatures {

    /** 协议规定的签名算法字面量,用于 {@code X-Signature-Algorithm}。 */
    public static final String ALGORITHM_HEADER_VALUE = "RSA-SHA256";

    private static final String JCA_ALGORITHM = "SHA256withRSA";

    private RsaSignatures() {
    }

    /**
     * 对规范串签名。
     *
     * @param privateKey     签名私钥
     * @param canonicalString 规范串,按 UTF-8 编码后参与签名
     * @return 标准 Base64 签名(带填充,无换行)
     * @throws PlutusSignatureException 签名失败时抛出
     */
    public static String sign(RSAPrivateKey privateKey, String canonicalString) {
        try {
            Signature signature = Signature.getInstance(JCA_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(canonicalString.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new PlutusSignatureException("请求签名失败", e);
        }
    }

    /**
     * 验证规范串签名。
     *
     * @param publicKey       验签公钥
     * @param canonicalString 本地重建的规范串
     * @param signatureBase64 Base64 签名值
     * @return 验签通过返回 {@code true};签名值格式非法或验签不通过返回 {@code false}
     */
    public static boolean verify(RSAPublicKey publicKey, String canonicalString, String signatureBase64) {
        if (signatureBase64 == null || signatureBase64.isEmpty()) {
            return false;
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException e) {
            return false;
        }
        try {
            Signature signature = Signature.getInstance(JCA_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(canonicalString.getBytes(StandardCharsets.UTF_8));
            return signature.verify(decoded);
        } catch (Exception e) {
            return false;
        }
    }
}
