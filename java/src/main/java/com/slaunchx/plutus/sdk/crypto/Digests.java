package com.slaunchx.plutus.sdk.crypto;

import com.slaunchx.plutus.sdk.exception.PlutusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Locale;
import java.util.Set;

/**
 * SHA-256 摘要与编码工具。
 *
 * <p>协议中存在两套摘要编码,不可混用:API 链(请求 body、请求规范串绑定、响应 body)
 * 用 <b>小写 hex</b>;Webhook 签名规范串的 body 摘要用 <b>Base64</b>。
 */
public final class Digests {

    /** 空字节序列的 SHA-256 小写十六进制值。 */
    public static final String EMPTY_BODY_SHA256_HEX =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /** 强制使用空 body 摘要的 HTTP 方法(SPEC 4.3)。 */
    public static final Set<String> FORCED_EMPTY_BODY_METHODS = Set.of("GET", "HEAD", "DELETE");

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Digests() {
    }

    /**
     * @param input 待摘要字节,允许为 {@code null}(按空处理)
     * @return SHA-256 原始摘要,32 字节
     */
    public static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input == null ? new byte[0] : input);
        } catch (NoSuchAlgorithmException e) {
            throw new PlutusException("当前 JVM 不支持 SHA-256", e);
        }
    }

    /**
     * @param input 待摘要字节
     * @return 64 位小写十六进制摘要
     */
    public static String sha256Hex(byte[] input) {
        return toHex(sha256(input));
    }

    /**
     * @param input 待摘要 UTF-8 文本
     * @return 64 位小写十六进制摘要
     */
    public static String sha256Hex(String input) {
        return sha256Hex(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * @param input 待摘要字节
     * @return 标准 Base64 摘要(带填充,无换行)。仅用于 Webhook 签名规范串
     */
    public static String sha256Base64(byte[] input) {
        return Base64.getEncoder().encodeToString(sha256(input));
    }

    /**
     * 计算请求规范串第 8 行的 body 摘要。
     *
     * <p>{@code GET} / {@code HEAD} / {@code DELETE} 强制使用空 body 摘要,
     * 即使请求实际携带了 body;其余方法对实际发送的原始字节取摘要,不做任何规整。
     *
     * @param method HTTP 方法,允许为 {@code null}(此时按非强制方法处理)
     * @param body   实际发送的 body 字节,允许为 {@code null}
     * @return 64 位小写十六进制摘要
     */
    public static String bodySha256Hex(String method, byte[] body) {
        if (method != null && FORCED_EMPTY_BODY_METHODS.contains(method.toUpperCase(Locale.ROOT))) {
            return EMPTY_BODY_SHA256_HEX;
        }
        if (body == null || body.length == 0) {
            return EMPTY_BODY_SHA256_HEX;
        }
        return sha256Hex(body);
    }

    /**
     * @param method HTTP 方法
     * @return 该方法是否强制使用空 body 摘要
     */
    public static boolean forcesEmptyBody(String method) {
        return method != null && FORCED_EMPTY_BODY_METHODS.contains(method.toUpperCase(Locale.ROOT));
    }

    /**
     * @param bytes 原始字节
     * @return 小写十六进制字符串
     */
    public static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }
}
