package com.slaunchx.plutus.sdk;

import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * {@code X-Nonce} 生成器。
 *
 * <p>协议约束:必须匹配 {@code ^[A-Za-z0-9._~-]{16,128}$},即只允许 RFC 3986 unreserved
 * 字符。UUID 带连字符是合法的;标准 Base64 输出<b>不合法</b>(含 {@code +} {@code /} {@code =}),
 * 应改用 Base64URL 去填充或十六进制。
 *
 * <p>每个 API Key 的 nonce 空间内一次性,重复使用会被判定为重放。
 */
@FunctionalInterface
public interface NonceGenerator {

    /** 协议规定的 nonce 字符集与长度约束。 */
    Pattern PATTERN = Pattern.compile("^[A-Za-z0-9._~-]{16,128}$");

    /**
     * @return 一个新的、满足 {@link #PATTERN} 的 nonce
     */
    String generate();

    /**
     * @param nonce 待校验的 nonce
     * @return 是否满足协议约束
     */
    static boolean isValid(String nonce) {
        return nonce != null && PATTERN.matcher(nonce).matches();
    }

    /**
     * 默认实现:32 字符小写十六进制(128 位熵),满足字符集与长度约束。
     *
     * @return 生成器实例
     */
    static NonceGenerator secureRandomHex() {
        SecureRandom random = new SecureRandom();
        char[] hex = "0123456789abcdef".toCharArray();
        return () -> {
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);
            char[] out = new char[32];
            for (int i = 0; i < bytes.length; i++) {
                int v = bytes[i] & 0xFF;
                out[i * 2] = hex[v >>> 4];
                out[i * 2 + 1] = hex[v & 0x0F];
            }
            return new String(out);
        };
    }
}
