package com.slaunchx.plutus.sdk.signing;

import com.slaunchx.plutus.sdk.exception.PlutusSignatureException;

/**
 * 请求签名的输入。
 *
 * <p>{@code body} 必须是<b>实际发送到线上的那一份字节</b>:先序列化一次拿到字节数组,
 * 摘要与发送都用同一个数组。加密端点的 {@code body} 是信封 JSON 的字节,不是明文的字节。
 *
 * @param method         HTTP 方法,大写
 * @param externalPath   外部路径,以 {@code /} 开头,不含 query 与 {@code /api/v1} 前缀
 * @param rawQuery       原始 query 串,不含前导 {@code ?};允许为 {@code null}
 * @param timestamp      {@code X-Timestamp} 的原值,Unix 毫秒十进制字符串
 * @param nonce          {@code X-Nonce} 的原值
 * @param apiVersion     {@code X-API-VERSION} 的原值,不可为空
 * @param idempotencyKey {@code X-Idempotency-Key} 的原值;不发送该头时为 {@code null}
 * @param body           实际发送的 body 字节;允许为 {@code null}
 */
public record SigningInput(String method,
                           String externalPath,
                           String rawQuery,
                           String timestamp,
                           String nonce,
                           String apiVersion,
                           String idempotencyKey,
                           byte[] body) {

    /**
     * 校验必填项。
     */
    public SigningInput {
        requireText(method, "method");
        requireText(externalPath, "externalPath");
        requireText(timestamp, "timestamp");
        requireText(nonce, "nonce");
        requireText(apiVersion, "apiVersion");
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new PlutusSignatureException("请求签名缺少必填项: " + field);
        }
    }
}
