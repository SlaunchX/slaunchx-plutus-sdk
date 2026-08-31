package com.slaunchx.plutus.sdk.signing;

/**
 * 响应验签规范串的输入。
 *
 * <p>{@code requestCanonicalSha256} 必须由 SDK 本地计算并缓存,绝不能从响应头读取;
 * {@code contentType} 必须使用响应头原值,不做归一化——{@code application/json} 与
 * {@code application/json;charset=UTF-8} 是不同的字符串。
 *
 * @param requestCanonicalSha256 本次请求 8 行规范串的 SHA-256,64 位小写十六进制
 * @param apiVersion             本次请求的 {@code X-API-VERSION}
 * @param externalPath           本次请求的外部路径
 * @param operationId            响应头 {@code X-Operation-Id};无则 {@code null}
 * @param requestId              响应头 {@code X-Request-Id};无则 {@code null}
 * @param httpStatus             HTTP 状态码
 * @param contentType            响应头 {@code Content-Type} 原值;无则 {@code null}
 * @param responseTimestamp      响应头 {@code X-Response-Timestamp} 原值
 * @param responseBodySha256Hex  原始响应体字节的 SHA-256,64 位小写十六进制
 */
public record ResponseSignatureContext(String requestCanonicalSha256,
                                       String apiVersion,
                                       String externalPath,
                                       String operationId,
                                       String requestId,
                                       int httpStatus,
                                       String contentType,
                                       String responseTimestamp,
                                       String responseBodySha256Hex) {
}
