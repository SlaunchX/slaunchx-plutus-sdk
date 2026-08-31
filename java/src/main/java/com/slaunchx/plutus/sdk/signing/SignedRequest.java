package com.slaunchx.plutus.sdk.signing;

/**
 * 请求签名结果。
 *
 * <p>{@link #requestCanonicalSha256()} 必须由 SDK 本地缓存,用于响应验签规范串第 2 行;
 * 绝不能从响应头读取,否则请求-响应绑定失效。
 *
 * @param canonicalQuery         规范化后的 query;无 query 时为空串
 * @param bodySha256Hex          body 摘要,64 位小写十六进制
 * @param canonicalString        8 行请求规范串,LF 连接,无尾换行
 * @param requestCanonicalSha256 规范串自身的 SHA-256,64 位小写十六进制
 * @param signatureBase64        {@code X-Signature} 的值
 */
public record SignedRequest(String canonicalQuery,
                            String bodySha256Hex,
                            String canonicalString,
                            String requestCanonicalSha256,
                            String signatureBase64) {
}
