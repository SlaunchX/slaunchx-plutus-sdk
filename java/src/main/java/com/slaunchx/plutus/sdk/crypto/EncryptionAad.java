package com.slaunchx.plutus.sdk.crypto;

import com.slaunchx.plutus.sdk.exception.PlutusCryptoException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 混合加密信封的附加认证数据(AAD)。
 *
 * <pre>
 * AAD = UTF8( requestId + "|" + routeTemplate + "|" + timestamp + "|" + keyId )
 * </pre>
 *
 * <p>四个分量中任何一个为 {@code null} 时按空串处理,分隔符仍然保留。
 * 三种用途的分量取值完全不同,不可混用:
 *
 * <table border="1">
 *   <caption>三处 AAD 的分量差异</caption>
 *   <tr><th>用途</th><th>requestId</th><th>routeTemplate</th><th>keyId</th></tr>
 *   <tr><td>加密请求</td><td>{@code X-Request-Id}</td><td>端点外部路径</td><td>平台加密公钥指纹</td></tr>
 *   <tr><td>敏感响应</td><td>请求关联 ID,可为空串</td><td>空串</td><td>商户加密公钥指纹</td></tr>
 *   <tr><td>Webhook</td><td>投递 ID</td><td>字面量 {@code webhook}</td><td>API Key 业务 ID</td></tr>
 * </table>
 *
 * @param requestId     第 1 分量
 * @param routeTemplate 第 2 分量
 * @param timestamp     第 3 分量,Unix 毫秒十进制字符串
 * @param keyId         第 4 分量
 */
public record EncryptionAad(String requestId, String routeTemplate, String timestamp, String keyId) {

    /** Webhook AAD 第 2 分量的固定字面量。 */
    public static final String WEBHOOK_ROUTE_TEMPLATE = "webhook";

    /**
     * 构造加密请求(商户 → 平台)的 AAD。
     *
     * @param requestId    {@code X-Request-Id} 的值,必填非空
     * @param externalPath 端点外部路径
     * @param timestamp    {@code X-Timestamp} 的值,与签名使用同一个值
     * @param platformEncFingerprint 平台加密公钥指纹
     * @return AAD
     */
    public static EncryptionAad forEncryptedRequest(String requestId, String externalPath,
                                                    String timestamp, String platformEncFingerprint) {
        return new EncryptionAad(requestId, externalPath, timestamp, platformEncFingerprint);
    }

    /**
     * 构造敏感响应(平台 → 商户)的 AAD。{@code routeTemplate} 固定为空串。
     *
     * @param requestId 请求关联 ID;无关联上下文时为空串
     * @param timestamp 平台生成的毫秒时间戳
     * @param merchantEncFingerprint 商户加密公钥指纹
     * @return AAD
     */
    public static EncryptionAad forSensitiveResponse(String requestId, String timestamp,
                                                     String merchantEncFingerprint) {
        return new EncryptionAad(requestId, "", timestamp, merchantEncFingerprint);
    }

    /**
     * 构造 Webhook 的 AAD。{@code routeTemplate} 固定为 {@code webhook},
     * {@code keyId} 是 API Key 业务 ID 而非指纹。
     *
     * @param deliveryBizId        {@code X-SlaunchX-Delivery-Id}
     * @param timestamp            {@code X-SlaunchX-Timestamp}
     * @param recipientApiKeyBizId {@code X-SlaunchX-Key-Id}
     * @return AAD
     */
    public static EncryptionAad forWebhook(String deliveryBizId, String timestamp,
                                           String recipientApiKeyBizId) {
        return new EncryptionAad(deliveryBizId, WEBHOOK_ROUTE_TEMPLATE, timestamp, recipientApiKeyBizId);
    }

    /**
     * 解析 AAD 字符串为四个分量。
     *
     * <p>仅用于从信封回显的 {@code aad} 中读取本地无法获得的分量(如敏感响应的时间戳);
     * 解析结果不可直接当作权威 AAD 使用,必须用本地上下文重建后再比对。
     *
     * @param aadString AAD 明文字符串
     * @return 解析结果
     * @throws PlutusCryptoException 分量数量不为 4 时抛出
     */
    public static EncryptionAad parse(String aadString) {
        if (aadString == null) {
            throw new PlutusCryptoException("AAD 字符串为空");
        }
        String[] parts = aadString.split("\\|", -1);
        if (parts.length != 4) {
            throw new PlutusCryptoException("AAD 字符串分量数量必须为 4, 实际 " + parts.length);
        }
        return new EncryptionAad(parts[0], parts[1], parts[2], parts[3]);
    }

    /**
     * 解析 Base64 编码的 AAD。
     *
     * @param aadBase64 信封 {@code aad} 字段
     * @return 解析结果
     * @throws PlutusCryptoException Base64 非法或分量数量不为 4 时抛出
     */
    public static EncryptionAad parseBase64(String aadBase64) {
        if (aadBase64 == null) {
            throw new PlutusCryptoException("信封缺少 aad 字段");
        }
        try {
            return parse(new String(Base64.getDecoder().decode(aadBase64), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new PlutusCryptoException("信封 aad 不是合法 Base64", e);
        }
    }

    /**
     * @return AAD 字符串形式,分量为 {@code null} 时按空串拼接
     */
    public String asString() {
        return nullToEmpty(requestId) + '|' + nullToEmpty(routeTemplate) + '|'
                + nullToEmpty(timestamp) + '|' + nullToEmpty(keyId);
    }

    /**
     * @return AAD 的 UTF-8 字节,直接用于 GCM
     */
    public byte[] bytes() {
        return asString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * @return AAD 的标准 Base64 编码,写入信封 {@code aad} 字段
     */
    public String base64() {
        return Base64.getEncoder().encodeToString(bytes());
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
