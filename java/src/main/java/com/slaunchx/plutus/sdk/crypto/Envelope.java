package com.slaunchx.plutus.sdk.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.slaunchx.plutus.sdk.exception.PlutusCryptoException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 混合加密信封。
 *
 * <p>API 链(加密请求 / 敏感响应)与 Webhook 使用同一算法但字段集不同:
 *
 * <ul>
 *   <li>API 链:{@code algorithm}、{@code keyFingerprint}、{@code encryptedKey}、
 *       {@code ciphertext}、{@code aad}、{@code encryptedPayload}(历史兼容字段,值恒等于
 *       {@code ciphertext});无 {@code envelopeVersion}。</li>
 *   <li>Webhook:{@code envelopeVersion}(恒为 1)、{@code algorithm}、{@code keyFingerprint}、
 *       {@code encryptedKey}、{@code ciphertext}、{@code aad};<b>无</b> {@code encryptedPayload}。</li>
 * </ul>
 *
 * <p>解密时应读 {@code ciphertext}。
 *
 * @param envelopeVersion  信封版本;API 链信封为 {@code null}
 * @param algorithm        算法标识,恒为 {@code RSA-OAEP-AES-256-GCM}
 * @param keyFingerprint   接收方公钥指纹
 * @param encryptedKey     Base64 的 RSA-OAEP 包装 AES 密钥
 * @param ciphertext       Base64 的 {@code IV(12) || 密文 || 标签(16)}
 * @param aad              Base64 的 AAD 回显
 * @param encryptedPayload 历史兼容字段;Webhook 信封为 {@code null}
 */
public record Envelope(Integer envelopeVersion,
                       String algorithm,
                       String keyFingerprint,
                       String encryptedKey,
                       String ciphertext,
                       String aad,
                       String encryptedPayload) {

    /** 协议规定的算法标识。 */
    public static final String ALGORITHM = "RSA-OAEP-AES-256-GCM";

    /** Webhook 信封的版本号。 */
    public static final int WEBHOOK_ENVELOPE_VERSION = 1;

    /**
     * 构造 API 链信封({@code encryptedPayload} 与 {@code ciphertext} 同值)。
     *
     * @param keyFingerprint 接收方公钥指纹
     * @param encryptedKey   Base64 包装密钥
     * @param ciphertext     Base64 密文块
     * @param aad            Base64 AAD
     * @return 信封
     */
    public static Envelope apiEnvelope(String keyFingerprint, String encryptedKey,
                                       String ciphertext, String aad) {
        return new Envelope(null, ALGORITHM, keyFingerprint, encryptedKey, ciphertext, aad, ciphertext);
    }

    /**
     * 从 JSON 节点读取信封,字段缺失时为 {@code null},形状校验由
     * {@link #requireApiShape()} / {@link #requireWebhookShape()} 负责。
     *
     * @param node JSON 对象节点
     * @return 信封
     * @throws PlutusCryptoException 节点不是 JSON 对象时抛出
     */
    public static Envelope fromJson(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new PlutusCryptoException("信封不是 JSON 对象");
        }
        Integer version = node.hasNonNull("envelopeVersion") ? node.get("envelopeVersion").asInt() : null;
        return new Envelope(version,
                text(node, "algorithm"),
                text(node, "keyFingerprint"),
                text(node, "encryptedKey"),
                text(node, "ciphertext"),
                text(node, "aad"),
                text(node, "encryptedPayload"));
    }

    private static String text(JsonNode node, String field) {
        return node.hasNonNull(field) ? node.get(field).asText() : null;
    }

    /**
     * 校验 API 链信封形状:算法正确,{@code encryptedKey} / {@code ciphertext} / {@code aad} 齐备。
     *
     * @return 自身,便于链式调用
     * @throws PlutusCryptoException 形状不合规时抛出
     */
    public Envelope requireApiShape() {
        requireCommon();
        return this;
    }

    /**
     * 校验 Webhook 信封形状:在通用校验之上,要求 {@code envelopeVersion} 恰为 1,
     * 且不存在 {@code encryptedPayload} 字段。
     *
     * @return 自身,便于链式调用
     * @throws PlutusCryptoException 形状不合规时抛出
     */
    public Envelope requireWebhookShape() {
        requireCommon();
        if (envelopeVersion == null || envelopeVersion != WEBHOOK_ENVELOPE_VERSION) {
            throw new PlutusCryptoException("Webhook 信封 envelopeVersion 必须恰为 1, 实际 " + envelopeVersion);
        }
        if (encryptedPayload != null) {
            throw new PlutusCryptoException("Webhook 信封不允许出现 encryptedPayload 字段");
        }
        return this;
    }

    private void requireCommon() {
        if (!ALGORITHM.equals(algorithm)) {
            throw new PlutusCryptoException("信封 algorithm 必须为 " + ALGORITHM + ", 实际 " + algorithm);
        }
        requireNonBlank(encryptedKey, "encryptedKey");
        requireNonBlank(ciphertext, "ciphertext");
        requireNonBlank(aad, "aad");
    }

    private static void requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new PlutusCryptoException("信封缺少字段 " + field);
        }
    }

    /**
     * @return 可直接序列化为 HTTP body 的有序字段映射;{@code null} 字段被省略
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        if (envelopeVersion != null) {
            map.put("envelopeVersion", envelopeVersion);
        }
        map.put("algorithm", algorithm);
        map.put("keyFingerprint", keyFingerprint);
        map.put("encryptedKey", encryptedKey);
        map.put("ciphertext", ciphertext);
        map.put("aad", aad);
        if (encryptedPayload != null) {
            map.put("encryptedPayload", encryptedPayload);
        }
        return map;
    }
}
