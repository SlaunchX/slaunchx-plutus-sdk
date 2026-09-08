package com.slaunchx.plutus.sdk.webhook;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.slaunchx.plutus.sdk.PlutusConfig;
import com.slaunchx.plutus.sdk.crypto.Digests;
import com.slaunchx.plutus.sdk.crypto.EncryptionAad;
import com.slaunchx.plutus.sdk.crypto.Envelope;
import com.slaunchx.plutus.sdk.crypto.EnvelopeCodec;
import com.slaunchx.plutus.sdk.crypto.PemKeys;
import com.slaunchx.plutus.sdk.crypto.RsaSignatures;
import com.slaunchx.plutus.sdk.exception.PlutusConfigurationException;
import com.slaunchx.plutus.sdk.exception.PlutusWebhookException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Map;
import java.util.TreeMap;

/**
 * Webhook 投递处理器(SPEC 10 节):先验签,后解密。
 *
 * <p>签名规范串共 4 行,LF 连接,无尾换行:
 *
 * <pre>
 * deliveryBizId
 * eventType
 * timestamp
 * bodyDigest
 * </pre>
 *
 * <p>其中 {@code bodyDigest} 是 <b>Base64</b> 编码的 body SHA-256,与 API 链使用的小写
 * 十六进制不同;签名覆盖的是<b>加密信封 JSON 的原始字节</b>,不是解密后的明文。
 * 验签失败即丢弃,不得尝试解密。
 *
 * <p>Webhook 信封形状与 API 链不同:有 {@code envelopeVersion}(恒为 1),
 * 无 {@code encryptedPayload}。AAD 第 2 分量固定为字面量 {@code webhook},
 * 第 4 分量是 API Key 业务 ID 而非公钥指纹。
 */
public final class WebhookHandler {

    private final RSAPublicKey platformAuthPublicKey;
    private final RSAPrivateKey merchantEncPrivateKey;
    private final String merchantEncFingerprint;
    private final String expectedApiKeyBizId;
    private final Duration timestampTolerance;
    private final ObjectMapper objectMapper;
    private final EnvelopeCodec envelopeCodec = new EnvelopeCodec();

    private WebhookHandler(Builder b) {
        if (b.expectedApiKeyBizId == null || b.expectedApiKeyBizId.isBlank()) {
            throw new PlutusConfigurationException("expectedApiKeyBizId 必填");
        }
        if (b.platformAuthPublicKeyPem == null) {
            throw new PlutusConfigurationException("Webhook 验签必须配置 platformAuthPublicKeyPem");
        }
        if (b.merchantEncPrivateKeyPem == null) {
            throw new PlutusConfigurationException("Webhook 解密必须配置 merchantEncPrivateKeyPem");
        }
        this.platformAuthPublicKey = PemKeys.parsePublicKey(b.platformAuthPublicKeyPem);
        this.merchantEncPrivateKey = PemKeys.parsePrivateKey(b.merchantEncPrivateKeyPem);
        this.merchantEncFingerprint = PemKeys.fingerprint(
                b.merchantEncPublicKeyPem != null
                        ? PemKeys.parsePublicKey(b.merchantEncPublicKeyPem)
                        : PemKeys.derivePublicKey(this.merchantEncPrivateKey));
        this.expectedApiKeyBizId = b.expectedApiKeyBizId;
        this.timestampTolerance = b.timestampTolerance;
        this.objectMapper = b.objectMapper == null ? new ObjectMapper() : b.objectMapper;
    }

    /**
     * @return 新的构造器
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * 复用 {@link PlutusConfig} 中的平台认证公钥与商户加密私钥构造处理器。
     *
     * @param config SDK 配置
     * @return 处理器
     */
    public static WebhookHandler fromConfig(PlutusConfig config) {
        if (config.platformAuthPublicKey() == null || config.merchantEncPrivateKey() == null) {
            throw new PlutusConfigurationException(
                    "从 PlutusConfig 构造 WebhookHandler 需要 platformAuthPublicKeyPem 与 merchantEncPrivateKeyPem");
        }
        return new WebhookHandler(config);
    }

    private WebhookHandler(PlutusConfig config) {
        this.platformAuthPublicKey = config.platformAuthPublicKey();
        this.merchantEncPrivateKey = config.merchantEncPrivateKey();
        this.merchantEncFingerprint = config.merchantEncFingerprint();
        this.expectedApiKeyBizId = config.apiKey();
        this.timestampTolerance = null;
        this.objectMapper = config.objectMapper();
    }

    /**
     * 拼装 4 行 Webhook 签名规范串。
     *
     * @param deliveryBizId 投递 ID
     * @param eventType     事件类型
     * @param timestamp     Unix 毫秒时间戳
     * @param body          原始 HTTP body 字节
     * @return 规范串
     */
    public static String canonicalString(String deliveryBizId, String eventType,
                                         String timestamp, byte[] body) {
        return String.join("\n", deliveryBizId, eventType, timestamp, Digests.sha256Base64(body));
    }

    /**
     * 仅验签,不解密。
     *
     * @param headers 传输头,键大小写不敏感
     * @param body    原始 HTTP body 字节
     * @return 验签通过返回 {@code true}
     * @throws PlutusWebhookException 必需的传输头缺失时抛出
     */
    public boolean verifySignature(Map<String, String> headers, byte[] body) {
        Map<String, String> h = caseInsensitive(headers);
        String canonical = canonicalString(
                require(h, WebhookHeaders.DELIVERY_ID),
                require(h, WebhookHeaders.EVENT_TYPE),
                require(h, WebhookHeaders.TIMESTAMP),
                body);
        return RsaSignatures.verify(platformAuthPublicKey, canonical, require(h, WebhookHeaders.SIGNATURE));
    }

    /**
     * 完整处理一次投递:验签 → 校验信封形状 → 重建 AAD 并解密 → 明文交叉校验。
     *
     * @param headers 传输头,键大小写不敏感
     * @param body    原始 HTTP body 字节
     * @return 通知对象
     * @throws PlutusWebhookException 验签失败、信封不合规、解密失败或交叉校验不通过时抛出
     */
    public WebhookNotification handle(Map<String, String> headers, byte[] body) {
        Map<String, String> h = caseInsensitive(headers);
        String deliveryId = require(h, WebhookHeaders.DELIVERY_ID);
        String eventType = require(h, WebhookHeaders.EVENT_TYPE);
        String timestamp = require(h, WebhookHeaders.TIMESTAMP);
        String keyId = require(h, WebhookHeaders.KEY_ID);
        String signature = require(h, WebhookHeaders.SIGNATURE);

        checkTimestamp(timestamp);

        String canonical = canonicalString(deliveryId, eventType, timestamp, body);
        if (!RsaSignatures.verify(platformAuthPublicKey, canonical, signature)) {
            throw new PlutusWebhookException("Webhook 验签失败, 投递已丢弃: deliveryBizId=" + deliveryId);
        }

        if (!java.security.MessageDigest.isEqual(expectedApiKeyBizId.getBytes(StandardCharsets.UTF_8), keyId.getBytes(StandardCharsets.UTF_8))) {
            throw new PlutusWebhookException("Webhook 接收方 API Key 不匹配");
        }
        Envelope envelope;
        try {
            envelope = Envelope.fromJson(objectMapper.readTree(body)).requireWebhookShape();
        } catch (PlutusWebhookException e) {
            throw e;
        } catch (Exception e) {
            throw new PlutusWebhookException("Webhook 信封解析失败: " + e.getMessage(), e);
        }
        if (!merchantEncFingerprint.equals(envelope.keyFingerprint())) {
            throw new PlutusWebhookException(
                    "Webhook 信封 keyFingerprint 与商户加密公钥指纹不一致, 可能是密钥轮换未生效");
        }

        EncryptionAad aad = EncryptionAad.forWebhook(deliveryId, timestamp, expectedApiKeyBizId);
        String plaintext;
        try {
            plaintext = envelopeCodec.openToString(envelope, merchantEncPrivateKey, aad);
        } catch (Exception e) {
            throw new PlutusWebhookException("Webhook 载荷解密失败: " + e.getMessage(), e);
        }

        JsonNode payload;
        try {
            payload = objectMapper.readTree(plaintext);
        } catch (Exception e) {
            throw new PlutusWebhookException("Webhook 明文不是合法 JSON", e);
        }
        crossCheck(payload, deliveryId, eventType);
        return new WebhookNotification(deliveryId, eventType, timestamp, keyId, plaintext, payload);
    }

    /**
     * 便捷重载:body 以 UTF-8 字符串给出。
     *
     * <p>注意:如果框架对 body 做过任何重编码或重格式化,摘要将不再匹配;
     * 生产环境应始终传入原始字节。
     *
     * @param headers 传输头
     * @param body    body 文本
     * @return 通知对象
     */
    public WebhookNotification handle(Map<String, String> headers, String body) {
        return handle(headers, body.getBytes(StandardCharsets.UTF_8));
    }

    private void crossCheck(JsonNode payload, String deliveryId, String eventType) {
        if (!deliveryId.equals(payload.path("deliveryBizId").asText(null))) {
            throw new PlutusWebhookException("明文 deliveryBizId 与传输头不一致");
        }
        if (!eventType.equals(payload.path("eventType").asText(null))) {
            throw new PlutusWebhookException("明文 eventType 与传输头不一致");
        }
        if (payload.path("payloadSchemaVersion").asInt(-1) != 1) {
            throw new PlutusWebhookException("payloadSchemaVersion 必须为 1");
        }
    }

    private void checkTimestamp(String timestamp) {
        if (timestampTolerance == null) {
            return;
        }
        long value;
        try {
            value = Long.parseLong(timestamp);
        } catch (NumberFormatException e) {
            throw new PlutusWebhookException(WebhookHeaders.TIMESTAMP + " 不是十进制毫秒时间戳");
        }
        long skew = Math.abs(System.currentTimeMillis() - value);
        if (skew > timestampTolerance.toMillis()) {
            throw new PlutusWebhookException("Webhook 时间戳偏差 " + skew + " 毫秒, 超过配置的容差");
        }
    }

    private static Map<String, String> caseInsensitive(Map<String, String> headers) {
        Map<String, String> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                if (entry.getKey() != null) {
                    map.put(entry.getKey().trim(), entry.getValue());
                }
            }
        }
        return map;
    }

    private static String require(Map<String, String> headers, String name) {
        String value = headers.get(name);
        if (value == null || value.isBlank()) {
            throw new PlutusWebhookException("缺少必需的 Webhook 传输头: " + name);
        }
        return value;
    }

    /**
     * {@link WebhookHandler} 构造器。
     */
    public static final class Builder {

        private String platformAuthPublicKeyPem;
        private String merchantEncPrivateKeyPem;
        private String merchantEncPublicKeyPem;
        private String expectedApiKeyBizId;
        private Duration timestampTolerance;
        private ObjectMapper objectMapper;

        private Builder() {
        }

        /**
         * @param pem {@code platform_auth} SPKI 公钥 PEM,用于验签
         * @return 自身
         */
        public Builder platformAuthPublicKeyPem(String pem) {
            this.platformAuthPublicKeyPem = pem;
            return this;
        }

        /**
         * @param pem {@code merchant_enc} PKCS#8 私钥 PEM,用于解密
         * @return 自身
         */
        public Builder merchantEncPrivateKeyPem(String pem) {
            this.merchantEncPrivateKeyPem = pem;
            return this;
        }

        /**
         * 可选。不提供时从私钥推导,用于校验信封 {@code keyFingerprint}。
         *
         * @param pem {@code merchant_enc} SPKI 公钥 PEM
         * @return 自身
         */
        public Builder merchantEncPublicKeyPem(String pem) {
            this.merchantEncPublicKeyPem = pem;
            return this;
        }

        /**
         * 必填。验签后会校验 {@code X-SlaunchX-Key-Id} 与本地 API Key 业务 ID 相等。
         *
         * @param apiKeyBizId API Key 业务 ID
         * @return 自身
         */
        public Builder expectedApiKeyBizId(String apiKeyBizId) {
            this.expectedApiKeyBizId = apiKeyBizId;
            return this;
        }

        /**
         * 可选,<b>默认关闭</b>。
         *
         * <p>协议契约未规定商户侧应接受多大的 {@code X-SlaunchX-Timestamp} 偏差,
         * 规定的防重放手段是 AAD 绑定与按 {@code deliveryBizId} 去重。
         * 这里提供可配置容差,但不设默认值,也不声称 ±60 秒是协议要求。
         *
         * @param tolerance 允许的时钟偏差;{@code null} 表示不校验
         * @return 自身
         */
        public Builder timestampTolerance(Duration tolerance) {
            this.timestampTolerance = tolerance;
            return this;
        }

        /**
         * @param mapper 自定义 Jackson 实例
         * @return 自身
         */
        public Builder objectMapper(ObjectMapper mapper) {
            this.objectMapper = mapper;
            return this;
        }

        /**
         * @return 处理器实例
         */
        public WebhookHandler build() {
            return new WebhookHandler(this);
        }
    }

    /**
     * @return 本地商户加密公钥指纹,用于与信封 {@code keyFingerprint} 比对
     */
    public String merchantEncFingerprint() {
        return merchantEncFingerprint;
    }
}
