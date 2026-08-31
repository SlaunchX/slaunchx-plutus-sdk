package com.slaunchx.plutus.sdk.webhook;

/**
 * Webhook 传输头名常量。
 */
public final class WebhookHeaders {

    /** 投递 ID,重试与手工重放时保持不变,是去重键。 */
    public static final String DELIVERY_ID = "X-SlaunchX-Delivery-Id";
    /** 事件类型,如 {@code card.issuance}。 */
    public static final String EVENT_TYPE = "X-SlaunchX-Event-Type";
    /** Unix 毫秒时间戳。 */
    public static final String TIMESTAMP = "X-SlaunchX-Timestamp";
    /** 接收方 API Key 业务 ID(不是指纹)。 */
    public static final String KEY_ID = "X-SlaunchX-Key-Id";
    /** Base64 RSA-SHA256 签名。 */
    public static final String SIGNATURE = "X-SlaunchX-Signature";

    private WebhookHeaders() {
    }
}
