package com.slaunchx.plutus.sdk.webhook;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * 已验签并解密的 Webhook 通知。
 *
 * <p>消费者义务:按 {@link #deliveryBizId()} 去重(自动重试与人工重放共用同一个投递 ID);
 * {@code eventId} 是业务事件的稳定标识,同一事件可能投递到多个 endpoint。
 *
 * <p>载荷中的金额为 {@code {currency, amount}} 结构,{@code amount} 是十进制字符串,
 * 不得解析为浮点数。
 *
 * @param deliveryBizId 投递 ID,取自传输头,已与明文交叉校验
 * @param eventType     事件类型,取自传输头,已与明文交叉校验
 * @param timestamp     传输头的 Unix 毫秒时间戳
 * @param apiKeyBizId   传输头的接收方 API Key 业务 ID
 * @param plaintext     解密后的明文 JSON 字符串
 * @param payload       解密后的明文 JSON 树
 */
public record WebhookNotification(String deliveryBizId,
                                  String eventType,
                                  String timestamp,
                                  String apiKeyBizId,
                                  String plaintext,
                                  JsonNode payload) {

    /**
     * @return 业务事件 ID {@code eventId}
     */
    public String eventId() {
        return payload.path("eventId").asText(null);
    }

    /**
     * @return 载荷 schema 版本,当前恒为 1
     */
    public int payloadSchemaVersion() {
        return payload.path("payloadSchemaVersion").asInt();
    }

    /**
     * @return 业务数据节点 {@code data}
     */
    public JsonNode data() {
        return payload.path("data");
    }
}
