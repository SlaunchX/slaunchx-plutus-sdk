<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Model;

/**
 * 已验签并解密的 Webhook 通知。
 *
 * 载荷中的金额形如 `{"currency":"USD","amount":"25.80"}`, `amount` 是十进制字符串,
 * 不得解析为浮点数。消费方必须按 {@see WebhookEvent::$deliveryBizId} 去重。
 */
final class WebhookEvent
{
    /**
     * @param string               $deliveryBizId 投递 ID (`X-SlaunchX-Delivery-Id`), 去重键
     * @param string               $eventType     事件类型 (`X-SlaunchX-Event-Type`)
     * @param string               $timestamp     投递时间戳 (`X-SlaunchX-Timestamp`, Unix 毫秒)
     * @param string               $keyId         接收方 API Key 业务 ID (`X-SlaunchX-Key-Id`)
     * @param string               $plaintext     解密后的明文 JSON 字节
     * @param array<string, mixed> $payload       解析后的明文载荷
     * @param array<string, mixed> $envelope      原始信封结构
     */
    public function __construct(
        public readonly string $deliveryBizId,
        public readonly string $eventType,
        public readonly string $timestamp,
        public readonly string $keyId,
        public readonly string $plaintext,
        public readonly array $payload,
        public readonly array $envelope,
    ) {
    }

    /**
     * 业务事件 ID (`eventId`)。同一 `eventId` 可能投递到多个 endpoint。
     */
    public function eventId(): ?string
    {
        $value = $this->payload['eventId'] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * 载荷 schema 版本 (`payloadSchemaVersion`), v1 恒为 1。
     */
    public function payloadSchemaVersion(): ?int
    {
        $value = $this->payload['payloadSchemaVersion'] ?? null;

        return is_int($value) ? $value : null;
    }

    /**
     * 事件发生时间 (`occurredAt`), UTC RFC 3339 带 `Z`。
     */
    public function occurredAt(): ?string
    {
        $value = $this->payload['occurredAt'] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * 业务数据段 (`data`)。
     *
     * @return array<string, mixed>
     */
    public function data(): array
    {
        $value = $this->payload['data'] ?? null;

        return is_array($value) ? $value : [];
    }

    /**
     * 资源标识段 (`resource`)。
     *
     * @return array<string, mixed>
     */
    public function resource(): array
    {
        $value = $this->payload['resource'] ?? null;

        return is_array($value) ? $value : [];
    }
}
