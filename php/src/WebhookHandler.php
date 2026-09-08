<?php

declare(strict_types=1);

namespace SlaunchX\Plutus;

use JsonException;
use SlaunchX\Plutus\Exception\EnvelopeException;
use SlaunchX\Plutus\Exception\WebhookPayloadException;
use SlaunchX\Plutus\Exception\WebhookSignatureException;
use SlaunchX\Plutus\Model\WebhookEvent;

/**
 * Webhook 接收处理: 先验签, 校验本地接收方 API Key, 后解密。
 *
 * 两处与 API 链的差异必须注意:
 * - 签名规范串第 4 行的 body 摘要用 **Base64**, 不是小写 hex;
 * - 信封形状不同: 有 `envelopeVersion`, 无 `encryptedPayload`。
 *
 * 签名覆盖的是加密信封 JSON 的原始字节, 验签失败即丢弃, 不得尝试解密。
 */
final class WebhookHandler
{
    /** 传输头名。 */
    public const HEADER_DELIVERY_ID = 'X-SlaunchX-Delivery-Id';
    public const HEADER_EVENT_TYPE = 'X-SlaunchX-Event-Type';
    public const HEADER_TIMESTAMP = 'X-SlaunchX-Timestamp';
    public const HEADER_KEY_ID = 'X-SlaunchX-Key-Id';
    public const HEADER_SIGNATURE = 'X-SlaunchX-Signature';

    /** AAD 的 routeTemplate 位固定字面量。 */
    public const AAD_ROUTE_TEMPLATE = 'webhook';

    public function __construct(private readonly PlutusConfig $config)
    {
    }

    /**
     * Webhook body 摘要: Base64(SHA256(原始 body 字节))。
     *
     * 注意与 API 链的小写 hex 摘要不是同一个工具函数, 不要复用。
     */
    public static function bodyDigestBase64(string $rawBody): string
    {
        return base64_encode(hash('sha256', $rawBody, true));
    }

    /**
     * 拼接 4 行 Webhook 签名规范串 (LF 连接, 无尾换行)。
     */
    public static function buildCanonicalString(
        string $deliveryBizId,
        string $eventType,
        string $timestamp,
        string $bodyDigestBase64,
    ): string {
        return implode("\n", [$deliveryBizId, $eventType, $timestamp, $bodyDigestBase64]);
    }

    /**
     * 拼接 Webhook 解密 AAD: `deliveryBizId|webhook|timestamp|apiKeyBizId`。
     *
     * 第 4 位是 **API Key 业务 ID**, 不是密钥指纹。
     */
    public static function buildAad(string $deliveryBizId, string $timestamp, string $apiKeyBizId): string
    {
        return EnvelopeCodec::buildAad($deliveryBizId, self::AAD_ROUTE_TEMPLATE, $timestamp, $apiKeyBizId);
    }

    /**
     * 校验投递签名。
     *
     * @param array<string, string> $headers 投递请求头 (大小写不敏感)
     * @param string                $rawBody 原始 HTTP body 字节
     *
     * @throws WebhookSignatureException 头缺失、时间戳越窗或验签失败
     */
    public function verifySignature(array $headers, string $rawBody): void
    {
        $deliveryId = $this->requireHeader($headers, self::HEADER_DELIVERY_ID);
        $eventType = $this->requireHeader($headers, self::HEADER_EVENT_TYPE);
        $timestamp = $this->requireHeader($headers, self::HEADER_TIMESTAMP);
        $signature = $this->requireHeader($headers, self::HEADER_SIGNATURE);

        $this->assertTimestampWithinTolerance($timestamp);

        $canonicalString = self::buildCanonicalString(
            $deliveryId,
            $eventType,
            $timestamp,
            self::bodyDigestBase64($rawBody)
        );

        $decoded = base64_decode($signature, true);
        if ($decoded === false) {
            throw new WebhookSignatureException('X-SlaunchX-Signature 不是合法 Base64');
        }

        $verified = openssl_verify(
            $canonicalString,
            $decoded,
            $this->config->platformAuthPublicKey(),
            OPENSSL_ALGO_SHA256
        );
        if ($verified !== 1) {
            throw new WebhookSignatureException('Webhook 验签失败, 投递已丢弃');
        }
    }

    /**
     * 解析并校验 Webhook 信封形状。
     *
     * @return array<string, mixed>
     *
     * @throws WebhookPayloadException body 不是 JSON 对象或信封形状非法
     */
    public function parseEnvelope(string $rawBody): array
    {
        try {
            $decoded = json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new WebhookPayloadException('Webhook body 不是合法 JSON: ' . $exception->getMessage());
        }

        if (!is_array($decoded)) {
            throw new WebhookPayloadException('Webhook body 必须是 JSON 对象');
        }

        try {
            EnvelopeCodec::assertWebhookShape($decoded);
        } catch (EnvelopeException $exception) {
            throw new WebhookPayloadException($exception->getMessage());
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * 校验接收方并解密 Webhook 信封, 返回明文 JSON 字节。调用前必须已完成验签。
     *
     * @param array<string, string> $headers
     *
     * @throws WebhookPayloadException 接收方 API Key 不匹配、AAD 不匹配、指纹不匹配或解密失败
     */
    public function decrypt(array $headers, string $rawBody): string
    {
        $deliveryId = $this->requireHeader($headers, self::HEADER_DELIVERY_ID);
        $timestamp = $this->requireHeader($headers, self::HEADER_TIMESTAMP);
        $this->requireRecipientApiKey($headers);

        $envelope = $this->parseEnvelope($rawBody);
        $aad = self::buildAad($deliveryId, $timestamp, $this->config->apiKey);

        try {
            return EnvelopeCodec::open(
                $envelope,
                $this->config->merchantEncPrivateKey(),
                $aad,
                $this->config->merchantEncKeyFingerprint(),
            );
        } catch (EnvelopeException $exception) {
            throw new WebhookPayloadException($exception->getMessage());
        }
    }

    /**
     * 完整处理一次投递: 验签 → 校验接收方 API Key → 解析信封 → 解密 → 与传输头交叉校验。
     *
     * 交叉校验项 (SPEC 10.6): 明文的 `deliveryBizId` / `eventType` 与传输头一致,
     * `payloadSchemaVersion` 恰为 1。
     *
     * 本方法**不做去重**: 调用方必须自行按 `deliveryBizId` 去重, 自动重试与人工重放
     * 共用同一个 `deliveryBizId`。
     *
     * @param array<string, string> $headers 投递请求头
     * @param string                $rawBody 原始 HTTP body 字节
     *
     * @throws WebhookSignatureException 验签失败
     * @throws WebhookPayloadException   信封非法、解密失败或交叉校验不一致
     */
    public function handle(array $headers, string $rawBody): WebhookEvent
    {
        $this->verifySignature($headers, $rawBody);

        $deliveryId = $this->requireHeader($headers, self::HEADER_DELIVERY_ID);
        $eventType = $this->requireHeader($headers, self::HEADER_EVENT_TYPE);
        $timestamp = $this->requireHeader($headers, self::HEADER_TIMESTAMP);
        $keyId = $this->requireRecipientApiKey($headers);

        $envelope = $this->parseEnvelope($rawBody);
        $plaintext = $this->decrypt($headers, $rawBody);

        try {
            $payload = json_decode($plaintext, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new WebhookPayloadException('Webhook 明文不是合法 JSON: ' . $exception->getMessage());
        }
        if (!is_array($payload)) {
            throw new WebhookPayloadException('Webhook 明文必须是 JSON 对象');
        }

        $this->assertCrossChecks($payload, $deliveryId, $eventType);

        /** @var array<string, mixed> $payload */
        return new WebhookEvent($deliveryId, $eventType, $timestamp, $keyId, $plaintext, $payload, $envelope);
    }

    /**
     * 校验传输头中的接收方, 返回本地登记的 API Key 业务 ID, 不是公钥指纹。
     *
     * @param array<string, string> $headers
     */
    private function requireRecipientApiKey(array $headers): string
    {
        $keyId = $this->requireHeader($headers, self::HEADER_KEY_ID);
        if (!hash_equals($this->config->apiKey, $keyId)) {
            throw new WebhookPayloadException('Webhook 接收方 API Key 不匹配');
        }

        return $this->config->apiKey;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function assertCrossChecks(array $payload, string $deliveryId, string $eventType): void
    {
        foreach (['eventId', 'eventType', 'payloadSchemaVersion', 'occurredAt', 'workspaceBizId', 'deliveryBizId', 'resource', 'data'] as $field) {
            if (!array_key_exists($field, $payload)) {
                throw new WebhookPayloadException(sprintf('Webhook 明文缺少必填字段 %s', $field));
            }
        }

        if ($payload['deliveryBizId'] !== $deliveryId) {
            throw new WebhookPayloadException('明文 deliveryBizId 与传输头不一致');
        }
        if ($payload['eventType'] !== $eventType) {
            throw new WebhookPayloadException('明文 eventType 与传输头不一致');
        }
        if ($payload['payloadSchemaVersion'] !== 1) {
            throw new WebhookPayloadException('payloadSchemaVersion 必须为 1');
        }
    }

    /**
     * @param array<string, string> $headers
     */
    private function requireHeader(array $headers, string $name): string
    {
        foreach ($headers as $key => $value) {
            if (strcasecmp((string) $key, $name) === 0 && $value !== '') {
                return (string) $value;
            }
        }

        throw new WebhookSignatureException(sprintf('Webhook 缺少传输头 %s', $name));
    }

    /**
     * 时间戳容差校验。
     *
     * 协议未规定商户侧的容差窗口 (SPEC 16.1), 因此默认关闭
     * (`webhookTimestampToleranceMs = 0`); 防重放依赖 AAD 常量时间比对与
     * `deliveryBizId` 去重。
     */
    private function assertTimestampWithinTolerance(string $timestamp): void
    {
        $tolerance = $this->config->webhookTimestampToleranceMs;
        if ($tolerance <= 0) {
            return;
        }

        if (!preg_match('/^\d+$/', $timestamp)) {
            throw new WebhookSignatureException('X-SlaunchX-Timestamp 不是十进制毫秒');
        }

        $now = (int) round(microtime(true) * 1000);
        if (abs($now - (int) $timestamp) > $tolerance) {
            throw new WebhookSignatureException(sprintf(
                'Webhook 时间戳偏差超过容差 %d 毫秒',
                $tolerance
            ));
        }
    }
}
