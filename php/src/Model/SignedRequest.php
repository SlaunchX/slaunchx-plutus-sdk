<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Model;

/**
 * 一次已签名请求的不可变快照。
 *
 * 同时承载响应验签所需的全部绑定信息 (规范串摘要、外部路径、API 版本),
 * 调用方必须把它保留到响应验签完成为止。
 */
final class SignedRequest
{
    /**
     * @param string                $method                 HTTP 方法 (大写)
     * @param string                $externalPath           外部路径, 以 `/` 开头
     * @param string                $canonicalQuery         规范化后的 query, 无 query 时为空串
     * @param string|null           $rawQuery               商户给出的原始 query
     * @param string                $timestamp              `X-Timestamp` 原值 (Unix 毫秒)
     * @param string                $nonce                  `X-Nonce` 原值
     * @param string                $apiVersion             `X-API-VERSION` 原值
     * @param string|null           $idempotencyKey         `X-Idempotency-Key`; 不发送时为 null
     * @param string                $body                   实际发送的 body 字节 (可能为空串)
     * @param string                $bodyHash               规范串第 8 行的 body 摘要 (小写 hex)
     * @param string                $canonicalString        所选协议的请求规范串 (8 行或 7 行)
     * @param string                $requestCanonicalSha256 规范串自身的 SHA-256 (小写 hex)
     * @param string                $signature              Base64 请求签名
     * @param array<string, string> $headers                待发送的完整请求头
     */
    public function __construct(
        public readonly string $method,
        public readonly string $externalPath,
        public readonly string $canonicalQuery,
        public readonly ?string $rawQuery,
        public readonly string $timestamp,
        public readonly string $nonce,
        public readonly string $apiVersion,
        public readonly ?string $idempotencyKey,
        public readonly string $body,
        public readonly string $bodyHash,
        public readonly string $canonicalString,
        public readonly string $requestCanonicalSha256,
        public readonly string $signature,
        public readonly array $headers,
    ) {
    }

    /**
     * 规范串按 LF 拆行, 便于按所选协议逐行比对。
     *
     * @return array<int, string>
     */
    public function canonicalStringLines(): array
    {
        return explode("\n", $this->canonicalString);
    }
}
