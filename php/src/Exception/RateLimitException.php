<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 限流 (429)。按 `Retry-After` 退避后重试, 重试须重新生成 timestamp + nonce 并重新签名。
 */
final class RateLimitException extends ApiException
{
    /**
     * `Retry-After` 响应头的秒数; 缺失或非数字时返回 null。
     */
    public function retryAfterSeconds(): ?int
    {
        $value = $this->response()->header('Retry-After');
        if ($value === null || !preg_match('/^\d+$/', trim($value))) {
            return null;
        }

        return (int) trim($value);
    }

    /**
     * `X-RateLimit-Reset` 响应头原值。
     */
    public function rateLimitReset(): ?string
    {
        return $this->response()->header('X-RateLimit-Reset');
    }
}
