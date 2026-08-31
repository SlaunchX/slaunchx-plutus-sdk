<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Http;

/**
 * 传输层原始响应: 状态码、响应头与未经任何处理的 body 字节。
 *
 * body 必须保持原始字节, 响应验签对其直接求 SHA-256。
 */
final class RawResponse
{
    /** @var array<string, string> 小写头名 → 头值 */
    private readonly array $lowercased;

    /**
     * @param array<string, string> $headers 保留线格式大小写的响应头
     */
    public function __construct(
        public readonly int $statusCode,
        public readonly array $headers,
        public readonly string $body,
    ) {
        $lowercased = [];
        foreach ($headers as $name => $value) {
            $lowercased[strtolower($name)] = $value;
        }
        $this->lowercased = $lowercased;
    }

    /**
     * 按大小写不敏感取响应头; 不存在时返回 null。
     */
    public function header(string $name): ?string
    {
        return $this->lowercased[strtolower($name)] ?? null;
    }
}
