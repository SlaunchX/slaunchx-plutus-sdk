<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Http;

/**
 * 传输抽象。默认实现为 {@see CurlTransport}; 测试或接入自有 HTTP 栈时可替换。
 *
 * 实现必须原样发送传入的 body 字节, 不得重新格式化、追加换行或改写编码,
 * 否则签名的 body 摘要与实际发送内容不一致, 平台验签必然失败。
 */
interface TransportInterface
{
    /**
     * @param string                $method  HTTP 方法 (大写)
     * @param string                $url     完整 URL, 含 query
     * @param array<string, string> $headers 完整请求头
     * @param string|null           $body    已序列化的 body 字节; null 表示不发送 body
     */
    public function send(string $method, string $url, array $headers, ?string $body): RawResponse;
}
