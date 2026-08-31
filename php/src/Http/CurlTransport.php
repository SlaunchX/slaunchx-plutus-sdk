<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Http;

use CurlHandle;
use SlaunchX\Plutus\Exception\TransportException;
use SlaunchX\Plutus\PlutusConfig;

/**
 * 基于 cURL 的传输实现。
 *
 * 关键约束: body 以已序列化的字符串原样发送, cURL 不得重新格式化。
 * 显式清空 `Expect` 头以避免 100-continue 影响大 body 的发送时序。
 */
final class CurlTransport implements TransportInterface
{
    public function __construct(private readonly PlutusConfig $config)
    {
    }

    /**
     * 发送一次请求并返回原始响应。
     *
     * @param string                $method  HTTP 方法 (大写)
     * @param string                $url     完整 URL, 含 query
     * @param array<string, string> $headers 完整请求头
     * @param string|null           $body    已序列化的 body 字节; null 表示不发送 body
     *
     * @throws TransportException 未收到 HTTP 响应
     */
    public function send(string $method, string $url, array $headers, ?string $body): RawResponse
    {
        $handle = curl_init();
        if (!$handle instanceof CurlHandle) {
            throw new TransportException('无法初始化 cURL 句柄');
        }

        $responseHeaders = [];
        $headerLines = ['Expect:'];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        $options = [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT_MS => $this->config->connectTimeoutMs,
            CURLOPT_TIMEOUT_MS => $this->config->timeoutMs,
            CURLOPT_USERAGENT => $this->config->userAgent,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HEADERFUNCTION => static function ($_handle, string $line) use (&$responseHeaders): int {
                $length = strlen($line);
                $position = strpos($line, ':');
                if ($position !== false) {
                    $name = trim(substr($line, 0, $position));
                    $value = trim(substr($line, $position + 1));
                    if ($name !== '') {
                        $responseHeaders[$name] = $value;
                    }
                }

                return $length;
            },
        ];

        if ($method === 'HEAD') {
            $options[CURLOPT_NOBODY] = true;
        }
        if ($body !== null) {
            $options[CURLOPT_POSTFIELDS] = $body;
        }

        foreach ($this->config->curlOptions as $option => $value) {
            $options[$option] = $value;
        }

        curl_setopt_array($handle, $options);

        $raw = curl_exec($handle);
        if ($raw === false) {
            $error = curl_error($handle);
            $errno = curl_errno($handle);
            curl_close($handle);

            throw new TransportException(sprintf('cURL 请求失败 (%d): %s', $errno, $error));
        }

        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);

        return new RawResponse($status, $responseHeaders, is_string($raw) ? $raw : '');
    }
}
