<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use SlaunchX\Plutus\Http\RawResponse;
use SlaunchX\Plutus\Http\TransportInterface;

/**
 * 测试用传输: 记录发出的请求, 返回由回调构造的响应。
 */
final class FakeTransport implements TransportInterface
{
    /** @var array<int, array{method: string, url: string, headers: array<string, string>, body: string|null}> */
    public array $sent = [];

    /** @var callable(array{method: string, url: string, headers: array<string, string>, body: string|null}): RawResponse */
    private $responder;

    /**
     * @param callable(array{method: string, url: string, headers: array<string, string>, body: string|null}): RawResponse $responder
     */
    public function __construct(callable $responder)
    {
        $this->responder = $responder;
    }

    public function send(string $method, string $url, array $headers, ?string $body): RawResponse
    {
        $record = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body];
        $this->sent[] = $record;

        return ($this->responder)($record);
    }

    /**
     * @return array{method: string, url: string, headers: array<string, string>, body: string|null}
     */
    public function last(): array
    {
        return $this->sent[count($this->sent) - 1];
    }
}
