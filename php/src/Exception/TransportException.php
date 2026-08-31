<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 传输层错误: cURL 连接失败、超时、TLS 握手失败等。未收到 HTTP 响应。
 */
final class TransportException extends PlutusException
{
}
