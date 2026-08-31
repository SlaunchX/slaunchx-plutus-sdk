<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 平台内部错误 (5xx)。可指数退避重试; 写操作必须携带 X-Idempotency-Key。
 */
final class ServerException extends ApiException
{
}
