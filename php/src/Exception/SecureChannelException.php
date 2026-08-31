<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 加密信封被平台判为无效 (SECURE_CHANNEL.INVALID_PAYLOAD): AAD 不匹配、GCM 认证失败或明文超过 1 MiB。
 */
final class SecureChannelException extends ApiException
{
}
