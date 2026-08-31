<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 认证失败 (401 族): API Key 无效/禁用/锁定、时间戳越窗、nonce 重放、请求验签失败。绝大多数验签失败源于规范串拼接错误, 不应重试。
 */
final class AuthenticationException extends ApiException
{
}
