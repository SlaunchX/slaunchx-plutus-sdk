<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 冲突 (409): 幂等键冲突、业务冲突或乐观锁版本过期。
 */
final class ConflictException extends ApiException
{
}
