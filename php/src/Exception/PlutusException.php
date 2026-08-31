<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

use RuntimeException;

/**
 * SDK 所有异常的基类。捕获本类即可覆盖 SDK 抛出的全部错误。
 */
class PlutusException extends RuntimeException
{
}
