<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 混合加密信封处理失败: 结构非法、AAD 不匹配、RSA-OAEP 解包失败、GCM 认证失败、明文超限。
 */
class EnvelopeException extends PlutusException
{
}
