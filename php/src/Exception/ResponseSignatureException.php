<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 响应验签失败或应有签名而缺失。按安全事故处理: 响应体必须丢弃, 不得交给业务代码。
 */
final class ResponseSignatureException extends PlutusException
{
}
