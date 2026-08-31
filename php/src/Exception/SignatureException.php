<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 本地生成请求签名失败 (私钥不可用、openssl_sign 返回失败)。
 */
final class SignatureException extends PlutusException
{
}
