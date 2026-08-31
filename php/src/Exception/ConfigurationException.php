<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 配置缺失或非法: 缺少密钥、PEM 无法解析、公钥不满足平台登记约束等。
 */
final class ConfigurationException extends PlutusException
{
}
