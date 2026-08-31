<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * Webhook 验签失败或传输头缺失。必须直接丢弃投递, 不得尝试解密。
 */
final class WebhookSignatureException extends WebhookException
{
}
