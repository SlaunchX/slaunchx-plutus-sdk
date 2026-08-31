<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * Webhook 信封形状非法、解密失败, 或解密后的明文与传输头交叉校验不一致。
 */
final class WebhookPayloadException extends WebhookException
{
}
