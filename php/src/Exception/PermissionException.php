<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 权限不足 (403 族): API Key 权限不够、门户不匹配、源 IP 不在白名单、workspace 不可用。
 */
final class PermissionException extends ApiException
{
}
