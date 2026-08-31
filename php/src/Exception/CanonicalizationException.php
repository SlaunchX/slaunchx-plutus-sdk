<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

/**
 * 规范化阶段的本地拒绝: query 含裸保留字符、非法 percent 转义、非 ASCII 或非法 UTF-8。
 *
 * SDK 在本地直接拒绝, 不做任何回退编码, 以免发出必然被平台判为签名无效的请求。
 */
final class CanonicalizationException extends PlutusException
{
}
