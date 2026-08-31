<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Support;

use InvalidArgumentException;

/**
 * `X-Nonce` 生成与校验。
 *
 * 平台约束为 `^[A-Za-z0-9._~-]{16,128}$`, 即 RFC 3986 unreserved 字符集。
 * 标准 Base64 输出含 `+` `/` `=`, 不满足该约束。
 */
final class Nonce
{
    /** 平台校验 nonce 使用的正则。 */
    public const PATTERN = '/^[A-Za-z0-9._~-]{16,128}$/';

    /** 允许的最小长度。 */
    public const MIN_LENGTH = 16;

    /** 允许的最大长度。 */
    public const MAX_LENGTH = 128;

    private function __construct()
    {
    }

    /**
     * 生成一次性 nonce, 采用 CSPRNG 的 Base64URL 无填充编码。
     *
     * @param int $length 输出字符数, 取值范围 16–128, 默认 43 (约 256 位熵)
     */
    public static function generate(int $length = 43): string
    {
        if ($length < self::MIN_LENGTH || $length > self::MAX_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'nonce 长度须在 %d–%d 之间, 收到 %d',
                self::MIN_LENGTH,
                self::MAX_LENGTH,
                $length
            ));
        }

        $bytes = random_bytes((int) ceil($length * 3 / 4) + 1);
        $encoded = rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

        return substr($encoded, 0, $length);
    }

    /**
     * 判断 nonce 是否满足平台约束。
     */
    public static function isValid(string $nonce): bool
    {
        return preg_match(self::PATTERN, $nonce) === 1;
    }
}
