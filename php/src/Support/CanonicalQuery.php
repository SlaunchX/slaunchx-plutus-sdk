<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Support;

use SlaunchX\Plutus\Exception\CanonicalizationException;

/**
 * Query 规范化: 严格解码 → RFC 3986 重编码 → 按 (key, value) 字节序排序 → 重组。
 *
 * 与语言内置的 `http_build_query` / `urlencode` 语义完全不同, 不得混用:
 * 本算法不把 `+` 当空格, 不编码 `-` `.` `_` `~`, 且对任何裸保留字符、非法 percent
 * 转义、非 ASCII 字符与非法 UTF-8 直接抛异常而非静默回退。
 */
final class CanonicalQuery
{
    private function __construct()
    {
    }

    /**
     * 规范化原始 query 串。
     *
     * @param string|null $rawQuery 不含前导 `?` 的原始 query; null、空串或全空白返回空串
     *
     * @throws CanonicalizationException 任一分量不满足 RFC 3986 严格解码要求
     */
    public static function canonicalize(?string $rawQuery): string
    {
        if ($rawQuery === null || trim($rawQuery) === '') {
            return '';
        }

        $pairs = [];
        foreach (explode('&', $rawQuery) as $segment) {
            $position = strpos($segment, '=');
            if ($position === false) {
                $rawKey = $segment;
                $rawValue = '';
            } else {
                $rawKey = substr($segment, 0, $position);
                $rawValue = substr($segment, $position + 1);
            }

            $pairs[] = [self::canonicalizeComponent($rawKey), self::canonicalizeComponent($rawValue)];
        }

        usort($pairs, static function (array $left, array $right): int {
            $byKey = strcmp($left[0], $right[0]);

            return $byKey !== 0 ? $byKey : strcmp($left[1], $right[1]);
        });

        $rendered = [];
        foreach ($pairs as [$key, $value]) {
            $rendered[] = $key . '=' . $value;
        }

        return implode('&', $rendered);
    }

    /**
     * 规范化单个分量 (key 或 value): 严格 percent 解码后再按 RFC 3986 重编码。
     *
     * @throws CanonicalizationException
     */
    public static function canonicalizeComponent(string $component): string
    {
        return self::percentEncode(self::percentDecodeStrict($component));
    }

    /**
     * 严格 percent 解码。裸保留字符、非 ASCII、非法或截断的 `%XX`、
     * 以及解码后非法的 UTF-8 一律拒绝。
     *
     * @throws CanonicalizationException
     */
    private static function percentDecodeStrict(string $component): string
    {
        $out = '';
        $length = strlen($component);
        for ($i = 0; $i < $length;) {
            $char = $component[$i];
            if ($char === '%') {
                if ($i + 2 >= $length) {
                    throw new CanonicalizationException('query component contains incomplete percent encoding');
                }
                $high = self::hexDigit($component[$i + 1]);
                $low = self::hexDigit($component[$i + 2]);
                if ($high < 0 || $low < 0) {
                    throw new CanonicalizationException('query component contains invalid percent encoding');
                }
                $out .= chr($high * 16 + $low);
                $i += 3;
                continue;
            }

            if (!self::isUnreserved(ord($char))) {
                throw new CanonicalizationException(
                    'query component must use RFC 3986 percent encoding for reserved characters'
                );
            }
            $out .= $char;
            $i++;
        }

        if ($out !== '' && preg_match('//u', $out) !== 1) {
            throw new CanonicalizationException('query component contains invalid UTF-8');
        }

        return $out;
    }

    /**
     * RFC 3986 重编码: unreserved 字符原样输出, 其余编码为大写 `%XX`。
     */
    private static function percentEncode(string $bytes): string
    {
        $out = '';
        $length = strlen($bytes);
        for ($i = 0; $i < $length; $i++) {
            $byte = ord($bytes[$i]);
            $out .= self::isUnreserved($byte)
                ? $bytes[$i]
                : '%' . strtoupper(str_pad(dechex($byte), 2, '0', STR_PAD_LEFT));
        }

        return $out;
    }

    /**
     * RFC 3986 unreserved 集合: ALPHA / DIGIT / `-` `.` `_` `~`。
     */
    private static function isUnreserved(int $byte): bool
    {
        return ($byte >= 0x41 && $byte <= 0x5A)
            || ($byte >= 0x61 && $byte <= 0x7A)
            || ($byte >= 0x30 && $byte <= 0x39)
            || $byte === 0x2D
            || $byte === 0x2E
            || $byte === 0x5F
            || $byte === 0x7E;
    }

    private static function hexDigit(string $char): int
    {
        $ord = ord($char);
        if ($ord >= 0x30 && $ord <= 0x39) {
            return $ord - 0x30;
        }
        if ($ord >= 0x41 && $ord <= 0x46) {
            return $ord - 0x41 + 10;
        }
        if ($ord >= 0x61 && $ord <= 0x66) {
            return $ord - 0x61 + 10;
        }

        return -1;
    }

    /**
     * 把键值数组编码成可被本算法接受的原始 query 串。
     *
     * 值按 RFC 3986 全量 percent 编码, 因此空格编为 `%20`, `+` 编为 `%2B`。
     * 重复 key 用列表值表达。
     *
     * @param array<string, scalar|array<int, scalar>> $params
     */
    public static function build(array $params): string
    {
        $segments = [];
        foreach ($params as $key => $value) {
            $values = is_array($value) ? $value : [$value];
            foreach ($values as $single) {
                $segments[] = self::percentEncode((string) $key)
                    . '='
                    . self::percentEncode(self::stringify($single));
            }
        }

        return implode('&', $segments);
    }

    /**
     * @param scalar $value
     */
    private static function stringify(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        return (string) $value;
    }
}
