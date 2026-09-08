<?php
declare(strict_types=1);

namespace SlaunchX\Plutus\Support;

use SlaunchX\Plutus\Exception\CanonicalizationException;

/**
 * product 的 RsaSignatureCodec Query 规则：form 解码，按解码后 Java String
 * (UTF-16 code unit) 排序，再用 URLEncoder 编码，并将空格替换为 %20。
 * SDK 对非法 percent 转义及非法 UTF-8 提前拒绝，不复制后端的宽松错误回退。
 */
final class ProductCanonicalQuery
{
    private function __construct() {}

    public static function canonicalize(?string $rawQuery): string
    {
        // Mirrors Java String.isBlank(), including its exclusions for non-breaking spaces.
        if ($rawQuery === null || preg_match(
            '/^[\x{0009}-\x{000D}\x{001C}-\x{0020}\x{1680}\x{2000}-\x{2006}\x{2008}-\x{200A}\x{2028}\x{2029}\x{205F}\x{3000}]*$/u',
            $rawQuery,
        ) === 1) {
            return '';
        }
        $pairs = [];
        foreach (explode('&', $rawQuery) as $segment) {
            $parts = explode('=', $segment, 2);
            $key = self::decode($parts[0]);
            $value = self::decode($parts[1] ?? '');
            $pairs[] = [$key, $value, self::utf16SortKey($key), self::utf16SortKey($value)];
        }
        usort($pairs, static function (array $left, array $right): int {
            $key = strcmp($left[2], $right[2]);
            return $key !== 0 ? $key : strcmp($left[3], $right[3]);
        });
        return implode('&', array_map(
            static fn(array $pair): string => self::encode($pair[0]) . '=' . self::encode($pair[1]),
            $pairs,
        ));
    }

    private static function decode(string $value): string
    {
        if (preg_match('/%(?![0-9a-fA-F]{2})/', $value)) {
            throw new CanonicalizationException('query component contains invalid percent encoding');
        }
        $decoded = urldecode($value);
        if (preg_match('//u', $decoded) !== 1) {
            throw new CanonicalizationException('query component contains invalid UTF-8');
        }
        return $decoded;
    }

    private static function encode(string $value): string
    {
        // PHP urlencode and Java URLEncoder differ on '*'; both encode '~'.
        return str_replace(['+', '%2A'], ['%20', '*'], urlencode($value));
    }

    /** UTF-8 已在 decode 校验；无需给 SDK 添加 mbstring/iconv 运行依赖。 */
    private static function utf16SortKey(string $value): string
    {
        $result = '';
        for ($i = 0, $length = strlen($value); $i < $length; $i++) {
            $first = ord($value[$i]);
            if ($first < 0x80) {
                $code = $first;
            } elseif ($first < 0xE0) {
                $code = (($first & 0x1F) << 6) | (ord($value[++$i]) & 0x3F);
            } elseif ($first < 0xF0) {
                $code = (($first & 0x0F) << 12) | ((ord($value[++$i]) & 0x3F) << 6)
                    | (ord($value[++$i]) & 0x3F);
            } else {
                $code = (($first & 0x07) << 18) | ((ord($value[++$i]) & 0x3F) << 12)
                    | ((ord($value[++$i]) & 0x3F) << 6) | (ord($value[++$i]) & 0x3F);
            }
            if ($code <= 0xFFFF) {
                $result .= pack('n', $code);
            } else {
                $code -= 0x10000;
                $result .= pack('nn', 0xD800 + ($code >> 10), 0xDC00 + ($code & 0x3FF));
            }
        }
        return $result;
    }
}
