<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Support;

use OpenSSLAsymmetricKey;
use SlaunchX\Plutus\Exception\EnvelopeException;

/**
 * RSAES-OAEP (RFC 8017) 的 SHA-256 实现。
 *
 * PHP 的 ext-openssl 只暴露 `OPENSSL_PKCS1_OAEP_PADDING`, 其摘要与 MGF1 均硬编码为
 * SHA-1, 无法满足协议要求的 `OAEP(hash=SHA-256, MGF1=SHA-256)`。因此本类在
 * `OPENSSL_NO_PADDING` (裸 RSA 模幂) 之上自行完成 EME-OAEP 编码与解码,
 * 从而不引入任何第三方依赖。label 为空串, 与协议一致。
 */
final class Oaep
{
    /** 摘要输出长度 (SHA-256)。 */
    private const H_LEN = 32;

    private function __construct()
    {
    }

    /**
     * 用接收方公钥做 RSA-OAEP-SHA256 加密。
     *
     * @param string               $plaintext 明文字节, 长度须 <= k - 2*hLen - 2
     * @param OpenSSLAsymmetricKey $publicKey 接收方公钥
     *
     * @throws EnvelopeException 明文过长或 RSA 运算失败
     */
    public static function encrypt(string $plaintext, OpenSSLAsymmetricKey $publicKey): string
    {
        $k = Keys::modulusByteLength($publicKey);
        $maxLen = $k - 2 * self::H_LEN - 2;
        if (strlen($plaintext) > $maxLen) {
            throw new EnvelopeException(sprintf(
                'RSA-OAEP-SHA256 明文过长: %d 字节, 上限 %d 字节',
                strlen($plaintext),
                $maxLen
            ));
        }

        $encoded = self::encode($plaintext, $k);

        $cipher = null;
        if (!openssl_public_encrypt($encoded, $cipher, $publicKey, OPENSSL_NO_PADDING) || $cipher === null) {
            throw new EnvelopeException('RSA 公钥加密失败: ' . self::opensslErrors());
        }

        return $cipher;
    }

    /**
     * 用接收方私钥做 RSA-OAEP-SHA256 解密。
     *
     * @throws EnvelopeException 密文长度不符、RSA 运算失败或 OAEP 校验失败
     */
    public static function decrypt(string $ciphertext, OpenSSLAsymmetricKey $privateKey): string
    {
        $k = Keys::modulusByteLength($privateKey);
        if (strlen($ciphertext) !== $k) {
            throw new EnvelopeException(sprintf(
                'RSA 密文长度非法: %d 字节, 期望 %d 字节',
                strlen($ciphertext),
                $k
            ));
        }

        $raw = null;
        if (!openssl_private_decrypt($ciphertext, $raw, $privateKey, OPENSSL_NO_PADDING) || $raw === null) {
            throw new EnvelopeException('RSA 私钥解密失败: ' . self::opensslErrors());
        }

        return self::decode($raw, $k);
    }

    /**
     * EME-OAEP 编码 (RFC 8017 7.1.1 步骤 2)。
     */
    private static function encode(string $message, int $k): string
    {
        $lHash = hash('sha256', '', true);
        $psLength = $k - strlen($message) - 2 * self::H_LEN - 2;
        $db = $lHash . str_repeat("\x00", $psLength) . "\x01" . $message;

        $seed = random_bytes(self::H_LEN);
        $maskedDb = $db ^ self::mgf1($seed, $k - self::H_LEN - 1);
        $maskedSeed = $seed ^ self::mgf1($maskedDb, self::H_LEN);

        return "\x00" . $maskedSeed . $maskedDb;
    }

    /**
     * EME-OAEP 解码 (RFC 8017 7.1.2 步骤 3)。
     *
     * 所有失败分支合并为同一条错误信息, 避免把 padding oracle 暴露给调用方。
     */
    private static function decode(string $encoded, int $k): string
    {
        if ($k < 2 * self::H_LEN + 2 || strlen($encoded) !== $k) {
            throw new EnvelopeException('RSA-OAEP-SHA256 解码失败');
        }

        $lHash = hash('sha256', '', true);
        $leading = $encoded[0];
        $maskedSeed = substr($encoded, 1, self::H_LEN);
        $maskedDb = substr($encoded, 1 + self::H_LEN);

        $seed = $maskedSeed ^ self::mgf1($maskedDb, self::H_LEN);
        $db = $maskedDb ^ self::mgf1($seed, $k - self::H_LEN - 1);

        $bad = $leading !== "\x00";
        $bad = $bad || !hash_equals($lHash, substr($db, 0, self::H_LEN));

        $index = self::H_LEN;
        $length = strlen($db);
        while ($index < $length && $db[$index] === "\x00") {
            $index++;
        }
        $bad = $bad || $index >= $length || $db[$index] !== "\x01";

        if ($bad) {
            throw new EnvelopeException('RSA-OAEP-SHA256 解码失败');
        }

        return substr($db, $index + 1);
    }

    /**
     * MGF1 掩码生成函数, 摘要固定为 SHA-256。
     */
    private static function mgf1(string $seed, int $length): string
    {
        $out = '';
        for ($counter = 0; strlen($out) < $length; $counter++) {
            $out .= hash('sha256', $seed . pack('N', $counter), true);
        }

        return substr($out, 0, $length);
    }

    private static function opensslErrors(): string
    {
        $messages = [];
        while (($error = openssl_error_string()) !== false) {
            $messages[] = $error;
        }

        return $messages === [] ? 'unknown' : implode('; ', $messages);
    }
}
