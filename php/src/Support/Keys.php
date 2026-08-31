<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Support;

use OpenSSLAsymmetricKey;
use SlaunchX\Plutus\Exception\ConfigurationException;

/**
 * RSA 密钥装载、格式校验与指纹计算。
 */
final class Keys
{
    /** 平台强制的模数位长下限。 */
    public const MIN_MODULUS_BITS = 2048;

    /** 平台强制的模数位长上限。 */
    public const MAX_MODULUS_BITS = 4096;

    /** 平台强制的公开指数。 */
    public const REQUIRED_PUBLIC_EXPONENT = 65537;

    private function __construct()
    {
    }

    /**
     * 装载 PKCS#8 PEM 私钥。
     *
     * @param string $pem       `-----BEGIN PRIVATE KEY-----` 开头的 PEM
     * @param string $labelHint 出错时用于定位的密钥用途名
     *
     * @throws ConfigurationException PEM 无法解析或不是 RSA 密钥
     */
    public static function loadPrivateKey(string $pem, string $labelHint = 'private key'): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_private($pem);
        if ($key === false) {
            throw new ConfigurationException(sprintf('无法解析 %s: 需要 PKCS#8 PEM 私钥', $labelHint));
        }
        self::assertRsa($key, $labelHint);

        return $key;
    }

    /**
     * 装载 SPKI PEM 公钥。
     *
     * @param string $pem       `-----BEGIN PUBLIC KEY-----` 开头的 PEM
     * @param string $labelHint 出错时用于定位的密钥用途名
     *
     * @throws ConfigurationException PEM 无法解析或不是 RSA 密钥
     */
    public static function loadPublicKey(string $pem, string $labelHint = 'public key'): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new ConfigurationException(sprintf('无法解析 %s: 需要 SPKI (BEGIN PUBLIC KEY) PEM 公钥', $labelHint));
        }
        self::assertRsa($key, $labelHint);

        return $key;
    }

    /**
     * 计算密钥指纹: `SHA256:` + 小写 hex(SHA256(SPKI DER))。
     *
     * 传入私钥时对其对应的公钥求指纹。
     */
    public static function fingerprint(OpenSSLAsymmetricKey $key): string
    {
        return 'SHA256:' . bin2hex(hash('sha256', self::spkiDer($key), true));
    }

    /**
     * 直接对 PEM 公钥求指纹。
     */
    public static function fingerprintFromPem(string $pem, string $labelHint = 'public key'): string
    {
        return self::fingerprint(self::loadPublicKey($pem, $labelHint));
    }

    /**
     * 模数字节长度 (k), 即 RSA 密文与签名的固定长度。
     */
    public static function modulusByteLength(OpenSSLAsymmetricKey $key): int
    {
        $details = openssl_pkey_get_details($key);
        if ($details === false || !isset($details['bits'])) {
            throw new ConfigurationException('无法读取 RSA 密钥参数');
        }

        return intdiv((int) $details['bits'] + 7, 8);
    }

    /**
     * 按平台登记规则校验商户公钥 PEM。
     *
     * 校验项: SPKI 格式、首尾标记独占一行、正文字符集、模数位长 2048–4096、
     * 公开指数恰为 65537、DER 规范编码 (重新编码后逐字节相等)。
     *
     * @throws ConfigurationException 任一项不满足
     */
    public static function assertRegistrablePublicKeyPem(string $pem, string $labelHint = 'public key'): void
    {
        $normalized = str_replace("\r\n", "\n", $pem);
        if (!preg_match(
            '/^-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+\/=\n]+)\n?-----END PUBLIC KEY-----\n?$/',
            trim($normalized) . "\n",
            $matches
        )) {
            throw new ConfigurationException(sprintf(
                '%s 不是合法的 SPKI PEM: 首尾标记须各自独占一行, 正文只允许 A-Za-z0-9+/= 与换行',
                $labelHint
            ));
        }

        $der = base64_decode(str_replace("\n", '', $matches[1]), true);
        if ($der === false) {
            throw new ConfigurationException(sprintf('%s 的 Base64 正文非法', $labelHint));
        }

        $key = self::loadPublicKey($normalized, $labelHint);
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new ConfigurationException(sprintf('无法读取 %s 的参数', $labelHint));
        }

        $bits = (int) $details['bits'];
        if ($bits < self::MIN_MODULUS_BITS || $bits > self::MAX_MODULUS_BITS) {
            throw new ConfigurationException(sprintf(
                '%s 模数位长 %d 超出 [%d, %d]',
                $labelHint,
                $bits,
                self::MIN_MODULUS_BITS,
                self::MAX_MODULUS_BITS
            ));
        }

        $exponent = $details['rsa']['e'] ?? null;
        if (!is_string($exponent) || self::bytesToInt($exponent) !== self::REQUIRED_PUBLIC_EXPONENT) {
            throw new ConfigurationException(sprintf('%s 的公开指数必须恰为 65537', $labelHint));
        }

        if (!hash_equals(self::spkiDer($key), $der)) {
            throw new ConfigurationException(sprintf('%s 的 DER 编码不规范 (重新编码后不相等)', $labelHint));
        }
    }

    /**
     * 提取密钥的 SPKI DER 字节。
     */
    private static function spkiDer(OpenSSLAsymmetricKey $key): string
    {
        $details = openssl_pkey_get_details($key);
        if ($details === false || !isset($details['key'])) {
            throw new ConfigurationException('无法导出公钥 SPKI');
        }

        $pem = (string) $details['key'];
        $body = preg_replace('/-----(BEGIN|END) PUBLIC KEY-----|\s+/', '', $pem) ?? '';
        $der = base64_decode($body, true);
        if ($der === false) {
            throw new ConfigurationException('无法解码公钥 SPKI DER');
        }

        return $der;
    }

    private static function assertRsa(OpenSSLAsymmetricKey $key, string $labelHint): void
    {
        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            throw new ConfigurationException(sprintf('%s 必须是 RSA 密钥', $labelHint));
        }
    }

    private static function bytesToInt(string $bytes): int
    {
        $value = 0;
        $length = strlen($bytes);
        for ($i = 0; $i < $length; $i++) {
            $value = ($value << 8) | ord($bytes[$i]);
        }

        return $value;
    }
}
