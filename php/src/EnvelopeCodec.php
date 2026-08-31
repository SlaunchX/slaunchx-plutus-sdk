<?php

declare(strict_types=1);

namespace SlaunchX\Plutus;

use OpenSSLAsymmetricKey;
use SlaunchX\Plutus\Exception\EnvelopeException;
use SlaunchX\Plutus\Support\Keys;
use SlaunchX\Plutus\Support\Oaep;

/**
 * 混合加密信封: RSA-OAEP-SHA256 包装一次性 AES-256 密钥, AES-256-GCM 加密载荷。
 *
 * 请求加密、敏感响应解密与 Webhook 解密共用同一算法, 只有 AAD 组成与信封字段集不同。
 * 密文布局固定为 `IV(12) || 密文 || 认证标签(16)`。
 */
final class EnvelopeCodec
{
    /** 算法标识, 信封 `algorithm` 字段的唯一合法值。 */
    public const ALGORITHM = 'RSA-OAEP-AES-256-GCM';

    /** AES-GCM IV 长度 (字节)。 */
    public const IV_LENGTH = 12;

    /** AES-GCM 认证标签长度 (字节)。 */
    public const TAG_LENGTH = 16;

    /** AES 密钥长度 (字节)。 */
    public const KEY_LENGTH = 32;

    /** 平台侧的明文长度上限。 */
    public const MAX_PLAINTEXT_BYTES = 1048576;

    /** Webhook 信封的版本号, 恒为 1。 */
    public const WEBHOOK_ENVELOPE_VERSION = 1;

    private const CIPHER = 'aes-256-gcm';

    private function __construct()
    {
    }

    /**
     * 拼接 AAD: `requestId|routeTemplate|timestamp|keyId`。
     *
     * 任一分量为 null 时按空串处理, 分隔符仍然保留。
     */
    public static function buildAad(
        ?string $requestId,
        ?string $routeTemplate,
        ?string $timestamp,
        ?string $keyId,
    ): string {
        return implode('|', [
            $requestId ?? '',
            $routeTemplate ?? '',
            $timestamp ?? '',
            $keyId ?? '',
        ]);
    }

    /**
     * 生成 API 链信封 (含历史兼容字段 `encryptedPayload`)。
     *
     * @param string               $plaintext        明文字节 (通常是业务 JSON)
     * @param OpenSSLAsymmetricKey $recipientKey     接收方公钥
     * @param string               $keyFingerprint   接收方公钥指纹, 写入 `keyFingerprint`
     * @param string               $aad              已按 {@see EnvelopeCodec::buildAad()} 拼好的 AAD
     *
     * @return array<string, mixed> 可直接 json_encode 的信封结构
     *
     * @throws EnvelopeException 明文超限或加密失败
     */
    public static function seal(
        string $plaintext,
        OpenSSLAsymmetricKey $recipientKey,
        string $keyFingerprint,
        string $aad,
    ): array {
        [$encryptedKey, $ciphertext] = self::sealParts($plaintext, $recipientKey, $aad);

        return [
            'algorithm' => self::ALGORITHM,
            'keyFingerprint' => $keyFingerprint,
            'encryptedKey' => $encryptedKey,
            'ciphertext' => $ciphertext,
            'aad' => base64_encode($aad),
            'encryptedPayload' => $ciphertext,
        ];
    }

    /**
     * 生成 Webhook 形状的信封 (含 `envelopeVersion`, 不含 `encryptedPayload`)。
     *
     * 商户侧一般只需解密; 本方法供自测与联调模拟使用。
     *
     * @return array<string, mixed>
     */
    public static function sealWebhook(
        string $plaintext,
        OpenSSLAsymmetricKey $recipientKey,
        string $keyFingerprint,
        string $aad,
    ): array {
        [$encryptedKey, $ciphertext] = self::sealParts($plaintext, $recipientKey, $aad);

        return [
            'envelopeVersion' => self::WEBHOOK_ENVELOPE_VERSION,
            'algorithm' => self::ALGORITHM,
            'keyFingerprint' => $keyFingerprint,
            'encryptedKey' => $encryptedKey,
            'ciphertext' => $ciphertext,
            'aad' => base64_encode($aad),
        ];
    }

    /**
     * 解开信封并返回明文。
     *
     * 流程严格按协议: 校验结构 → 重建的 AAD 与信封回显值常量时间比对 →
     * RSA-OAEP 解出 AES 密钥 → 用**重建的** AAD 做 GCM 解密。
     * 绝不直接使用信封里回显的 `aad` 作为权威值。
     *
     * @param array<string, mixed> $envelope           信封结构 (API 链或 Webhook 形状均可)
     * @param OpenSSLAsymmetricKey $recipientPrivateKey 接收方私钥
     * @param string               $expectedAad         调用方本地重建的 AAD
     * @param string|null          $expectedFingerprint 期望的接收方公钥指纹; 传 null 跳过比对
     *
     * @throws EnvelopeException 结构非法、AAD 不匹配、指纹不匹配、解包失败或明文超限
     */
    public static function open(
        array $envelope,
        OpenSSLAsymmetricKey $recipientPrivateKey,
        string $expectedAad,
        ?string $expectedFingerprint = null,
    ): string {
        $algorithm = $envelope['algorithm'] ?? null;
        if (!is_string($algorithm) || $algorithm !== self::ALGORITHM) {
            throw new EnvelopeException('信封 algorithm 必须是 ' . self::ALGORITHM);
        }

        foreach (['encryptedKey', 'ciphertext', 'aad'] as $field) {
            if (!isset($envelope[$field]) || !is_string($envelope[$field]) || $envelope[$field] === '') {
                throw new EnvelopeException(sprintf('信封缺少必填字段 %s', $field));
            }
        }

        if ($expectedFingerprint !== null) {
            $fingerprint = $envelope['keyFingerprint'] ?? null;
            if (!is_string($fingerprint) || !hash_equals($expectedFingerprint, $fingerprint)) {
                throw new EnvelopeException(sprintf(
                    '信封 keyFingerprint 与本地密钥不一致: 期望 %s, 实际 %s',
                    $expectedFingerprint,
                    is_string($fingerprint) ? $fingerprint : '(缺失)'
                ));
            }
        }

        $echoedAad = base64_decode((string) $envelope['aad'], true);
        if ($echoedAad === false) {
            throw new EnvelopeException('信封 aad 不是合法 Base64');
        }
        if (!hash_equals($expectedAad, $echoedAad)) {
            throw new EnvelopeException('重建的 AAD 与信封回显的 aad 不一致, 拒绝解密');
        }

        $encryptedKey = base64_decode((string) $envelope['encryptedKey'], true);
        if ($encryptedKey === false) {
            throw new EnvelopeException('信封 encryptedKey 不是合法 Base64');
        }

        $blob = base64_decode((string) $envelope['ciphertext'], true);
        if ($blob === false) {
            throw new EnvelopeException('信封 ciphertext 不是合法 Base64');
        }
        if (strlen($blob) < self::IV_LENGTH + self::TAG_LENGTH) {
            throw new EnvelopeException('信封 ciphertext 长度不足以容纳 IV 与认证标签');
        }

        $aesKey = Oaep::decrypt($encryptedKey, $recipientPrivateKey);
        if (strlen($aesKey) !== self::KEY_LENGTH) {
            throw new EnvelopeException(sprintf('解出的 AES 密钥长度非法: %d 字节', strlen($aesKey)));
        }

        $iv = substr($blob, 0, self::IV_LENGTH);
        $tag = substr($blob, -self::TAG_LENGTH);
        $ciphertext = substr($blob, self::IV_LENGTH, strlen($blob) - self::IV_LENGTH - self::TAG_LENGTH);

        $plaintext = openssl_decrypt($ciphertext, self::CIPHER, $aesKey, OPENSSL_RAW_DATA, $iv, $tag, $expectedAad);
        if ($plaintext === false) {
            throw new EnvelopeException('AES-256-GCM 认证失败: 密文、AAD 或密钥不匹配');
        }

        if (strlen($plaintext) > self::MAX_PLAINTEXT_BYTES) {
            throw new EnvelopeException('解密后的明文超过 1 MiB 上限');
        }

        return $plaintext;
    }

    /**
     * 校验 Webhook 信封形状: 恰好 6 个字段, `envelopeVersion` 为 1, 无 `encryptedPayload`。
     *
     * @param array<string, mixed> $envelope
     *
     * @throws EnvelopeException
     */
    public static function assertWebhookShape(array $envelope): void
    {
        $required = ['envelopeVersion', 'algorithm', 'keyFingerprint', 'encryptedKey', 'ciphertext', 'aad'];
        foreach ($required as $field) {
            if (!array_key_exists($field, $envelope)) {
                throw new EnvelopeException(sprintf('Webhook 信封缺少必填字段 %s', $field));
            }
        }

        $extra = array_diff(array_keys($envelope), $required);
        if ($extra !== []) {
            throw new EnvelopeException('Webhook 信封含未定义字段: ' . implode(', ', $extra));
        }

        if (($envelope['envelopeVersion'] ?? null) !== self::WEBHOOK_ENVELOPE_VERSION) {
            throw new EnvelopeException('Webhook 信封 envelopeVersion 必须恰为 1');
        }
    }

    /**
     * 计算 PEM 公钥的指纹, 见 {@see Keys::fingerprintFromPem()}。
     */
    public static function fingerprintFromPem(string $publicKeyPem): string
    {
        return Keys::fingerprintFromPem($publicKeyPem);
    }

    /**
     * @return array{0: string, 1: string} [Base64 encryptedKey, Base64 ciphertext]
     */
    private static function sealParts(string $plaintext, OpenSSLAsymmetricKey $recipientKey, string $aad): array
    {
        if (strlen($plaintext) > self::MAX_PLAINTEXT_BYTES) {
            throw new EnvelopeException('明文超过 1 MiB 上限');
        }

        $aesKey = random_bytes(self::KEY_LENGTH);
        $iv = random_bytes(self::IV_LENGTH);

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
            self::TAG_LENGTH
        );
        if ($ciphertext === false) {
            throw new EnvelopeException('AES-256-GCM 加密失败');
        }

        return [
            base64_encode(Oaep::encrypt($aesKey, $recipientKey)),
            base64_encode($iv . $ciphertext . $tag),
        ];
    }
}
