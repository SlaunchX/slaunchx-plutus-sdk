<?php

declare(strict_types=1);

namespace SlaunchX\Plutus;

use OpenSSLAsymmetricKey;
use SlaunchX\Plutus\Exception\ConfigurationException;
use SlaunchX\Plutus\Exception\SignatureException;
use SlaunchX\Plutus\Model\SignedRequest;
use SlaunchX\Plutus\Support\CanonicalQuery;
use SlaunchX\Plutus\Support\Keys;
use SlaunchX\Plutus\Support\Nonce;

/**
 * 请求签名: 拼接 8 行规范串并用 `merchant_auth` 私钥做 RSA-SHA256 (PKCS#1 v1.5) 签名。
 */
final class RequestSigner
{
    /** 空 body 的 SHA-256 摘要, 小写 hex。 */
    public const EMPTY_BODY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    /** `X-Signature-Algorithm` 的字面量, 不参与规范串。 */
    public const SIGNATURE_ALGORITHM = 'RSA-SHA256';

    /** 一律使用空 body 摘要的方法。 */
    private const FORCED_EMPTY_BODY_METHODS = ['GET', 'HEAD', 'DELETE'];

    public function __construct(private readonly PlutusConfig $config)
    {
    }

    /**
     * 规范化 query 串, 见 {@see CanonicalQuery::canonicalize()}。
     */
    public static function canonicalizeQuery(?string $rawQuery): string
    {
        return CanonicalQuery::canonicalize($rawQuery);
    }

    /**
     * 判断该方法是否强制使用空 body 摘要 (`GET` / `HEAD` / `DELETE`)。
     */
    public static function isForcedEmptyBodyMethod(string $method): bool
    {
        return in_array(strtoupper($method), self::FORCED_EMPTY_BODY_METHODS, true);
    }

    /**
     * 计算规范串第 8 行的 body 摘要 (小写 hex)。
     *
     * `GET` / `HEAD` / `DELETE` 无论是否携带 body, 一律返回空 body 摘要。
     *
     * @param string      $method HTTP 方法
     * @param string|null $body   实际发送的 body 字节
     */
    public static function bodyDigestHex(string $method, ?string $body): string
    {
        if (self::isForcedEmptyBodyMethod($method) || $body === null || $body === '') {
            return self::EMPTY_BODY_SHA256;
        }

        return hash('sha256', $body);
    }

    /**
     * 拼接 8 行请求规范串 (LF 连接, 无尾换行)。
     *
     * @param string      $canonicalQuery 已规范化的 query, 无 query 时传空串
     * @param string|null $idempotencyKey 不发送 `X-Idempotency-Key` 时传 null
     */
    public static function buildCanonicalString(
        string $method,
        string $externalPath,
        string $canonicalQuery,
        string $timestamp,
        string $nonce,
        string $apiVersion,
        ?string $idempotencyKey,
        string $bodyHash,
    ): string {
        return implode("\n", [
            strtoupper($method),
            $externalPath,
            $canonicalQuery,
            $timestamp,
            $nonce,
            $apiVersion,
            $idempotencyKey ?? '',
            $bodyHash,
        ]);
    }

    /**
     * 计算规范串自身的 SHA-256 (小写 hex), 即响应规范串第 2 行。
     */
    public static function canonicalStringDigest(string $canonicalString): string
    {
        return hash('sha256', $canonicalString);
    }

    /**
     * 用给定私钥对规范串签名, 返回标准 Base64。
     *
     * @throws SignatureException openssl 签名失败
     */
    public static function signCanonicalString(string $canonicalString, OpenSSLAsymmetricKey $privateKey): string
    {
        $signature = null;
        if (!openssl_sign($canonicalString, $signature, $privateKey, OPENSSL_ALGO_SHA256) || $signature === null) {
            throw new SignatureException('请求签名失败: openssl_sign 返回错误');
        }

        return base64_encode($signature);
    }

    /**
     * 验证规范串签名, 用于自检与测试。
     */
    public static function verifyCanonicalString(
        string $canonicalString,
        string $signatureBase64,
        OpenSSLAsymmetricKey $publicKey,
    ): bool {
        $signature = base64_decode($signatureBase64, true);
        if ($signature === false) {
            return false;
        }

        return openssl_verify($canonicalString, $signature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * 对一次请求完成规范化、签名与请求头组装。
     *
     * body 必须是**已经序列化完毕的字节**: 摘要与实际发送必须使用同一个字符串,
     * 不得在调用方再次序列化。
     *
     * @param string                $method         HTTP 方法
     * @param string                $externalPath   外部路径 (不含链/版本/门户前缀, 不含 query)
     * @param string|null           $rawQuery       原始 query 串, 不含前导 `?`
     * @param string|null           $body           已序列化的 body 字节
     * @param string|null           $idempotencyKey `X-Idempotency-Key`; null 表示不发送
     * @param string|null           $requestId      `X-Request-Id`; 不参与请求签名, 但加密端点必填
     * @param array<string, string> $extraHeaders   附加请求头, 覆盖同名默认值
     * @param string|null           $timestamp      覆盖时间戳 (Unix 毫秒), 仅测试用
     * @param string|null           $nonce          覆盖 nonce, 仅测试用
     *
     * @throws ConfigurationException 外部路径非法或 nonce 不满足平台约束
     */
    public function sign(
        string $method,
        string $externalPath,
        ?string $rawQuery = null,
        ?string $body = null,
        ?string $idempotencyKey = null,
        ?string $requestId = null,
        array $extraHeaders = [],
        ?string $timestamp = null,
        ?string $nonce = null,
    ): SignedRequest {
        $method = strtoupper($method);
        if ($externalPath === '' || $externalPath[0] !== '/') {
            throw new ConfigurationException('外部路径必须以 "/" 开头, 且不含链/版本/门户前缀');
        }
        if (str_starts_with($externalPath, '/api/') || preg_match('#^/v\d+/#', $externalPath) === 1) {
            throw new ConfigurationException('外部路径不得包含 /api 或 /v{N} 前缀, 版本走 X-API-VERSION 头');
        }

        $timestamp ??= $this->config->currentTimestampMillis();
        $nonce ??= $this->config->generateNonce();
        if (!Nonce::isValid($nonce)) {
            throw new ConfigurationException('nonce 不满足平台约束 ^[A-Za-z0-9._~-]{16,128}$');
        }

        $canonicalQuery = self::canonicalizeQuery($rawQuery);
        $bodyBytes = $body ?? '';
        $bodyHash = self::bodyDigestHex($method, $bodyBytes);

        $canonicalString = self::buildCanonicalString(
            $method,
            $externalPath,
            $canonicalQuery,
            $timestamp,
            $nonce,
            $this->config->apiVersion,
            $idempotencyKey,
            $bodyHash,
        );

        $signature = self::signCanonicalString($canonicalString, $this->config->merchantAuthPrivateKey());

        $headers = [
            'X-Api-Key' => $this->config->apiKey,
            'X-API-VERSION' => $this->config->apiVersion,
            'X-Timestamp' => $timestamp,
            'X-Nonce' => $nonce,
            'X-Signature' => $signature,
            'X-Signature-Algorithm' => self::SIGNATURE_ALGORITHM,
        ];
        if ($idempotencyKey !== null) {
            $headers['X-Idempotency-Key'] = $idempotencyKey;
        }
        if ($requestId !== null) {
            $headers['X-Request-Id'] = $requestId;
        }
        foreach ($extraHeaders as $name => $value) {
            $headers[$name] = $value;
        }

        return new SignedRequest(
            $method,
            $externalPath,
            $canonicalQuery,
            $rawQuery,
            $timestamp,
            $nonce,
            $this->config->apiVersion,
            $idempotencyKey,
            $bodyBytes,
            $bodyHash,
            $canonicalString,
            self::canonicalStringDigest($canonicalString),
            $signature,
            $headers,
        );
    }

    /**
     * 商户认证公钥指纹, 便于与平台登记值核对。
     */
    public function merchantAuthKeyFingerprint(): string
    {
        return Keys::fingerprint($this->config->merchantAuthPrivateKey());
    }
}
