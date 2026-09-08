<?php

declare(strict_types=1);

namespace SlaunchX\Plutus;

use OpenSSLAsymmetricKey;
use SlaunchX\Plutus\Exception\ResponseSignatureException;
use SlaunchX\Plutus\Http\RawResponse;
use SlaunchX\Plutus\Model\SignedRequest;
use SlaunchX\Plutus\Support\Keys;

/**
 * 响应验签: 默认按 10 行请求绑定规范串，PRODUCT_V1 按后端的 5 行规范串。
 *
 * 默认协议第 2 行的请求绑定摘要必须由 SDK 本地计算 (取自 {@see SignedRequest}),
 * 绝不能从响应头读取, 否则绑定失效。
 */
final class ResponseVerifier
{
    /** 响应规范串首行字面量。 */
    public const CANONICAL_PREFIX = 'SLAUNCHX-API-RESPONSE-V1';

    /** 空 body 的 SHA-256 摘要, 小写 hex。 */
    public const EMPTY_BODY_SHA256 = RequestSigner::EMPTY_BODY_SHA256;

    public function __construct(private readonly PlutusConfig $config)
    {
    }

    /**
     * 拼接响应规范串 (LF 连接, 无尾换行)。默认 10 行，PRODUCT_V1 为 5 行。
     *
     * @param string      $requestCanonicalSha256 请求规范串的 SHA-256, 小写 hex
     * @param string|null $operationId            响应头 `X-Operation-Id`; 无则传 null
     * @param string|null $requestId              响应头 `X-Request-Id`; 无则传 null
     * @param string|null $contentType            响应头 `Content-Type` 原值, 不得归一化
     * @param string      $responseBodyHash       响应体 SHA-256, 小写 hex
     */
    public static function buildCanonicalString(
        string $requestCanonicalSha256,
        string $apiVersion,
        string $externalPath,
        ?string $operationId,
        ?string $requestId,
        int $httpStatus,
        ?string $contentType,
        string $responseTimestamp,
        string $responseBodyHash,
        ProtocolProfile $protocolProfile = ProtocolProfile::REQUEST_BOUND_V1,
    ): string {
        if ($protocolProfile === ProtocolProfile::PRODUCT_V1) {
            return implode("\n", [
                $requestId ?? '', (string) $httpStatus, $contentType ?? '',
                $responseTimestamp, $responseBodyHash,
            ]);
        }
        return implode("\n", [
            self::CANONICAL_PREFIX,
            $requestCanonicalSha256,
            $apiVersion,
            $externalPath,
            $operationId ?? '',
            $requestId ?? '',
            (string) $httpStatus,
            $contentType ?? '',
            $responseTimestamp,
            $responseBodyHash,
        ]);
    }

    /**
     * 计算响应体摘要 (小写 hex)。空体使用空 body 摘要。
     */
    public static function bodyDigestHex(string $body): string
    {
        return $body === '' ? self::EMPTY_BODY_SHA256 : hash('sha256', $body);
    }

    /**
     * 用平台认证公钥校验规范串签名。
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
     * 校验一次响应。
     *
     * 行为受配置控制:
     * - `verifyResponseSignature = false`: 直接返回 false, 不做任何校验;
     * - 响应带 `X-Response-Signature`: 强制验签, 失败抛异常并丢弃响应体;
     * - HTTP 2xx 且缺签名头: 抛异常;
     * - 非 2xx 且缺签名头: 放行并返回 false (调用方可从
     *   `ApiResponse::$signatureVerified` 看到未验签), 除非
     *   `requireSignatureOnErrorResponses = true`, 此时同样抛异常。
     *
     * 缺签名头的处理属于 SPEC「SDK 约定 (非平台契约)」一节: 平台契约只说明认证失败等
     * 场景的响应可能不带签名头, **并未穷举无签名的状态码集合**, 因此 SDK 不做状态码
     * 白名单, 改用"2xx 必须有签名、非 2xx 默认放行"的统一策略。
     *
     * @return bool 是否实际完成了验签
     *
     * @throws ResponseSignatureException 验签失败、应有签名而缺失、或缺少平台认证公钥
     */
    public function verify(SignedRequest $request, RawResponse $response): bool
    {
        if (!$this->config->verifyResponseSignature) {
            return false;
        }

        $signature = $response->header('X-Response-Signature');
        if ($signature === null || $signature === '') {
            $isSuccessStatus = $response->statusCode >= 200 && $response->statusCode < 300;
            if (!$isSuccessStatus && !$this->config->requireSignatureOnErrorResponses) {
                return false;
            }

            throw new ResponseSignatureException(sprintf(
                '响应缺少 X-Response-Signature (HTTP %d)',
                $response->statusCode
            ));
        }

        $algorithm = $response->header('X-Response-Signature-Algorithm');
        if ($algorithm !== null && strcasecmp(trim($algorithm), RequestSigner::SIGNATURE_ALGORITHM) !== 0) {
            throw new ResponseSignatureException('响应签名算法不是 RSA-SHA256: ' . $algorithm);
        }

        $timestamp = $response->header('X-Response-Timestamp');
        if ($timestamp === null || $timestamp === '') {
            throw new ResponseSignatureException('响应缺少 X-Response-Timestamp, 无法重建规范串');
        }

        $publicKeyPem = $this->config->platformAuthPublicKeyPem;
        if ($publicKeyPem === null) {
            throw new ResponseSignatureException(
                '未配置 platformAuthPublicKeyPem, 无法验签; 如确需关闭请显式设置 verifyResponseSignature = false'
            );
        }

        $responseRequestId = $response->header('X-Request-Id');
        if ($responseRequestId === null && $this->config->protocolProfile === ProtocolProfile::PRODUCT_V1) {
            // Use only this request's retained ID; the full RSA signature must still verify.
            $responseRequestId = $request->headers['X-Request-Id'] ?? null;
            if ($responseRequestId === null || trim($responseRequestId) === '') {
                throw new ResponseSignatureException('product 响应缺少 X-Request-Id，且本次请求未保留该值');
            }
        }

        $canonicalString = self::buildCanonicalString(
            $request->requestCanonicalSha256,
            $request->apiVersion,
            $request->externalPath,
            $response->header('X-Operation-Id'),
            $responseRequestId,
            $response->statusCode,
            $response->header('Content-Type'),
            $timestamp,
            self::bodyDigestHex($response->body),
            $this->config->protocolProfile,
        );

        if (!self::verifyCanonicalString($canonicalString, $signature, $this->config->platformAuthPublicKey())) {
            throw new ResponseSignatureException(
                '响应验签失败, 响应体已按安全事故处理丢弃; 规范串: ' . str_replace("\n", '\\n', $canonicalString)
            );
        }

        $expectedKeyId = $this->config->platformAuthKeyId;
        $actualKeyId = $response->header('X-Platform-Signing-Key-Id');
        if ($expectedKeyId !== null && $actualKeyId !== null && !hash_equals($expectedKeyId, $actualKeyId)) {
            throw new ResponseSignatureException(sprintf(
                '响应签名密钥指纹不匹配: 期望 %s, 实际 %s',
                $expectedKeyId,
                $actualKeyId
            ));
        }

        return true;
    }

    /**
     * 平台认证公钥指纹, 便于与响应头 `X-Platform-Signing-Key-Id` 核对。
     */
    public function platformAuthKeyFingerprint(): string
    {
        return Keys::fingerprint($this->config->platformAuthPublicKey());
    }
}
