<?php

declare(strict_types=1);

namespace SlaunchX\Plutus;

use Closure;
use OpenSSLAsymmetricKey;
use SlaunchX\Plutus\Exception\ConfigurationException;
use SlaunchX\Plutus\Support\Keys;
use SlaunchX\Plutus\Support\Nonce;

/**
 * SDK 配置。构造后不可变, 密钥句柄按需惰性装载并缓存。
 *
 * 四把密钥职责严格分离, 不得混用:
 * - `merchant_auth` 私钥: 对请求规范串签名 (必填);
 * - `platform_auth` 公钥: 校验响应签名与 Webhook 签名;
 * - `merchant_enc` 私钥: 解密敏感响应与 Webhook 载荷;
 * - `platform_enc` 公钥: 加密请求体。
 */
final class PlutusConfig
{
    /** @var array<string, OpenSSLAsymmetricKey> */
    private array $keyCache = [];

    /**
     * @param string        $baseUrl                     商户 API 基址, 必须是**对外 CONSUMER API 域名**
     *                                                   (如 `https://consumer-api.example.com`)。
     *                                                   不能填源站地址, 也不能自行拼接
     *                                                   `/prometheus`、`/api/v1/consumer` 等内部前缀——
     *                                                   这些改写由边缘完成, SDK 只对外部路径签名,
     *                                                   baseUrl 配错会导致签名 PATH 与实际请求路径不一致
     *                                                   而验签失败。
     * @param string        $apiKey                      `X-Api-Key` 的值 (API Key 业务 ID)
     * @param string        $merchantAuthPrivateKeyPem   商户认证私钥 (PKCS#8 PEM)
     * @param string|null   $platformAuthPublicKeyPem    平台认证公钥 (SPKI PEM), 响应验签与 Webhook 验签所需
     * @param string|null   $merchantEncPrivateKeyPem    商户加密私钥 (PKCS#8 PEM), 敏感响应与 Webhook 解密所需
     * @param string|null   $platformEncPublicKeyPem     平台加密公钥 (SPKI PEM), 请求加密所需
     * @param string|null   $platformEncKeyId            平台加密公钥指纹; 为 null 时从 PEM 推导
     * @param string|null   $platformAuthKeyId           平台认证公钥指纹; 非 null 时与响应头 `X-Platform-Signing-Key-Id` 比对
     * @param string        $apiVersion                  `X-API-VERSION` 的值, 当前恒为 `1`
     * @param bool          $verifyResponseSignature     是否校验响应签名, 默认开启
     * @param bool          $requireSignatureOnErrorResponses 非 2xx 响应缺少 `X-Response-Signature` 时是否也强制验签, 默认关闭。
     *                                                   与之无关: HTTP 2xx 缺签名头一律抛
     *                                                   {@see \SlaunchX\Plutus\Exception\ResponseSignatureException},
     *                                                   不受本开关影响; 非 2xx 缺签名头默认放行
     *                                                   (`ApiResponse::$signatureVerified === false`),
     *                                                   打开本开关后非 2xx 缺签名头同样抛异常
     * @param bool          $throwOnErrorStatus          响应判定为失败时是否抛出类型化异常, 默认开启
     * @param bool          $sendCanonicalQuery          发送规范化后的 query 而非原始串, 默认开启
     * @param int           $connectTimeoutMs            连接超时 (毫秒)
     * @param int           $timeoutMs                   整体超时 (毫秒)
     * @param string        $userAgent                   `User-Agent` 请求头
     * @param int           $webhookTimestampToleranceMs Webhook 时间戳容差 (毫秒); 0 表示不校验
     * @param Closure|null  $nonceGenerator              自定义 nonce 生成器 `fn(): string`
     * @param Closure|null  $clock                       自定义时钟 `fn(): string`, 返回 Unix 毫秒十进制串
     * @param array<int, mixed> $curlOptions             追加的 cURL 选项, 覆盖 SDK 默认值
     * @param bool          $strictEncryptedRouteValidation 加密请求的外部路径不在
     *                                                   {@see \SlaunchX\Plutus\EncryptedRoutes} 已知表中时
     *                                                   是否直接拒绝, 默认 `false` (仅记录一条 `error_log`
     *                                                   提示, 不阻断请求)。设计取舍见
     *                                                   {@see \SlaunchX\Plutus\EncryptedRoutes} 类注释。
     */
    public function __construct(
        public readonly string $baseUrl,
        public readonly string $apiKey,
        public readonly string $merchantAuthPrivateKeyPem,
        public readonly ?string $platformAuthPublicKeyPem = null,
        public readonly ?string $merchantEncPrivateKeyPem = null,
        public readonly ?string $platformEncPublicKeyPem = null,
        public readonly ?string $platformEncKeyId = null,
        public readonly ?string $platformAuthKeyId = null,
        public readonly string $apiVersion = '1',
        public readonly bool $verifyResponseSignature = true,
        public readonly bool $requireSignatureOnErrorResponses = false,
        public readonly bool $throwOnErrorStatus = true,
        public readonly bool $sendCanonicalQuery = true,
        public readonly int $connectTimeoutMs = 5000,
        public readonly int $timeoutMs = 30000,
        public readonly string $userAgent = 'slaunchx-plutus-php-sdk/1.0',
        public readonly int $webhookTimestampToleranceMs = 0,
        public readonly ?Closure $nonceGenerator = null,
        public readonly ?Closure $clock = null,
        public readonly array $curlOptions = [],
        public readonly bool $strictEncryptedRouteValidation = false,
    ) {
        if ($apiKey === '') {
            throw new ConfigurationException('apiKey 不能为空');
        }
        if ($apiVersion === '') {
            throw new ConfigurationException('apiVersion 不能为空, 当前协议恒为 "1"');
        }
        if ($merchantAuthPrivateKeyPem === '') {
            throw new ConfigurationException('merchantAuthPrivateKeyPem 不能为空');
        }
        if ($baseUrl !== '' && !preg_match('#^https?://#i', $baseUrl)) {
            throw new ConfigurationException('baseUrl 必须以 http:// 或 https:// 开头');
        }
    }

    /**
     * 商户认证私钥句柄。
     */
    public function merchantAuthPrivateKey(): OpenSSLAsymmetricKey
    {
        return $this->keyCache['merchant_auth'] ??= Keys::loadPrivateKey(
            $this->merchantAuthPrivateKeyPem,
            'merchant_auth 私钥'
        );
    }

    /**
     * 平台认证公钥句柄。
     *
     * @throws ConfigurationException 未配置 `platformAuthPublicKeyPem`
     */
    public function platformAuthPublicKey(): OpenSSLAsymmetricKey
    {
        if ($this->platformAuthPublicKeyPem === null) {
            throw new ConfigurationException('未配置 platformAuthPublicKeyPem, 无法校验响应或 Webhook 签名');
        }

        return $this->keyCache['platform_auth'] ??= Keys::loadPublicKey(
            $this->platformAuthPublicKeyPem,
            'platform_auth 公钥'
        );
    }

    /**
     * 商户加密私钥句柄。
     *
     * @throws ConfigurationException 未配置 `merchantEncPrivateKeyPem`
     */
    public function merchantEncPrivateKey(): OpenSSLAsymmetricKey
    {
        if ($this->merchantEncPrivateKeyPem === null) {
            throw new ConfigurationException('未配置 merchantEncPrivateKeyPem, 无法解密敏感响应或 Webhook');
        }

        return $this->keyCache['merchant_enc'] ??= Keys::loadPrivateKey(
            $this->merchantEncPrivateKeyPem,
            'merchant_enc 私钥'
        );
    }

    /**
     * 平台加密公钥句柄。
     *
     * @throws ConfigurationException 未配置 `platformEncPublicKeyPem`
     */
    public function platformEncPublicKey(): OpenSSLAsymmetricKey
    {
        if ($this->platformEncPublicKeyPem === null) {
            throw new ConfigurationException('未配置 platformEncPublicKeyPem, 无法加密请求体');
        }

        return $this->keyCache['platform_enc'] ??= Keys::loadPublicKey(
            $this->platformEncPublicKeyPem,
            'platform_enc 公钥'
        );
    }

    /**
     * `X-Platform-Encryption-Key-Id` 的值: 平台加密公钥指纹。
     *
     * 优先使用显式配置的 `platformEncKeyId`, 否则从平台加密公钥 PEM 推导。
     */
    public function resolvePlatformEncKeyId(): string
    {
        if ($this->platformEncKeyId !== null && $this->platformEncKeyId !== '') {
            return $this->platformEncKeyId;
        }

        return Keys::fingerprint($this->platformEncPublicKey());
    }

    /**
     * 商户加密公钥指纹, 用于与信封 `keyFingerprint` 比对。
     */
    public function merchantEncKeyFingerprint(): string
    {
        return Keys::fingerprint($this->merchantEncPrivateKey());
    }

    /**
     * 商户认证公钥指纹, 用于与平台登记值核对。
     */
    public function merchantAuthKeyFingerprint(): string
    {
        return Keys::fingerprint($this->merchantAuthPrivateKey());
    }

    /**
     * 当前时间戳, Unix 毫秒十进制字符串。
     */
    public function currentTimestampMillis(): string
    {
        if ($this->clock !== null) {
            return (string) ($this->clock)();
        }

        return (string) (int) round(microtime(true) * 1000);
    }

    /**
     * 生成一次性 nonce。
     */
    public function generateNonce(): string
    {
        if ($this->nonceGenerator !== null) {
            return (string) ($this->nonceGenerator)();
        }

        return Nonce::generate();
    }
}
