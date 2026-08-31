<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Error;

/**
 * 平台对外错误码 (`域.名称`)。仅收录与商户 API 认证/协议相关的码。
 *
 * 未收录的码由 {@see PublicErrorCode::tryFromCode()} 返回 null, 调用方应改用
 * {@see \SlaunchX\Plutus\Exception\ApiException::rawErrorCode()} 取原始字符串。
 */
enum PublicErrorCode: string
{
    case API_KEY_MISSING = 'API.KEY_MISSING';
    case API_KEY_INVALID = 'API.KEY_INVALID';
    case API_KEY_DISABLED = 'API.KEY_DISABLED';
    case API_KEY_LOCKED = 'API.KEY_LOCKED';
    case API_TIMESTAMP_REQUIRED = 'API.TIMESTAMP_REQUIRED';
    case API_TIMESTAMP_INVALID = 'API.TIMESTAMP_INVALID';
    case API_TIMESTAMP_EXPIRED = 'API.TIMESTAMP_EXPIRED';
    case API_VERSION_REQUIRED = 'API.VERSION_REQUIRED';
    case API_VERSION_UNSUPPORTED = 'API.VERSION_UNSUPPORTED';
    case API_ENDPOINT_RETIRED = 'API.ENDPOINT_RETIRED';
    case API_NONCE_REQUIRED = 'API.NONCE_REQUIRED';
    case API_NONCE_INVALID = 'API.NONCE_INVALID';
    case API_NONCE_REUSED = 'API.NONCE_REUSED';
    case API_SIGNATURE_REQUIRED = 'API.SIGNATURE_REQUIRED';
    case API_SIGNATURE_ALGORITHM_INVALID = 'API.SIGNATURE_ALGORITHM_INVALID';
    case API_SIGNATURE_INVALID = 'API.SIGNATURE_INVALID';
    case API_IP_NOT_ALLOWED = 'API.IP_NOT_ALLOWED';
    case API_WORKSPACE_REQUIRED = 'API.WORKSPACE_REQUIRED';
    case API_WORKSPACE_UNAVAILABLE = 'API.WORKSPACE_UNAVAILABLE';
    case ACCESS_PERMISSION_DENIED = 'ACCESS.PERMISSION_DENIED';
    case SECURE_CHANNEL_INVALID_PAYLOAD = 'SECURE_CHANNEL.INVALID_PAYLOAD';
    case REQUEST_RATE_LIMITED = 'REQUEST.RATE_LIMITED';
    case REQUEST_CONFLICT = 'REQUEST.CONFLICT';
    case REQUEST_STALE_VERSION = 'REQUEST.STALE_VERSION';
    case VALIDATION_INVALID_PARAMETER = 'VALIDATION.INVALID_PARAMETER';
    case RESOURCE_NOT_FOUND = 'RESOURCE.NOT_FOUND';
    case SYSTEM_INTERNAL_ERROR = 'SYSTEM.INTERNAL_ERROR';

    /**
     * 宽松解析: 未知码返回 null 而不抛异常。
     */
    public static function tryFromCode(?string $code): ?self
    {
        if ($code === null || $code === '') {
            return null;
        }

        return self::tryFrom($code);
    }

    /**
     * 错误族 (码的域部分), 如 `API` / `ACCESS` / `SECURE_CHANNEL`。
     */
    public function domain(): string
    {
        return explode('.', $this->value, 2)[0];
    }

    /**
     * 是否属于凭据/签名类失败 (定位到密钥、时钟、nonce 或规范串)。
     */
    public function isAuthenticationFailure(): bool
    {
        return match ($this) {
            self::API_KEY_MISSING,
            self::API_KEY_INVALID,
            self::API_KEY_DISABLED,
            self::API_KEY_LOCKED,
            self::API_TIMESTAMP_REQUIRED,
            self::API_TIMESTAMP_INVALID,
            self::API_TIMESTAMP_EXPIRED,
            self::API_NONCE_REQUIRED,
            self::API_NONCE_INVALID,
            self::API_NONCE_REUSED,
            self::API_SIGNATURE_REQUIRED,
            self::API_SIGNATURE_ALGORITHM_INVALID,
            self::API_SIGNATURE_INVALID => true,
            default => false,
        };
    }

    /**
     * SPEC 第 13 节的重试建议: 是否值得在重新签名或退避后重试。
     *
     * 注意 `API.TIMESTAMP_EXPIRED` 与 `API.NONCE_REUSED` 必须重新生成
     * timestamp + nonce 并重新签名, 不能复用原签名头。
     */
    public function isRetryable(): bool
    {
        return match ($this) {
            self::API_TIMESTAMP_EXPIRED,
            self::API_NONCE_REUSED,
            self::REQUEST_RATE_LIMITED,
            self::SYSTEM_INTERNAL_ERROR => true,
            default => false,
        };
    }
}
