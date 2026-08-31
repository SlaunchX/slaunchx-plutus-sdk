<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Exception;

use SlaunchX\Plutus\Error\PublicErrorCode;
use SlaunchX\Plutus\Model\ApiResponse;

/**
 * 平台返回的业务/协议错误。按错误码与状态码派生为更精确的子类。
 *
 * 触发条件是 {@see ApiResponse::isSuccess()} 判定为失败, 而非 HTTP 状态码 >= 400:
 * HTTP 200 且包络 `success:false` 同样抛出本异常族。
 * 错误码是包络的 `code` 字段, 可能是网关码 `域.名称`, 也可能是业务层的数字字符串
 * (如 `"4022"`); 后者不在 {@see PublicErrorCode} 中收录时按 HTTP 状态码回退选型,
 * 原值始终可从 {@see ApiException::rawErrorCode()} 取得。
 */
class ApiException extends PlutusException
{
    public function __construct(
        string $message,
        private readonly int $statusCode,
        private readonly ?PublicErrorCode $errorCode,
        private readonly ?string $rawErrorCode,
        private readonly ApiResponse $response,
    ) {
        parent::__construct($message);
    }

    /**
     * 依据状态码与错误码构造对应的子类实例。
     */
    public static function fromResponse(ApiResponse $response): self
    {
        $raw = $response->errorCode();
        $code = PublicErrorCode::tryFromCode($raw);
        $status = $response->statusCode;
        $message = $response->errorMessage() ?? ('HTTP ' . $status);
        $label = $raw !== null && $raw !== '' ? $raw . ': ' . $message : $message;

        $class = self::resolveClass($status, $code);

        /** @var self $instance */
        $instance = new $class($label, $status, $code, $raw, $response);

        return $instance;
    }

    /**
     * 先按已收录的错误码选型; 未收录 (含 4xxx/5xxx 数字业务码) 时按 HTTP 状态码回退。
     * HTTP 2xx 且业务判定失败时没有更精确的状态线索, 回退为基类 {@see ApiException}。
     *
     * @return class-string<self>
     */
    private static function resolveClass(int $status, ?PublicErrorCode $code): string
    {
        if ($code !== null) {
            if ($code === PublicErrorCode::SECURE_CHANNEL_INVALID_PAYLOAD) {
                return SecureChannelException::class;
            }
            if ($code === PublicErrorCode::REQUEST_RATE_LIMITED) {
                return RateLimitException::class;
            }
            if ($code->isAuthenticationFailure()) {
                return AuthenticationException::class;
            }
            if (
                $code === PublicErrorCode::ACCESS_PERMISSION_DENIED
                || $code === PublicErrorCode::API_IP_NOT_ALLOWED
                || $code === PublicErrorCode::API_WORKSPACE_UNAVAILABLE
            ) {
                return PermissionException::class;
            }
            if ($code === PublicErrorCode::RESOURCE_NOT_FOUND) {
                return NotFoundException::class;
            }
            if (
                $code === PublicErrorCode::REQUEST_CONFLICT
                || $code === PublicErrorCode::REQUEST_STALE_VERSION
            ) {
                return ConflictException::class;
            }
            if (
                $code === PublicErrorCode::VALIDATION_INVALID_PARAMETER
                || $code === PublicErrorCode::API_VERSION_REQUIRED
                || $code === PublicErrorCode::API_VERSION_UNSUPPORTED
                || $code === PublicErrorCode::API_WORKSPACE_REQUIRED
            ) {
                return ValidationException::class;
            }
            if ($code === PublicErrorCode::SYSTEM_INTERNAL_ERROR) {
                return ServerException::class;
            }
        }

        return match (true) {
            $status === 401 => AuthenticationException::class,
            $status === 403 => PermissionException::class,
            $status === 404 => NotFoundException::class,
            $status === 409 => ConflictException::class,
            $status === 429 => RateLimitException::class,
            $status >= 500 => ServerException::class,
            $status >= 400 => ValidationException::class,
            default => self::class,
        };
    }

    /**
     * HTTP 状态码。
     */
    public function statusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * 已知的平台错误码枚举; 未收录时为 null。
     */
    public function errorCode(): ?PublicErrorCode
    {
        return $this->errorCode;
    }

    /**
     * 平台返回的错误码原始字符串 (含未收录的码与 `GATEWAY_*` 阶段码)。
     */
    public function rawErrorCode(): ?string
    {
        return $this->rawErrorCode;
    }

    /**
     * 完整响应对象, 含原始 body 与响应头。
     */
    public function response(): ApiResponse
    {
        return $this->response;
    }

    /**
     * 平台回显的请求关联 ID (`X-Request-Id`), 便于向平台报障时定位。
     */
    public function requestId(): ?string
    {
        return $this->response->requestId();
    }

    /**
     * 依据 SPEC 第 13 节的重试建议判断是否值得重试。重试必须重新生成
     * timestamp + nonce 并重新签名。
     */
    public function isRetryable(): bool
    {
        if ($this->errorCode !== null) {
            return $this->errorCode->isRetryable();
        }

        return $this->statusCode === 429 || $this->statusCode >= 500;
    }
}
