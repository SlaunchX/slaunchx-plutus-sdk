<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Model;

use SlaunchX\Plutus\Http\RawResponse;

/**
 * 统一响应对象: 原始响应 + 已解析的 JSON + 本次请求的签名快照 + 验签结果。
 *
 * 平台统一响应包络形如:
 *
 * ```json
 * {"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{}}
 * ```
 *
 * `success` 是布尔字段, 是成功与否的唯一权威 (见 {@see ApiResponse::isSuccess()});
 * `code` 是字符串, 成功族见 {@see ResultCodes::SUCCESS_CODES}, 失败时为网关码 `域.名称`
 * 或业务层的数字字符串 (如 `"4022"`)。
 *
 * 早期/非标准响应的字段名未固化, 因此 {@see ApiResponse::errorCode()} /
 * {@see ApiResponse::errorMessage()} 在权威字段之外保留次级回退。
 */
final class ApiResponse
{
    /** HTTP 状态码。 */
    public readonly int $statusCode;

    /** @var array<string, string> 保留线格式大小写的响应头 */
    public readonly array $headers;

    /** 原始响应体字节。响应验签对该字节串求摘要。 */
    public readonly string $rawBody;

    /** @var array<string, mixed>|null 解析后的 JSON; body 非 JSON 对象时为 null */
    public readonly ?array $json;

    public function __construct(
        public readonly SignedRequest $request,
        private readonly RawResponse $raw,
        public readonly bool $signatureVerified,
    ) {
        $this->statusCode = $raw->statusCode;
        $this->headers = $raw->headers;
        $this->rawBody = $raw->body;

        $decoded = null;
        if ($raw->body !== '') {
            $parsed = json_decode($raw->body, true);
            if (is_array($parsed)) {
                $decoded = $parsed;
            }
        }
        $this->json = $decoded;
    }

    /**
     * 按大小写不敏感取响应头; 不存在时返回 null。
     */
    public function header(string $name): ?string
    {
        return $this->raw->header($name);
    }

    /**
     * 包络中的权威 `success` 布尔。
     *
     * 仅当响应体是 JSON 对象、含 `success` 键、且其值是 **JSON 布尔类型** 时返回该布尔;
     * 缺失、为 `null`、为字符串或数字一律返回 null (由 {@see ApiResponse::isSuccess()} 走 HTTP 回退)。
     */
    public function successFlag(): ?bool
    {
        if ($this->json === null || !array_key_exists('success', $this->json)) {
            return null;
        }

        $flag = $this->json['success'];

        return is_bool($flag) ? $flag : null;
    }

    /**
     * 本次调用是否成功。
     *
     * 判定算法 (五语言逐字对齐):
     * 1. 响应体是 JSON 对象且 `success` 键存在且为布尔类型 → 返回该布尔值;
     * 2. 否则 → 返回 `200 <= httpStatus < 300`。
     *
     * 不再使用 `code == 0` 之类的判定; `code` 只用于取错误码, 不参与成功判定。
     */
    public function isSuccess(): bool
    {
        $flag = $this->successFlag();
        if ($flag !== null) {
            return $flag;
        }

        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

    /**
     * 包络版本 (`version`), 如 `2.0.0`; 缺失或非字符串时返回 null。
     */
    public function version(): ?string
    {
        if ($this->json === null) {
            return null;
        }
        $version = $this->json['version'] ?? null;

        return is_string($version) && $version !== '' ? $version : null;
    }

    /**
     * 平台生成的包络时间戳 (`timestamp`), Unix 毫秒; 缺失或不可解析为整数时返回 null。
     *
     * 与响应头 `X-Response-Timestamp` 无关: 后者参与响应验签, 取值见
     * {@see ApiResponse::responseTimestamp()}。
     */
    public function timestampMs(): ?int
    {
        if ($this->json === null) {
            return null;
        }
        $timestamp = $this->json['timestamp'] ?? null;
        if (is_int($timestamp)) {
            return $timestamp;
        }
        if (is_string($timestamp) && preg_match('/^-?\d+$/', $timestamp) === 1) {
            return (int) $timestamp;
        }

        return null;
    }

    /**
     * 包络中的权威 `code` 字段, 统一字符串化; 缺失或类型不适用时返回 null。
     *
     * 成功响应也能读到成功码 (如 `"2000"` / `"2101"`)。数字码按十进制字符串返回,
     * 判定成功仍以 {@see ApiResponse::isSuccess()} 为准。
     */
    public function code(): ?string
    {
        if ($this->json === null || !array_key_exists('code', $this->json)) {
            return null;
        }

        return self::stringifyCode($this->json['code']);
    }

    /**
     * 响应头 `X-Request-Id` 回显值。
     */
    public function requestId(): ?string
    {
        return $this->header('X-Request-Id');
    }

    /**
     * 响应头 `X-Operation-Id`, 幂等写操作的稳定业务恢复身份。
     */
    public function operationId(): ?string
    {
        return $this->header('X-Operation-Id');
    }

    /**
     * 响应头 `Content-Type` 原值 (含 charset 参数)。
     */
    public function contentType(): ?string
    {
        return $this->header('Content-Type');
    }

    /**
     * 响应头 `X-Response-Timestamp` 原值。
     */
    public function responseTimestamp(): ?string
    {
        return $this->header('X-Response-Timestamp');
    }

    /**
     * 业务数据段 (`data`)。
     */
    public function data(): mixed
    {
        return $this->json['data'] ?? null;
    }

    /**
     * 从 `data` 中按点分路径取值, 缺失时返回 $default。
     */
    public function dataPath(string $path, mixed $default = null): mixed
    {
        $node = $this->data();
        foreach (explode('.', $path) as $segment) {
            if (!is_array($node) || !array_key_exists($segment, $node)) {
                return $default;
            }
            $node = $node[$segment];
        }

        return $node;
    }

    /**
     * 错误码原始字符串; 成功响应 (见 {@see ApiResponse::isSuccess()}) 返回 null。
     *
     * 主路径是包络的权威 `code` 字段, 数字码按十进制字符串返回 (业务错误码本就是
     * `"4022"` 这样的数字字符串, 不因"看起来是数字"而被丢弃)。
     * `errorCode` / `error_code` / `error.code` 仅作次级回退。
     */
    public function errorCode(): ?string
    {
        if ($this->json === null || $this->isSuccess()) {
            return null;
        }

        $code = $this->code();
        if ($code !== null && $code !== '') {
            return $code;
        }

        foreach (['errorCode', 'error_code'] as $key) {
            $candidate = $this->json[$key] ?? null;
            if (is_string($candidate) && $candidate !== '') {
                return $candidate;
            }
        }

        $error = $this->json['error'] ?? null;
        if (is_array($error) && is_string($error['code'] ?? null) && $error['code'] !== '') {
            return $error['code'];
        }

        return null;
    }

    /**
     * 错误描述; 缺失时返回 null。
     */
    public function errorMessage(): ?string
    {
        if ($this->json === null) {
            return null;
        }

        foreach (['message', 'msg', 'errorMessage'] as $key) {
            $candidate = $this->json[$key] ?? null;
            if (is_string($candidate) && $candidate !== '') {
                return $candidate;
            }
        }

        $error = $this->json['error'] ?? null;
        if (is_array($error) && is_string($error['message'] ?? null) && $error['message'] !== '') {
            return $error['message'];
        }

        return null;
    }

    /**
     * 平台阶段码 (`GATEWAY_*`), 仅用于排障日志, 不应作为业务判定依据。
     */
    public function gatewayStage(): ?string
    {
        if ($this->json === null) {
            return null;
        }
        $stage = $this->json['stage'] ?? $this->json['gatewayCode'] ?? null;

        return is_string($stage) && $stage !== '' ? $stage : null;
    }

    /**
     * 把 `code` 字段统一为字符串: 字符串原样, 整数按十进制转换, 其余类型返回 null。
     */
    private static function stringifyCode(mixed $code): ?string
    {
        if (is_string($code)) {
            return $code === '' ? null : $code;
        }
        if (is_int($code)) {
            return (string) $code;
        }

        return null;
    }
}
