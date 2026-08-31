<?php

declare(strict_types=1);

namespace SlaunchX\Plutus;

use InvalidArgumentException;
use SlaunchX\Plutus\Exception\ApiException;
use SlaunchX\Plutus\Exception\ConfigurationException;
use SlaunchX\Plutus\Exception\EnvelopeException;
use SlaunchX\Plutus\Http\CurlTransport;
use SlaunchX\Plutus\Http\TransportInterface;
use SlaunchX\Plutus\Model\ApiResponse;
use SlaunchX\Plutus\Model\SignedRequest;
use SlaunchX\Plutus\Support\CanonicalQuery;
use SlaunchX\Plutus\Support\Nonce;

/**
 * 通用 HTTP 客户端: 组装请求头、一次序列化 body、对同一字节签名并发送, 随后强制响应验签。
 *
 * 本类只覆盖传输层, 不建立任何业务端点模型。路径由调用方以**外部路径**给出
 * (不含 `/api`、`/v{N}`、门户前缀), 版本走 `X-API-VERSION` 头。
 */
final class PlutusClient
{
    /** {@see PlutusClient::request()} 允许的选项键。 */
    private const ALLOWED_OPTIONS = [
        'query',
        'body',
        'json',
        'idempotencyKey',
        'requestId',
        'headers',
        'contentType',
        'timestamp',
        'nonce',
    ];

    /** SDK 序列化 JSON 时使用的固定标志, 保证同一入参得到同一字节串。 */
    private const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

    private readonly RequestSigner $signer;

    private readonly ResponseVerifier $verifier;

    private readonly TransportInterface $transport;

    public function __construct(
        private readonly PlutusConfig $config,
        ?TransportInterface $transport = null,
    ) {
        $this->signer = new RequestSigner($config);
        $this->verifier = new ResponseVerifier($config);
        $this->transport = $transport ?? new CurlTransport($config);
    }

    /**
     * 当前配置。
     */
    public function config(): PlutusConfig
    {
        return $this->config;
    }

    /**
     * 请求签名器, 供需要脱离 HTTP 客户端单独签名的场景使用。
     */
    public function signer(): RequestSigner
    {
        return $this->signer;
    }

    /**
     * 响应验签器。
     */
    public function verifier(): ResponseVerifier
    {
        return $this->verifier;
    }

    /**
     * 发送一次明文请求。
     *
     * 选项:
     * - `query`: `string|array|null`, 数组按 RFC 3986 全量编码后再规范化;
     * - `body`: `string|null`, 已序列化的 body 字节, 与 `json` 互斥;
     * - `json`: `mixed`, 由 SDK 一次性序列化, 与 `body` 互斥;
     * - `idempotencyKey`: `string|null`, 发送即参与签名;
     * - `requestId`: `string|null`, 写入 `X-Request-Id`, 不参与请求签名;
     * - `headers`: `array<string, string>`, 附加请求头;
     * - `contentType`: `string`, 默认 `application/json`, 仅在有 body 时发送;
     * - `timestamp` / `nonce`: `string`, 覆盖自动生成值, 仅测试用。
     *
     * @param string               $method       HTTP 方法
     * @param string               $externalPath 外部路径, 以 `/` 开头
     * @param array<string, mixed> $options
     *
     * @throws ApiException 响应判定为失败 (包络 `success:false`, 或缺 `success` 时 HTTP 非 2xx) 且 `throwOnErrorStatus` 开启
     */
    public function request(string $method, string $externalPath, array $options = []): ApiResponse
    {
        $unknown = array_diff(array_keys($options), self::ALLOWED_OPTIONS);
        if ($unknown !== []) {
            throw new InvalidArgumentException('未知的请求选项: ' . implode(', ', $unknown));
        }

        $method = strtoupper($method);
        $rawQuery = $this->normalizeQuery($options['query'] ?? null);
        [$body, $contentType] = $this->resolveBody($options);

        $headers = $options['headers'] ?? [];
        if (!is_array($headers)) {
            throw new InvalidArgumentException('headers 选项必须是数组');
        }
        if ($body !== null && $contentType !== null && !$this->hasHeader($headers, 'Content-Type')) {
            $headers['Content-Type'] = $contentType;
        }

        $signed = $this->signer->sign(
            $method,
            $externalPath,
            $rawQuery,
            $body,
            $this->optionalString($options, 'idempotencyKey'),
            $this->optionalString($options, 'requestId'),
            $headers,
            $this->optionalString($options, 'timestamp'),
            $this->optionalString($options, 'nonce'),
        );

        return $this->dispatch($signed, $body);
    }

    /**
     * 发送一次加密请求 (仅用于协议标注为加密的端点)。
     *
     * 明文一次序列化后封入 RSA-OAEP-AES-256-GCM 信封, 信封 JSON 的字节即实际 body,
     * 签名的 body 摘要也基于该字节。AAD 为
     * `requestId | 外部路径 | X-Timestamp | 平台加密公钥指纹`。
     *
     * @param string               $method       HTTP 方法, 加密端点均为 `POST`
     * @param string               $externalPath 外部路径, 同时作为 AAD 的 routeTemplate
     * @param mixed                $payload      业务明文; 字符串按已序列化字节处理, 其余由 SDK 序列化
     * @param array<string, mixed> $options      同 {@see PlutusClient::request()}, 但不接受 `body` / `json`
     *
     * 外部路径不在 {@see EncryptedRoutes::ROUTES} 已知表中时: 默认仅记录一条 `error_log`
     * 提示, 不阻断请求; `PlutusConfig::$strictEncryptedRouteValidation` 打开时直接抛出
     * `ConfigurationException`。设计取舍见 {@see EncryptedRoutes} 类注释。
     *
     * @throws ConfigurationException 缺少平台加密公钥、`X-Request-Id` 为空,
     *                                或严格模式下外部路径不在已知加密端点表中
     */
    public function requestEncrypted(
        string $method,
        string $externalPath,
        mixed $payload,
        array $options = [],
    ): ApiResponse {
        if (isset($options['body']) || isset($options['json'])) {
            throw new InvalidArgumentException('加密请求的 body 由 SDK 生成, 不接受 body / json 选项');
        }

        if (!EncryptedRoutes::isKnown($externalPath)) {
            if ($this->config->strictEncryptedRouteValidation) {
                throw new ConfigurationException(sprintf(
                    '外部路径 "%s" 不在已知加密请求端点表 (EncryptedRoutes::ROUTES) 中',
                    $externalPath
                ));
            }
            error_log(sprintf(
                '[slaunchx-plutus-sdk] 外部路径 "%s" 不在已知加密请求端点表 (EncryptedRoutes::ROUTES) 中,'
                . ' 仍按加密请求处理; 如平台已新增该端点, 请升级 SDK 或反馈补充常量表',
                $externalPath
            ));
        }

        $requestId = $this->optionalString($options, 'requestId') ?? self::generateRequestId();
        if ($requestId === '') {
            throw new ConfigurationException('加密请求的 X-Request-Id 不能为空');
        }
        if ($this->config->apiKey === '') {
            throw new ConfigurationException('加密请求的 X-Api-Key 不能为空');
        }

        $timestamp = $this->optionalString($options, 'timestamp') ?? $this->config->currentTimestampMillis();
        $keyId = $this->config->resolvePlatformEncKeyId();
        if ($keyId === '') {
            throw new ConfigurationException('加密请求的 X-Platform-Encryption-Key-Id 不能为空');
        }

        $plaintext = is_string($payload) ? $payload : json_encode($payload, self::JSON_FLAGS);
        $aad = EnvelopeCodec::buildAad($requestId, $externalPath, $timestamp, $keyId);
        $envelope = EnvelopeCodec::seal($plaintext, $this->config->platformEncPublicKey(), $keyId, $aad);

        $options['body'] = json_encode($envelope, self::JSON_FLAGS);
        $options['requestId'] = $requestId;
        $options['timestamp'] = $timestamp;

        $headers = $options['headers'] ?? [];
        if (!is_array($headers)) {
            throw new InvalidArgumentException('headers 选项必须是数组');
        }
        $headers['X-Platform-Encryption-Key-Id'] = $keyId;
        $options['headers'] = $headers;

        return $this->request($method, $externalPath, $options);
    }

    /**
     * `GET` 请求。
     *
     * @param array<string, mixed> $options
     */
    public function get(string $externalPath, array $options = []): ApiResponse
    {
        return $this->request('GET', $externalPath, $options);
    }

    /**
     * `POST` 请求。
     *
     * @param array<string, mixed> $options
     */
    public function post(string $externalPath, array $options = []): ApiResponse
    {
        return $this->request('POST', $externalPath, $options);
    }

    /**
     * `PUT` 请求。
     *
     * @param array<string, mixed> $options
     */
    public function put(string $externalPath, array $options = []): ApiResponse
    {
        return $this->request('PUT', $externalPath, $options);
    }

    /**
     * `PATCH` 请求。
     *
     * @param array<string, mixed> $options
     */
    public function patch(string $externalPath, array $options = []): ApiResponse
    {
        return $this->request('PATCH', $externalPath, $options);
    }

    /**
     * `DELETE` 请求。body 摘要恒为空 body 摘要。
     *
     * @param array<string, mixed> $options
     */
    public function delete(string $externalPath, array $options = []): ApiResponse
    {
        return $this->request('DELETE', $externalPath, $options);
    }

    /**
     * 解密敏感响应信封。
     *
     * AAD 的 routeTemplate 位固定为空串; timestamp 由平台生成, 从信封回显的 `aad`
     * 中解析。SDK 用解析出的时间戳连同本地已知的 requestId 与 `merchant_enc` 指纹
     * 重建 AAD, 再与回显值逐字节比对, 比对通过后才用**重建的** AAD 解密。
     *
     * @param array<string, mixed> $envelope  信封结构
     * @param string|null          $requestId 本次请求的关联 ID; null 按空串处理
     * @param string|null          $timestamp 平台时间戳; null 表示从信封 `aad` 解析
     *
     * @throws EnvelopeException AAD 不匹配、指纹不匹配或解密失败
     */
    public function decryptSensitiveEnvelope(
        array $envelope,
        ?string $requestId = null,
        ?string $timestamp = null,
    ): string {
        $keyId = $this->config->merchantEncKeyFingerprint();
        $resolvedTimestamp = $timestamp ?? self::parseAadTimestamp($envelope);

        $aad = EnvelopeCodec::buildAad($requestId ?? '', '', $resolvedTimestamp, $keyId);

        return EnvelopeCodec::open($envelope, $this->config->merchantEncPrivateKey(), $aad, $keyId);
    }

    /**
     * 从响应中提取敏感信封并解密, requestId 取响应头 `X-Request-Id` 回显值。
     *
     * @param array<string, mixed>|null $envelope 显式指定信封; null 表示自动从响应体定位
     *
     * @throws EnvelopeException 响应中不含合法信封或解密失败
     */
    public function decryptSensitiveResponse(ApiResponse $response, ?array $envelope = null): string
    {
        $envelope ??= self::locateEnvelope($response);
        if ($envelope === null) {
            throw new EnvelopeException('响应体中未找到混合加密信封');
        }

        return $this->decryptSensitiveEnvelope($envelope, $response->requestId() ?? '');
    }

    /**
     * 生成符合 nonce 字符集约束的请求关联 ID。
     */
    public static function generateRequestId(): string
    {
        return 'req_' . bin2hex(random_bytes(16));
    }

    /**
     * 发送已签名的请求并完成响应验签。
     *
     * 供已用 {@see RequestSigner} 自行签名的调用方复用传输与验签逻辑。
     *
     * @throws ApiException 响应判定为失败 (包络 `success:false`, 或缺 `success` 时 HTTP 非 2xx) 且 `throwOnErrorStatus` 开启
     */
    public function dispatch(SignedRequest $signed, ?string $body): ApiResponse
    {
        $url = $this->buildUrl($signed);
        $raw = $this->transport->send($signed->method, $url, $signed->headers, $body);
        $verified = $this->verifier->verify($signed, $raw);

        $response = new ApiResponse($signed, $raw, $verified);
        if (!$response->isSuccess() && $this->config->throwOnErrorStatus) {
            throw ApiException::fromResponse($response);
        }

        return $response;
    }

    private function buildUrl(SignedRequest $signed): string
    {
        $query = $this->config->sendCanonicalQuery
            ? $signed->canonicalQuery
            : ($signed->rawQuery ?? '');

        return rtrim($this->config->baseUrl, '/')
            . $signed->externalPath
            . ($query === '' ? '' : '?' . $query);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array{0: string|null, 1: string|null} [body 字节, Content-Type]
     */
    private function resolveBody(array $options): array
    {
        $hasBody = array_key_exists('body', $options) && $options['body'] !== null;
        $hasJson = array_key_exists('json', $options) && $options['json'] !== null;
        if ($hasBody && $hasJson) {
            throw new InvalidArgumentException('body 与 json 选项互斥');
        }

        $contentType = $this->optionalString($options, 'contentType');

        if ($hasBody) {
            if (!is_string($options['body'])) {
                throw new InvalidArgumentException('body 选项必须是已序列化的字符串');
            }

            return [$options['body'], $contentType ?? 'application/json'];
        }

        if ($hasJson) {
            return [json_encode($options['json'], self::JSON_FLAGS), $contentType ?? 'application/json'];
        }

        return [null, null];
    }

    private function normalizeQuery(mixed $query): ?string
    {
        if ($query === null || $query === '') {
            return null;
        }
        if (is_string($query)) {
            return $query;
        }
        if (is_array($query)) {
            return CanonicalQuery::build($query);
        }

        throw new InvalidArgumentException('query 选项必须是字符串或数组');
    }

    /**
     * @param array<string, mixed> $options
     */
    private function optionalString(array $options, string $key): ?string
    {
        $value = $options[$key] ?? null;
        if ($value === null) {
            return null;
        }
        if (!is_string($value)) {
            throw new InvalidArgumentException(sprintf('%s 选项必须是字符串', $key));
        }

        return $value;
    }

    /**
     * @param array<string, string> $headers
     */
    private function hasHeader(array $headers, string $name): bool
    {
        foreach (array_keys($headers) as $key) {
            if (strcasecmp((string) $key, $name) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * 从信封回显的 AAD 中解析时间戳分量 (第 3 位)。
     *
     * @param array<string, mixed> $envelope
     */
    private static function parseAadTimestamp(array $envelope): string
    {
        $encoded = $envelope['aad'] ?? null;
        if (!is_string($encoded) || $encoded === '') {
            throw new EnvelopeException('信封缺少 aad, 无法解析平台时间戳');
        }

        $decoded = base64_decode($encoded, true);
        if ($decoded === false) {
            throw new EnvelopeException('信封 aad 不是合法 Base64');
        }

        $parts = explode('|', $decoded);
        if (count($parts) !== 4) {
            throw new EnvelopeException('信封 aad 不是四分量结构, 无法解析平台时间戳');
        }

        return $parts[2];
    }

    /**
     * 在响应体中定位混合加密信封: 优先 `data`, 其次顶层。
     *
     * @return array<string, mixed>|null
     */
    private static function locateEnvelope(ApiResponse $response): ?array
    {
        foreach ([$response->data(), $response->json] as $candidate) {
            if (is_array($candidate) && isset($candidate['algorithm'], $candidate['ciphertext'], $candidate['aad'])) {
                /** @var array<string, mixed> $candidate */
                return $candidate;
            }
        }

        return null;
    }

    /**
     * 校验 nonce 是否满足平台约束, 供自定义 nonce 生成器自检。
     */
    public static function isValidNonce(string $nonce): bool
    {
        return Nonce::isValid($nonce);
    }
}
