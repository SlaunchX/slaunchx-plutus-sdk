<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use SlaunchX\Plutus\EnvelopeCodec;
use SlaunchX\Plutus\Exception\ApiException;
use SlaunchX\Plutus\Exception\AuthenticationException;
use SlaunchX\Plutus\Exception\ConflictException;
use SlaunchX\Plutus\Exception\RateLimitException;
use SlaunchX\Plutus\Exception\ResponseSignatureException;
use SlaunchX\Plutus\Exception\SecureChannelException;
use SlaunchX\Plutus\Http\RawResponse;
use SlaunchX\Plutus\PlutusClient;
use SlaunchX\Plutus\RequestSigner;
use SlaunchX\Plutus\ResponseVerifier;
use SlaunchX\Plutus\Support\Keys;
use SlaunchX\Plutus\Support\Nonce;

final class PlutusClientTest extends VectorTestCase
{
    /** 标准成功包络 (`code` 2000)。 */
    private const SUCCESS_BODY =
        '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{"ok":true}}';

    /**
     * 构造成功包络, `data` 由调用方给出的已序列化 JSON 片段填充。
     */
    private static function successBody(string $codeValue, string $dataJson): string
    {
        return sprintf(
            '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"%s","message":"Success","data":%s}',
            $codeValue,
            $dataJson
        );
    }

    /**
     * 构造一个会对响应正确签名的传输。
     *
     * @param array<string, string> $extraHeaders
     */
    private function signingTransport(
        int $status = 200,
        string $body = self::SUCCESS_BODY,
        string $contentType = 'application/json;charset=UTF-8',
        array $extraHeaders = [],
    ): FakeTransport {
        return new FakeTransport(function (array $request) use ($status, $body, $contentType, $extraHeaders): RawResponse {
            $signer = new RequestSigner(self::config());
            $signed = $signer->sign(
                $request['method'],
                (string) parse_url($request['url'], PHP_URL_PATH),
                parse_url($request['url'], PHP_URL_QUERY) ?: null,
                $request['body'],
                $request['headers']['X-Idempotency-Key'] ?? null,
                null,
                [],
                $request['headers']['X-Timestamp'],
                $request['headers']['X-Nonce'],
            );

            $requestId = $request['headers']['X-Request-Id'] ?? 'req_fake_0001';
            $timestamp = '1755600000123';
            $headers = array_merge([
                'Content-Type' => $contentType,
                'X-Request-Id' => $requestId,
                'X-Response-Timestamp' => $timestamp,
                'X-Response-Signature-Algorithm' => 'RSA-SHA256',
            ], $extraHeaders);

            $canonical = ResponseVerifier::buildCanonicalString(
                $signed->requestCanonicalSha256,
                '1',
                (string) parse_url($request['url'], PHP_URL_PATH),
                $headers['X-Operation-Id'] ?? null,
                $requestId,
                $status,
                $contentType,
                $timestamp,
                ResponseVerifier::bodyDigestHex($body),
            );

            $signature = '';
            openssl_sign(
                $canonical,
                $signature,
                Keys::loadPrivateKey(self::privateKeyPem('platform_auth')),
                OPENSSL_ALGO_SHA256
            );
            $headers['X-Response-Signature'] = base64_encode($signature);

            return new RawResponse($status, $headers, $body);
        });
    }

    public function testGetAssemblesAllRequiredHeaders(): void
    {
        $transport = $this->signingTransport();
        $client = new PlutusClient(self::config(), $transport);

        $response = $client->get('/card-products/cards/page', ['query' => 'status=IN_USE&pageSize=20']);

        $sent = $transport->last();
        self::assertSame('GET', $sent['method']);
        self::assertSame(
            'https://consumer-api.example.test/card-products/cards/page?pageSize=20&status=IN_USE',
            $sent['url']
        );
        self::assertNull($sent['body']);

        foreach (['X-Api-Key', 'X-API-VERSION', 'X-Timestamp', 'X-Nonce', 'X-Signature', 'X-Signature-Algorithm'] as $name) {
            self::assertArrayHasKey($name, $sent['headers'], $name);
        }
        self::assertSame('apk_vector_0001', $sent['headers']['X-Api-Key']);
        self::assertSame('1', $sent['headers']['X-API-VERSION']);
        self::assertSame('RSA-SHA256', $sent['headers']['X-Signature-Algorithm']);
        self::assertMatchesRegularExpression('/^\d{13}$/', $sent['headers']['X-Timestamp']);
        self::assertTrue(Nonce::isValid($sent['headers']['X-Nonce']));

        self::assertTrue($response->signatureVerified);
        self::assertTrue($response->isSuccess());
        self::assertSame('2000', $response->code());
        self::assertSame(['ok' => true], $response->data());
    }

    public function testJsonBodyIsSerializedOnceAndSigned(): void
    {
        $transport = $this->signingTransport(201, self::successBody('2001', '{"batchBizId":"ccb_1"}'));
        $client = new PlutusClient(self::config(), $transport);

        $response = $client->post('/card-products/cards/freeze', [
            'json' => ['reasonCategory' => 'USER_REQUESTED'],
            'idempotencyKey' => 'idem-local-0000000001',
        ]);

        $sent = $transport->last();
        self::assertSame('{"reasonCategory":"USER_REQUESTED"}', $sent['body']);
        self::assertSame('application/json', $sent['headers']['Content-Type']);
        self::assertSame('idem-local-0000000001', $sent['headers']['X-Idempotency-Key']);

        // 规范串第 8 行必须是实际发送字节的摘要。
        self::assertSame(
            hash('sha256', (string) $sent['body']),
            $response->request->bodyHash
        );
        self::assertSame('idem-local-0000000001', $response->request->canonicalStringLines()[6]);
    }

    public function testDeleteSignsForcedEmptyBodyDigest(): void
    {
        $transport = $this->signingTransport();
        $client = new PlutusClient(self::config(), $transport);

        $response = $client->delete('/card-products/cards/cancel', ['query' => ['reason' => 'CLOSED_BY_MERCHANT']]);

        self::assertSame(RequestSigner::EMPTY_BODY_SHA256, $response->request->bodyHash);
        self::assertSame('reason=CLOSED_BY_MERCHANT', $response->request->canonicalQuery);
    }

    public function testEncryptedRequestBuildsEnvelopeAndBindsAad(): void
    {
        $transport = $this->signingTransport(201, self::successBody('2001', '{"batchBizId":"ccb_1"}'));
        $client = new PlutusClient(self::config(), $transport);
        $route = '/card-products/10010106/shared/cards/create';

        $response = $client->requestEncrypted('POST', $route, [
            'platformCardProductBizId' => 'pcp_example_001',
            'quantity' => 2,
        ], ['requestId' => 'req_local_0000000001']);

        $sent = $transport->last();
        self::assertSame('req_local_0000000001', $sent['headers']['X-Request-Id']);
        self::assertSame(self::fingerprint('platform_enc'), $sent['headers']['X-Platform-Encryption-Key-Id']);

        $envelope = json_decode((string) $sent['body'], true);
        self::assertIsArray($envelope);
        self::assertSame(EnvelopeCodec::ALGORITHM, $envelope['algorithm']);
        self::assertSame($envelope['ciphertext'], $envelope['encryptedPayload']);

        // 签名的 body 摘要是信封字节的摘要, 不是明文的摘要。
        self::assertSame(hash('sha256', (string) $sent['body']), $response->request->bodyHash);

        $expectedAad = EnvelopeCodec::buildAad(
            'req_local_0000000001',
            $route,
            $sent['headers']['X-Timestamp'],
            self::fingerprint('platform_enc'),
        );
        self::assertSame($expectedAad, base64_decode((string) $envelope['aad'], true));

        // 平台侧用 platform_enc 私钥解开, 应得到原始明文。
        self::assertSame(
            '{"platformCardProductBizId":"pcp_example_001","quantity":2}',
            EnvelopeCodec::open(
                $envelope,
                Keys::loadPrivateKey(self::privateKeyPem('platform_enc')),
                $expectedAad,
                self::fingerprint('platform_enc')
            )
        );
    }

    public function testSensitiveResponseIsDecryptedFromResponseBody(): void
    {
        $vector = self::group('encryptedEnvelope')[1];
        /** @var array<string, mixed> $components */
        $components = $vector['aadComponents'];
        $body = (string) json_encode([
            'version' => '2.0.0',
            'timestamp' => 1755600000123,
            'success' => true,
            'code' => '2000',
            'message' => 'Success',
            'data' => $vector['envelope'],
        ], JSON_UNESCAPED_SLASHES);

        $transport = $this->signingTransport(200, $body, 'application/json;charset=UTF-8', [
            'X-Request-Id' => (string) $components['requestId'],
        ]);
        $client = new PlutusClient(self::config(), $transport);

        $response = $client->get('/card-products/cards/sensitive', [
            'requestId' => (string) $components['requestId'],
        ]);

        self::assertSame($vector['expectedPlaintext'], $client->decryptSensitiveResponse($response));
    }

    public function testErrorStatusMapsToTypedException(): void
    {
        $cases = [
            [401, '{"code":"API.SIGNATURE_INVALID","message":"signature mismatch"}', AuthenticationException::class],
            [409, '{"code":"REQUEST.CONFLICT","message":"duplicate"}', ConflictException::class],
            [429, '{"code":"REQUEST.RATE_LIMITED","message":"slow down"}', RateLimitException::class],
            [400, '{"code":"SECURE_CHANNEL.INVALID_PAYLOAD","message":"aad"}', SecureChannelException::class],
        ];

        foreach ($cases as [$status, $body, $expected]) {
            $transport = $this->signingTransport($status, $body);
            $client = new PlutusClient(self::config(), $transport);

            try {
                $client->get('/card-products/cards/page');
                self::fail(sprintf('HTTP %d 未抛出异常', $status));
            } catch (\SlaunchX\Plutus\Exception\ApiException $exception) {
                self::assertInstanceOf($expected, $exception);
                self::assertSame($status, $exception->statusCode());
                self::assertNotNull($exception->errorCode());
            }
        }
    }

    public function testRateLimitExceptionExposesRetryAfter(): void
    {
        $transport = $this->signingTransport(
            429,
            '{"code":"REQUEST.RATE_LIMITED"}',
            'application/json;charset=UTF-8',
            ['Retry-After' => '7']
        );
        $client = new PlutusClient(self::config(), $transport);

        try {
            $client->get('/card-products/cards/page');
            self::fail('未抛出限流异常');
        } catch (RateLimitException $exception) {
            self::assertSame(7, $exception->retryAfterSeconds());
            self::assertTrue($exception->isRetryable());
        }
    }

    public function testErrorStatusCanBeReturnedInsteadOfThrown(): void
    {
        $transport = $this->signingTransport(404, '{"code":"RESOURCE.NOT_FOUND"}');
        $client = new PlutusClient(self::config(['throwOnErrorStatus' => false]), $transport);

        $response = $client->get('/card-products/cards/page');

        self::assertFalse($response->isSuccess());
        self::assertSame('RESOURCE.NOT_FOUND', $response->errorCode());
        self::assertTrue($response->signatureVerified);
    }

    /**
     * 构造一个**不**对响应签名的传输, 用于缺签名头策略的用例。
     */
    private function unsignedTransport(int $status, string $body): FakeTransport
    {
        return new FakeTransport(static fn (): RawResponse => new RawResponse($status, [
            'Content-Type' => 'application/json;charset=UTF-8',
            'X-Request-Id' => 'req_fake_0001',
            'X-Response-Timestamp' => '1755600000123',
        ], $body));
    }

    /**
     * HTTP 2xx 缺 `X-Response-Signature` 一律抛验签异常, 响应体丢弃。
     */
    public function testMissingSignatureOnSuccessStatusThrows(): void
    {
        $client = new PlutusClient(self::config(), $this->unsignedTransport(200, self::SUCCESS_BODY));

        $this->expectException(ResponseSignatureException::class);
        $client->get('/card-products/cards/page');
    }

    /**
     * 非 2xx 缺签名头默认放行, 调用方能看到 `signatureVerified === false`。
     */
    public function testMissingSignatureOnErrorStatusIsAllowedByDefault(): void
    {
        $body = '{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"API.KEY_INVALID","message":"bad key"}';
        $client = new PlutusClient(
            self::config(['throwOnErrorStatus' => false]),
            $this->unsignedTransport(401, $body)
        );

        $response = $client->get('/card-products/cards/page');

        self::assertFalse($response->signatureVerified);
        self::assertFalse($response->isSuccess());
        self::assertSame('API.KEY_INVALID', $response->errorCode());
    }

    /**
     * 非 2xx 缺签名头放行后, 仍按类型化 API 错误抛出 (而不是验签异常)。
     */
    public function testMissingSignatureOnErrorStatusStillRaisesTypedApiException(): void
    {
        $body = '{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"API.KEY_INVALID","message":"bad key"}';
        $client = new PlutusClient(self::config(), $this->unsignedTransport(401, $body));

        try {
            $client->get('/card-products/cards/page');
            self::fail('未抛出类型化 API 异常');
        } catch (AuthenticationException $exception) {
            self::assertSame(401, $exception->statusCode());
            self::assertFalse($exception->response()->signatureVerified);
        }
    }

    /**
     * 打开 `requireSignatureOnErrorResponses` 后, 非 2xx 缺签名头同样抛验签异常。
     */
    public function testMissingSignatureOnErrorStatusThrowsUnderStrictSwitch(): void
    {
        $client = new PlutusClient(
            self::config(['requireSignatureOnErrorResponses' => true]),
            $this->unsignedTransport(401, '{"success":false,"code":"API.KEY_INVALID"}')
        );

        $this->expectException(ResponseSignatureException::class);
        $client->get('/card-products/cards/page');
    }

    /**
     * HTTP 200 但包络 `success:false` 也必须抛出类型化异常。
     */
    public function testHttpOkWithBusinessFailureThrowsTypedException(): void
    {
        $body = '{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"4022","message":"Validation Error"}';
        $transport = $this->signingTransport(200, $body);
        $client = new PlutusClient(self::config(), $transport);

        try {
            $client->get('/card-products/cards/page');
            self::fail('HTTP 200 + success:false 未抛出异常');
        } catch (ApiException $exception) {
            self::assertSame(200, $exception->statusCode());
            self::assertSame('4022', $exception->rawErrorCode());
            self::assertNull($exception->errorCode());
            self::assertTrue($exception->response()->signatureVerified);
        }
    }

    /**
     * HTTP 200 + `success:false` 且 `throwOnErrorStatus` 关闭时按失败响应返回。
     */
    public function testHttpOkWithBusinessFailureCanBeReturned(): void
    {
        $body = '{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"4022","message":"Validation Error"}';
        $client = new PlutusClient(self::config(['throwOnErrorStatus' => false]), $this->signingTransport(200, $body));

        $response = $client->get('/card-products/cards/page');

        self::assertFalse($response->isSuccess());
        self::assertSame('4022', $response->errorCode());
        self::assertSame('Validation Error', $response->errorMessage());
    }

    /**
     * 「签名字节 == 发送字节」不变量: 参与签名的 body 与发往传输层的 body 是同一份字节,
     * 且 body 只序列化一次 (每次调用只有一条传输记录, 不存在二次编码)。
     */
    public function testSignedBodyBytesAreExactlyTheTransmittedBytes(): void
    {
        $transport = $this->signingTransport(201, self::successBody('2001', '{"batchBizId":"ccb_1"}'));
        $client = new PlutusClient(self::config(), $transport);

        // 含斜杠与非 ASCII: 任何一次多余的序列化/转义都会破坏字节相等。
        $response = $client->post('/card-products/cards/remark/update', [
            'json' => ['remark' => '备注/说明 "quoted"', 'url' => 'https://a.example/b?x=1&y=2'],
        ]);

        self::assertCount(1, $transport->sent);
        $sent = $transport->last();

        // 逐字节相等: 传输层收到的 body 就是 SignedRequest 快照里参与签名的那一份。
        self::assertSame($response->request->body, $sent['body']);
        self::assertSame(hash('sha256', (string) $sent['body']), $response->request->bodyHash);
        self::assertSame($response->request->bodyHash, $response->request->canonicalStringLines()[7]);
        self::assertSame(strlen((string) $sent['body']), strlen($response->request->body));
    }

    /**
     * 加密请求同样满足该不变量: 签名的是信封字节, 与发送字节逐字节相等。
     */
    public function testEncryptedRequestSignsExactlyTheTransmittedEnvelopeBytes(): void
    {
        $transport = $this->signingTransport(201, self::successBody('2001', '{"batchBizId":"ccb_1"}'));
        $client = new PlutusClient(self::config(), $transport);

        $response = $client->requestEncrypted('POST', '/card-products/10010106/shared/cards/create', [
            'platformCardProductBizId' => 'pcp_example_001',
        ], ['requestId' => 'req_local_0000000002']);

        self::assertCount(1, $transport->sent);
        $sent = $transport->last();

        self::assertSame($response->request->body, $sent['body']);
        self::assertSame(hash('sha256', (string) $sent['body']), $response->request->bodyHash);
    }

    public function testRetryUsesFreshTimestampAndNonce(): void
    {
        $transport = $this->signingTransport();
        $client = new PlutusClient(self::config(), $transport);

        $first = $client->get('/card-products/cards/page');
        $second = $client->get('/card-products/cards/page');

        self::assertNotSame($first->request->nonce, $second->request->nonce);
        self::assertNotSame($first->request->signature, $second->request->signature);
    }
}
