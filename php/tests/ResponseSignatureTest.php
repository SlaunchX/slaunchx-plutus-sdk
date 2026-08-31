<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SlaunchX\Plutus\Exception\ResponseSignatureException;
use SlaunchX\Plutus\Http\RawResponse;
use SlaunchX\Plutus\RequestSigner;
use SlaunchX\Plutus\ResponseVerifier;
use SlaunchX\Plutus\Support\Keys;

final class ResponseSignatureTest extends VectorTestCase
{
    /** 本地成功包络 fixture, 与向量无关: 向量只固定签名字节。 */
    private const SUCCESS_BODY =
        '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{}}';

    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function vectorProvider(): array
    {
        $cases = [];
        foreach (self::group('responseSignature') as $vector) {
            $cases[(string) $vector['id']] = [$vector];
        }

        return $cases;
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testResponseCanonicalStringAndSignature(array $vector): void
    {
        $body = (string) $vector['responseBody'];

        self::assertSame($vector['responseBodyHash'], ResponseVerifier::bodyDigestHex($body));

        $canonical = ResponseVerifier::buildCanonicalString(
            (string) $vector['requestCanonicalSha256'],
            (string) $vector['apiVersion'],
            (string) $vector['externalPath'],
            $vector['operationId'],
            $vector['requestId'],
            (int) $vector['httpStatus'],
            $vector['contentType'],
            (string) $vector['responseTimestamp'],
            (string) $vector['responseBodyHash'],
        );

        self::assertSame($vector['canonicalString'], $canonical);
        self::assertSame($vector['canonicalStringLines'], explode("\n", $canonical));

        self::assertTrue(ResponseVerifier::verifyCanonicalString(
            $canonical,
            (string) $vector['signature'],
            Keys::loadPublicKey(self::publicKeyPem('platform_auth')),
        ));
    }

    /**
     * 第 2 行的请求绑定摘要必须由本地重算, 且与关联的请求向量一致。
     *
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testRequestBindingIsLocallyRecomputed(array $vector): void
    {
        $requestVector = null;
        foreach (self::group('requestSignature') as $candidate) {
            if ($candidate['id'] === $vector['requestVectorId']) {
                $requestVector = $candidate;
                break;
            }
        }
        self::assertIsArray($requestVector, '未找到关联的请求向量');

        self::assertSame(
            $vector['requestCanonicalSha256'],
            RequestSigner::canonicalStringDigest((string) $requestVector['canonicalString'])
        );
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testTamperedCanonicalLineFailsVerification(array $vector): void
    {
        $publicKey = Keys::loadPublicKey(self::publicKeyPem('platform_auth'));
        $lines = explode("\n", (string) $vector['canonicalString']);

        foreach (array_keys($lines) as $index) {
            $tampered = $lines;
            $tampered[$index] .= 'x';

            self::assertFalse(
                ResponseVerifier::verifyCanonicalString(
                    implode("\n", $tampered),
                    (string) $vector['signature'],
                    $publicKey
                ),
                sprintf('篡改第 %d 行后验签仍然通过', $index + 1)
            );
        }
    }

    /**
     * Content-Type 必须使用响应头原值, 归一化会改变签名。
     */
    public function testContentTypeMustNotBeNormalized(): void
    {
        $vector = self::group('responseSignature')[1];
        $publicKey = Keys::loadPublicKey(self::publicKeyPem('platform_auth'));

        $normalized = ResponseVerifier::buildCanonicalString(
            (string) $vector['requestCanonicalSha256'],
            (string) $vector['apiVersion'],
            (string) $vector['externalPath'],
            $vector['operationId'],
            $vector['requestId'],
            (int) $vector['httpStatus'],
            'application/json',
            (string) $vector['responseTimestamp'],
            (string) $vector['responseBodyHash'],
        );

        self::assertSame('application/json;charset=UTF-8', $vector['contentType']);
        self::assertFalse(
            ResponseVerifier::verifyCanonicalString($normalized, (string) $vector['signature'], $publicKey)
        );
    }

    public function testVerifierAcceptsVectorResponseEndToEnd(): void
    {
        $vector = self::group('responseSignature')[1];
        $requestVector = self::group('requestSignature')[3];
        /** @var array<string, mixed> $request */
        $request = $requestVector['request'];

        $signer = new RequestSigner(self::config());
        $signed = $signer->sign(
            (string) $request['method'],
            (string) $request['externalPath'],
            $request['queryString'],
            $request['body'],
            $request['idempotencyKey'],
            null,
            [],
            (string) $request['timestamp'],
            (string) $request['nonce'],
        );

        $raw = new RawResponse((int) $vector['httpStatus'], [
            'Content-Type' => (string) $vector['contentType'],
            'X-Operation-Id' => (string) $vector['operationId'],
            'X-Request-Id' => (string) $vector['requestId'],
            'X-Response-Timestamp' => (string) $vector['responseTimestamp'],
            'X-Response-Signature' => (string) $vector['signature'],
            'X-Response-Signature-Algorithm' => 'RSA-SHA256',
        ], (string) $vector['responseBody']);

        $verifier = new ResponseVerifier(self::config());
        self::assertTrue($verifier->verify($signed, $raw));
    }

    public function testTamperedResponseBodyIsRejected(): void
    {
        $vector = self::group('responseSignature')[1];
        $requestVector = self::group('requestSignature')[3];
        /** @var array<string, mixed> $request */
        $request = $requestVector['request'];

        $signer = new RequestSigner(self::config());
        $signed = $signer->sign(
            (string) $request['method'],
            (string) $request['externalPath'],
            $request['queryString'],
            $request['body'],
            $request['idempotencyKey'],
            null,
            [],
            (string) $request['timestamp'],
            (string) $request['nonce'],
        );

        $raw = new RawResponse((int) $vector['httpStatus'], [
            'Content-Type' => (string) $vector['contentType'],
            'X-Operation-Id' => (string) $vector['operationId'],
            'X-Request-Id' => (string) $vector['requestId'],
            'X-Response-Timestamp' => (string) $vector['responseTimestamp'],
            'X-Response-Signature' => (string) $vector['signature'],
        ], (string) $vector['responseBody'] . ' ');

        $verifier = new ResponseVerifier(self::config());

        $this->expectException(ResponseSignatureException::class);
        $verifier->verify($signed, $raw);
    }

    /**
     * 缺签名头的默认策略: 2xx 必须有签名, 非 2xx 放行。
     *
     * 不按状态码白名单放行 —— 平台契约只说明认证失败等场景可能不带签名头,
     * 并未穷举无签名的状态码集合。
     */
    public function testMissingSignatureIsRejectedOnlyOnSuccessStatus(): void
    {
        $signer = new RequestSigner(self::config());
        $signed = $signer->sign('GET', '/card-products/cards/page');
        $verifier = new ResponseVerifier(self::config());

        // 非 2xx 缺签名头放行, 返回 false 表示未完成验签。
        foreach ([400, 401, 403, 404, 429, 500, 503] as $status) {
            self::assertFalse(
                $verifier->verify($signed, new RawResponse($status, [], '{"success":false,"code":"API.KEY_INVALID"}')),
                sprintf('HTTP %d 缺签名头应放行', $status)
            );
        }

        // 2xx 缺签名头一律抛异常。
        foreach ([200, 201, 204] as $status) {
            try {
                $verifier->verify($signed, new RawResponse($status, [], self::SUCCESS_BODY));
                self::fail(sprintf('HTTP %d 缺签名头未抛异常', $status));
            } catch (ResponseSignatureException $exception) {
                self::assertStringContainsString('X-Response-Signature', $exception->getMessage());
            }
        }
    }

    /**
     * `requireSignatureOnErrorResponses` 打开后, 非 2xx 缺签名头同样抛异常。
     */
    public function testStrictSwitchAlsoRequiresSignatureOnErrorResponses(): void
    {
        $config = self::config(['requireSignatureOnErrorResponses' => true]);
        $signer = new RequestSigner($config);
        $verifier = new ResponseVerifier($config);
        $signed = $signer->sign('GET', '/card-products/cards/page');

        $this->expectException(ResponseSignatureException::class);
        $verifier->verify($signed, new RawResponse(401, [], '{"success":false,"code":"API.KEY_INVALID"}'));
    }

    public function testVerificationCanBeDisabled(): void
    {
        $config = self::config(['verifyResponseSignature' => false]);
        $signer = new RequestSigner($config);
        $verifier = new ResponseVerifier($config);

        self::assertFalse($verifier->verify(
            $signer->sign('GET', '/card-products/cards/page'),
            new RawResponse(200, [], self::SUCCESS_BODY)
        ));
    }

    public function testVectorGroupIsFullyCovered(): void
    {
        self::assertCount(3, self::group('responseSignature'));
    }
}
