<?php
declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SlaunchX\Plutus\Exception\CanonicalizationException;
use SlaunchX\Plutus\Exception\ResponseSignatureException;
use SlaunchX\Plutus\Http\RawResponse;
use SlaunchX\Plutus\PlutusClient;
use SlaunchX\Plutus\ProtocolProfile;
use SlaunchX\Plutus\RequestSigner;
use SlaunchX\Plutus\ResponseVerifier;

final class ProductProtocolTest extends VectorTestCase
{
    public function testProductRequestHasSevenLinesAndStillSendsIdempotencyHeader(): void
    {
        $signer = new RequestSigner(self::config(['protocolProfile' => ProtocolProfile::PRODUCT_V1]));
        $signed = $signer->sign('POST', '/card-products/groups/list', null, '{"isActive":true}', 'operation-1');
        self::assertCount(7, $signed->canonicalStringLines());
        self::assertSame(hash('sha256', '{"isActive":true}'), $signed->canonicalStringLines()[6]);
        self::assertSame('operation-1', $signed->headers['X-Idempotency-Key']);
        self::assertSame('1', $signed->headers['X-API-VERSION']);
    }

    public static function queryCases(): array
    {
        return [
            'special characters' => ['q=a+b&tilde=~&star=%2A', 'q=a%20b&star=*&tilde=%7E'],
            'decoded sorting' => ['%C3%A9=1&z=2&a=%C3%A9&a=z', 'a=z&a=%C3%A9&z=2&%C3%A9=1'],
            'UTF16 sorting' => ['%EE%80%80=x&%F0%90%80%80=y', '%F0%90%80%80=y&%EE%80%80=x'],
            'empty and repeated values' => ['b&b=&a=%2B', 'a=%2B&b=&b='],
            'Java blank input' => [" \t\u{2003}", ''],
            'non-breaking space is not Java blank' => ["\u{00A0}", '%C2%A0='],
            'empty string' => ['', ''],
        ];
    }

    #[DataProvider('queryCases')]
    public function testQueryUsesProductJavaFormEncoding(string $raw, string $expected): void
    {
        $signed = (new RequestSigner(self::config(['protocolProfile' => ProtocolProfile::PRODUCT_V1])))
            ->sign('GET', '/card-products/cards/page', $raw);
        self::assertSame($expected, $signed->canonicalQuery);
        self::assertSame($expected, $signed->canonicalStringLines()[2]);
    }

    public function testMalformedQueryStillFailsLocally(): void
    {
        $this->expectException(CanonicalizationException::class);
        (new RequestSigner(self::config(['protocolProfile' => ProtocolProfile::PRODUCT_V1])))
            ->sign('GET', '/card-products/cards/page', 'x=%GG');
    }

    private function productResponse(string $body = '{"success":true,"code":"2000","data":[]}'): RawResponse
    {
        $canonical = implode("\n", ['request-product-test', '200', 'application/json', '1788836400000', hash('sha256', $body)]);
        openssl_sign($canonical, $signature, self::privateKeyPem('platform_auth'), OPENSSL_ALGO_SHA256);
        return new RawResponse(200, [
            'X-Request-Id' => 'request-product-test',
            'Content-Type' => 'application/json',
            'X-Response-Timestamp' => '1788836400000',
            'X-Response-Signature-Algorithm' => 'RSA-SHA256',
            'X-Response-Signature' => base64_encode($signature),
        ], $body);
    }

    public function testProductResponseIsVerifiedThroughClient(): void
    {
        $config = self::config(['protocolProfile' => ProtocolProfile::PRODUCT_V1]);
        $transport = new FakeTransport(fn() => $this->productResponse());
        $result = (new PlutusClient($config, $transport))->get('/card-products/cards/page', [
            'query' => ['cardDisplayName' => 'a~* b', 'size' => 10],
        ]);
        self::assertTrue($result->signatureVerified);
        self::assertTrue($result->isSuccess());
        self::assertStringContainsString('cardDisplayName=a%7E*%20b&size=10', $transport->last()['url']);
    }

    public function testProductRejectsTamperedBody(): void
    {
        $config = self::config(['protocolProfile' => ProtocolProfile::PRODUCT_V1]);
        $raw = $this->productResponse();
        $this->expectException(ResponseSignatureException::class);
        (new ResponseVerifier($config))->verify(
            (new RequestSigner($config))->sign('GET', '/card-products/cards/page'),
            new RawResponse(200, $raw->headers, $raw->body . ' '),
        );
    }

    public function testDefaultProfileDoesNotFallBackToProductResponse(): void
    {
        $config = self::config();
        $this->expectException(ResponseSignatureException::class);
        (new ResponseVerifier($config))->verify(
            (new RequestSigner($config))->sign('GET', '/card-products/cards/page'),
            $this->productResponse(),
        );
    }

    public function testProductRejectsMissingSuccessSignature(): void
    {
        $config = self::config(['protocolProfile' => ProtocolProfile::PRODUCT_V1]);
        $this->expectException(ResponseSignatureException::class);
        (new ResponseVerifier($config))->verify(
            (new RequestSigner($config))->sign('GET', '/card-products/cards/page'),
            new RawResponse(200, [], '{"success":true}'),
        );
    }

    public function testProductRejectsBoundProtocolResponseInsteadOfFallingBack(): void
    {
        $config = self::config(['protocolProfile' => ProtocolProfile::PRODUCT_V1]);
        $signed = (new RequestSigner($config))->sign('GET', '/card-products/cards/page');
        $raw = $this->productResponse();
        $canonical = ResponseVerifier::buildCanonicalString(
            $signed->requestCanonicalSha256, $signed->apiVersion, $signed->externalPath,
            null, $raw->header('X-Request-Id'), 200, $raw->header('Content-Type'),
            $raw->header('X-Response-Timestamp'), hash('sha256', $raw->body),
        );
        openssl_sign($canonical, $signature, self::privateKeyPem('platform_auth'), OPENSSL_ALGO_SHA256);
        $headers = $raw->headers;
        $headers['X-Response-Signature'] = base64_encode($signature);
        $this->expectException(ResponseSignatureException::class);
        (new ResponseVerifier($config))->verify($signed, new RawResponse(200, $headers, $raw->body));
    }

    public function testProductRejectsTamperedContentType(): void
    {
        $config = self::config(['protocolProfile' => ProtocolProfile::PRODUCT_V1]);
        $raw = $this->productResponse();
        $headers = $raw->headers;
        $headers['Content-Type'] = 'application/json;charset=UTF-8';
        $this->expectException(ResponseSignatureException::class);
        (new ResponseVerifier($config))->verify(
            (new RequestSigner($config))->sign('GET', '/card-products/cards/page'),
            new RawResponse(200, $headers, $raw->body),
        );
    }
}
