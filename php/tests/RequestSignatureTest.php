<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SlaunchX\Plutus\Exception\ConfigurationException;
use SlaunchX\Plutus\RequestSigner;
use SlaunchX\Plutus\Support\Keys;

final class RequestSignatureTest extends VectorTestCase
{
    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function vectorProvider(): array
    {
        $cases = [];
        foreach (self::group('requestSignature') as $vector) {
            $cases[(string) $vector['id']] = [$vector];
        }

        return $cases;
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testRequestSignatureVector(array $vector): void
    {
        /** @var array<string, mixed> $request */
        $request = $vector['request'];
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

        self::assertSame($vector['canonicalQuery'], $signed->canonicalQuery, 'canonicalQuery');
        self::assertSame($vector['bodyHash'], $signed->bodyHash, 'bodyHash');
        self::assertSame($vector['canonicalString'], $signed->canonicalString, 'canonicalString');
        self::assertSame(
            $vector['canonicalStringLines'],
            $signed->canonicalStringLines(),
            'canonicalString 逐行'
        );
        self::assertSame(
            $vector['requestCanonicalSha256'],
            $signed->requestCanonicalSha256,
            'requestCanonicalSha256'
        );

        // PKCS#1 v1.5 是确定性的: 重新签名必须与向量逐字节相等。
        self::assertSame($vector['signature'], $signed->signature, 'signature');

        self::assertTrue(RequestSigner::verifyCanonicalString(
            $signed->canonicalString,
            (string) $vector['signature'],
            Keys::loadPublicKey(self::publicKeyPem('merchant_auth')),
        ));
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testTamperedCanonicalStringFailsVerification(array $vector): void
    {
        $publicKey = Keys::loadPublicKey(self::publicKeyPem('merchant_auth'));
        $canonical = (string) $vector['canonicalString'];
        $signature = (string) $vector['signature'];

        $lines = explode("\n", $canonical);
        foreach (array_keys($lines) as $index) {
            $tampered = $lines;
            $tampered[$index] .= 'x';

            self::assertFalse(
                RequestSigner::verifyCanonicalString(implode("\n", $tampered), $signature, $publicKey),
                sprintf('篡改第 %d 行后验签仍然通过', $index + 1)
            );
        }
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testHeadersMatchVector(array $vector): void
    {
        /** @var array<string, mixed> $request */
        $request = $vector['request'];
        /** @var array<string, string> $expected */
        $expected = $vector['headers'];

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

        foreach ($expected as $name => $value) {
            self::assertArrayHasKey($name, $signed->headers, $name);
            self::assertSame($value, $signed->headers[$name], $name);
        }

        self::assertSame('RSA-SHA256', $signed->headers['X-Signature-Algorithm']);
        // X-Signature-Algorithm 不参与规范串。
        self::assertStringNotContainsString('RSA-SHA256', $signed->canonicalString);
    }

    public function testVectorGroupIsFullyCovered(): void
    {
        self::assertCount(7, self::group('requestSignature'));
    }

    public function testIdempotencyKeyLineIsBinary(): void
    {
        $signer = new RequestSigner(self::config());

        $without = $signer->sign('POST', '/x/y', null, '{}', null, null, [], '1755600000000', 'nonce-vector-0000000001');
        $with = $signer->sign('POST', '/x/y', null, '{}', 'k-1', null, [], '1755600000000', 'nonce-vector-0000000001');

        self::assertSame('', $without->canonicalStringLines()[6]);
        self::assertSame('k-1', $with->canonicalStringLines()[6]);
        self::assertArrayNotHasKey('X-Idempotency-Key', $without->headers);
        self::assertSame('k-1', $with->headers['X-Idempotency-Key']);
        self::assertNotSame($without->signature, $with->signature);
    }

    public function testExternalPathMustNotCarryChainOrVersionPrefix(): void
    {
        $signer = new RequestSigner(self::config());

        $this->expectException(ConfigurationException::class);
        $signer->sign('GET', '/api/v1/consumer/card-products/cards/page');
    }

    public function testInvalidNonceIsRejectedLocally(): void
    {
        $signer = new RequestSigner(self::config());

        $this->expectException(ConfigurationException::class);
        $signer->sign('GET', '/card-products/cards/page', null, null, null, null, [], '1755600000000', 'aGVsbG8=+/');
    }

    public function testMerchantAuthFingerprintMatchesVector(): void
    {
        $signer = new RequestSigner(self::config());

        self::assertSame(self::fingerprint('merchant_auth'), $signer->merchantAuthKeyFingerprint());
    }
}
