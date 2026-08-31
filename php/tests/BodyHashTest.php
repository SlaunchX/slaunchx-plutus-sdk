<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SlaunchX\Plutus\RequestSigner;

final class BodyHashTest extends VectorTestCase
{
    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function vectorProvider(): array
    {
        $cases = [];
        foreach (self::group('bodyHash') as $vector) {
            $cases[(string) $vector['id']] = [$vector];
        }

        return $cases;
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testBodyHashVector(array $vector): void
    {
        $method = $vector['method'] ?? 'POST';
        self::assertIsString($method);

        $digest = RequestSigner::bodyDigestHex($method, $vector['body']);

        self::assertSame($vector['expected'], $digest);
        self::assertSame(
            $vector['forcedEmptyBody'],
            RequestSigner::isForcedEmptyBodyMethod($method)
        );
    }

    public function testVectorGroupIsFullyCovered(): void
    {
        self::assertCount(7, self::group('bodyHash'));
    }

    public function testForcedEmptyBodyMethodsIgnoreActualBody(): void
    {
        foreach (['GET', 'HEAD', 'DELETE', 'get', 'head', 'delete'] as $method) {
            self::assertSame(
                RequestSigner::EMPTY_BODY_SHA256,
                RequestSigner::bodyDigestHex($method, '{"ignored":true}')
            );
        }
    }

    public function testPostHashesActualBytes(): void
    {
        self::assertNotSame(
            RequestSigner::bodyDigestHex('POST', '{"a":1}'),
            RequestSigner::bodyDigestHex('POST', '{"a": 1}')
        );
    }
}
