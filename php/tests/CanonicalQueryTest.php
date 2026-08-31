<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SlaunchX\Plutus\Exception\CanonicalizationException;
use SlaunchX\Plutus\RequestSigner;
use SlaunchX\Plutus\Support\CanonicalQuery;

final class CanonicalQueryTest extends VectorTestCase
{
    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function vectorProvider(): array
    {
        $cases = [];
        foreach (self::group('canonicalQuery') as $vector) {
            $cases[(string) $vector['id']] = [$vector];
        }

        return $cases;
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testCanonicalQueryVector(array $vector): void
    {
        $input = $vector['input'];
        self::assertTrue($input === null || is_string($input));

        if ($vector['expectError'] === true) {
            $this->expectException(CanonicalizationException::class);
            CanonicalQuery::canonicalize($input);

            return;
        }

        self::assertSame($vector['expected'], CanonicalQuery::canonicalize($input));
        self::assertSame($vector['expected'], RequestSigner::canonicalizeQuery($input));
    }

    public function testVectorGroupIsFullyCovered(): void
    {
        $group = self::group('canonicalQuery');
        self::assertCount(21, $group);

        $rejections = array_filter($group, static fn (array $vector): bool => $vector['expectError'] === true);
        self::assertCount(6, $rejections);
    }

    public function testBuildProducesCanonicalizableQuery(): void
    {
        $raw = CanonicalQuery::build(['q' => 'hello world', 'sign' => '+1', 'a' => ['2', '1']]);

        self::assertSame('q=hello%20world&sign=%2B1&a=2&a=1', $raw);
        self::assertSame('a=1&a=2&q=hello%20world&sign=%2B1', CanonicalQuery::canonicalize($raw));
    }

    public function testRawPlusIsNotASpace(): void
    {
        $this->expectException(CanonicalizationException::class);
        CanonicalQuery::canonicalize('q=a+b');
    }
}
