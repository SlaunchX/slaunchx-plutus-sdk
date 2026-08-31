<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SlaunchX\Plutus\Support\Nonce;

final class NonceTest extends TestCase
{
    public function testGeneratedNonceMatchesPlatformPattern(): void
    {
        for ($i = 0; $i < 200; $i++) {
            $nonce = Nonce::generate();
            self::assertMatchesRegularExpression(Nonce::PATTERN, $nonce);
            self::assertSame(43, strlen($nonce));
        }
    }

    public function testBoundaryLengthsAreAccepted(): void
    {
        foreach ([16, 32, 64, 128] as $length) {
            $nonce = Nonce::generate($length);
            self::assertSame($length, strlen($nonce));
            self::assertTrue(Nonce::isValid($nonce));
        }
    }

    public function testGeneratedNoncesAreUnique(): void
    {
        $seen = [];
        for ($i = 0; $i < 1000; $i++) {
            $seen[Nonce::generate()] = true;
        }
        self::assertCount(1000, $seen);
    }

    public function testOutOfRangeLengthIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Nonce::generate(15);
    }

    public function testStandardBase64IsNotAValidNonce(): void
    {
        // 标准 Base64 含 `+` `/` `=`, 均不在 unreserved 集合内。
        self::assertSame('++++////aGVsbG8gd29ybGQ=', base64_encode("\xfb\xef\xbe\xff\xff\xff" . 'hello world'));
        self::assertFalse(Nonce::isValid(base64_encode("\xfb\xef\xbe\xff\xff\xff" . 'hello world')));
        self::assertFalse(Nonce::isValid('short'));
        self::assertFalse(Nonce::isValid(str_repeat('a', 129)));
    }

    public function testUuidWithHyphensIsValid(): void
    {
        self::assertTrue(Nonce::isValid('123e4567-e89b-12d3-a456-426614174000'));
    }
}
