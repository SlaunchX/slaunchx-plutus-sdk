<?php
declare(strict_types=1);
namespace SlaunchX\Plutus\Tests;

use SlaunchX\Plutus\PlutusConfig;
use SlaunchX\Plutus\RequestSigner;
use SlaunchX\Plutus\Exception\ConfigurationException;

final class ApiVersionTest extends VectorTestCase
{
    public function testMissingVersionIsRejected(): void
    {
        $this->expectException(\ArgumentCountError::class);
        new PlutusConfig(baseUrl: 'https://example.test', apiKey: 'key', merchantAuthPrivateKeyPem: 'unused');
    }

    public function testBlankVersionsAreRejected(): void
    {
        foreach (['', ' ', "\t\n"] as $version) {
            try {
                self::config(['apiVersion' => $version]);
                self::fail('Blank version was accepted');
            } catch (ConfigurationException $error) {
                self::assertStringContainsString('apiVersion', $error->getMessage());
            }
        }
    }

    public function testExplicitVersionIsSigned(): void
    {
        foreach (['1', '2'] as $version) {
            $signed = (new RequestSigner(self::config(['apiVersion' => $version])))->sign('GET', '/test');
            self::assertSame($version, $signed->headers['X-API-VERSION']);
            self::assertSame($version, $signed->canonicalStringLines()[5]);
        }
    }
}
