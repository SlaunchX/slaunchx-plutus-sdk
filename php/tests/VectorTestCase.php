<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SlaunchX\Plutus\PlutusConfig;

/**
 * 黄金测试向量的装载基类。向量文件是协议的最高权威, 与 SPEC 冲突时以向量为准。
 */
abstract class VectorTestCase extends TestCase
{
    /** @var array<string, mixed>|null */
    private static ?array $vectors = null;

    /**
     * @return array<string, mixed>
     */
    protected static function vectors(): array
    {
        if (self::$vectors === null) {
            $path = dirname(__DIR__, 2) . '/shared/test-vectors.json';
            $contents = file_get_contents($path);
            if ($contents === false) {
                throw new RuntimeException('无法读取测试向量: ' . $path);
            }
            $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($decoded)) {
                throw new RuntimeException('测试向量不是 JSON 对象');
            }
            self::$vectors = $decoded;
        }

        return self::$vectors;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    protected static function group(string $name): array
    {
        /** @var array<int, array<string, mixed>> $group */
        $group = self::vectors()['vectors'][$name];

        return $group;
    }

    /**
     * @return array<string, mixed>
     */
    protected static function key(string $name): array
    {
        /** @var array<string, mixed> $key */
        $key = self::vectors()['keys'][$name];

        return $key;
    }

    protected static function privateKeyPem(string $name): string
    {
        return (string) self::key($name)['privateKeyPem'];
    }

    protected static function publicKeyPem(string $name): string
    {
        return (string) self::key($name)['publicKeyPem'];
    }

    protected static function fingerprint(string $name): string
    {
        return (string) self::key($name)['fingerprint'];
    }

    /**
     * 构造一个装载了全部四把测试密钥的配置。
     *
     * @param array<string, mixed> $overrides 覆盖默认构造参数
     */
    protected static function config(array $overrides = []): PlutusConfig
    {
        $defaults = [
            'baseUrl' => 'https://consumer-api.example.test',
            'apiKey' => 'apk_vector_0001',
            'merchantAuthPrivateKeyPem' => self::privateKeyPem('merchant_auth'),
            'platformAuthPublicKeyPem' => self::publicKeyPem('platform_auth'),
            'merchantEncPrivateKeyPem' => self::privateKeyPem('merchant_enc'),
            'platformEncPublicKeyPem' => self::publicKeyPem('platform_enc'),
        ];

        /** @var array<string, mixed> $arguments */
        $arguments = array_merge($defaults, $overrides);

        return new PlutusConfig(...$arguments);
    }
}
