<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SlaunchX\Plutus\EnvelopeCodec;
use SlaunchX\Plutus\Exception\EnvelopeException;
use SlaunchX\Plutus\PlutusClient;
use SlaunchX\Plutus\Support\Keys;

final class EncryptedEnvelopeTest extends VectorTestCase
{
    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function vectorProvider(): array
    {
        $cases = [];
        foreach (self::group('encryptedEnvelope') as $vector) {
            $cases[(string) $vector['id']] = [$vector];
        }

        return $cases;
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testAadReconstructionAndDecryption(array $vector): void
    {
        /** @var array<string, mixed> $components */
        $components = $vector['aadComponents'];
        /** @var array<string, mixed> $envelope */
        $envelope = $vector['envelope'];

        $aad = EnvelopeCodec::buildAad(
            $components['requestId'],
            $components['routeTemplate'],
            $components['timestamp'],
            $components['keyId'],
        );

        self::assertSame($vector['aadString'], $aad);
        self::assertSame($vector['aadBase64'], base64_encode($aad));
        self::assertSame($aad, base64_decode((string) $envelope['aad'], true));

        $privateKey = Keys::loadPrivateKey(self::privateKeyPem((string) $vector['decryptionKey']));
        $plaintext = EnvelopeCodec::open($envelope, $privateKey, $aad, (string) $components['keyId']);

        self::assertSame($vector['expectedPlaintext'], $plaintext);
    }

    /**
     * API 链信封的 encryptedPayload 是兼容字段, 值恒等于 ciphertext。
     *
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testApiChainEnvelopeShape(array $vector): void
    {
        /** @var array<string, mixed> $envelope */
        $envelope = $vector['envelope'];

        self::assertSame(EnvelopeCodec::ALGORITHM, $envelope['algorithm']);
        self::assertArrayHasKey('encryptedPayload', $envelope);
        self::assertArrayNotHasKey('envelopeVersion', $envelope);
        self::assertSame($envelope['ciphertext'], $envelope['encryptedPayload']);
        self::assertSame(self::fingerprint((string) $vector['decryptionKey']), $envelope['keyFingerprint']);
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testTamperedAadIsRejected(array $vector): void
    {
        /** @var array<string, mixed> $components */
        $components = $vector['aadComponents'];
        /** @var array<string, mixed> $envelope */
        $envelope = $vector['envelope'];
        $privateKey = Keys::loadPrivateKey(self::privateKeyPem((string) $vector['decryptionKey']));

        $mutations = [
            'requestId' => [$components['requestId'] . 'x', $components['routeTemplate'], $components['timestamp'], $components['keyId']],
            'routeTemplate' => [$components['requestId'], $components['routeTemplate'] . '/x', $components['timestamp'], $components['keyId']],
            'timestamp' => [$components['requestId'], $components['routeTemplate'], '1', $components['keyId']],
            'keyId' => [$components['requestId'], $components['routeTemplate'], $components['timestamp'], 'SHA256:00'],
        ];

        foreach ($mutations as $label => [$requestId, $routeTemplate, $timestamp, $keyId]) {
            $aad = EnvelopeCodec::buildAad($requestId, $routeTemplate, $timestamp, $keyId);
            try {
                EnvelopeCodec::open($envelope, $privateKey, $aad);
                self::fail(sprintf('篡改 AAD 分量 %s 后仍然解密成功', $label));
            } catch (EnvelopeException) {
                self::assertTrue(true);
            }
        }
    }

    /**
     * 信封回显的 aad 绝不可当作权威值: 用回显值 + 篡改的密文/AAD 必须失败。
     *
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testTamperedCiphertextIsRejected(array $vector): void
    {
        /** @var array<string, mixed> $components */
        $components = $vector['aadComponents'];
        /** @var array<string, mixed> $envelope */
        $envelope = $vector['envelope'];

        $blob = base64_decode((string) $envelope['ciphertext'], true);
        self::assertIsString($blob);
        $blob[20] = $blob[20] === "\x00" ? "\x01" : "\x00";
        $envelope['ciphertext'] = base64_encode($blob);

        $aad = EnvelopeCodec::buildAad(
            $components['requestId'],
            $components['routeTemplate'],
            $components['timestamp'],
            $components['keyId'],
        );

        $this->expectException(EnvelopeException::class);
        EnvelopeCodec::open(
            $envelope,
            Keys::loadPrivateKey(self::privateKeyPem((string) $vector['decryptionKey'])),
            $aad
        );
    }

    public function testWrongFingerprintIsRejected(): void
    {
        $vector = self::group('encryptedEnvelope')[1];
        /** @var array<string, mixed> $components */
        $components = $vector['aadComponents'];
        $aad = EnvelopeCodec::buildAad(
            $components['requestId'],
            $components['routeTemplate'],
            $components['timestamp'],
            $components['keyId'],
        );

        $this->expectException(EnvelopeException::class);
        EnvelopeCodec::open(
            $vector['envelope'],
            Keys::loadPrivateKey(self::privateKeyPem('merchant_enc')),
            $aad,
            self::fingerprint('platform_enc')
        );
    }

    /**
     * 加密方向由 round-trip 自测: GCM 随机 IV 导致密文无法静态比对。
     */
    public function testRequestEncryptionRoundTrip(): void
    {
        $plaintext = '{"platformCardProductBizId":"pcp_example_001","quantity":2}';
        $routeTemplate = '/card-products/10010106/shared/cards/create';
        $keyId = self::fingerprint('platform_enc');
        $aad = EnvelopeCodec::buildAad('req_local_0001', $routeTemplate, '1755600010000', $keyId);

        $envelope = EnvelopeCodec::seal(
            $plaintext,
            Keys::loadPublicKey(self::publicKeyPem('platform_enc')),
            $keyId,
            $aad
        );

        self::assertSame(EnvelopeCodec::ALGORITHM, $envelope['algorithm']);
        self::assertSame($envelope['ciphertext'], $envelope['encryptedPayload']);
        self::assertSame(base64_encode($aad), $envelope['aad']);

        $blob = base64_decode((string) $envelope['ciphertext'], true);
        self::assertIsString($blob);
        self::assertSame(
            EnvelopeCodec::IV_LENGTH + strlen($plaintext) + EnvelopeCodec::TAG_LENGTH,
            strlen($blob)
        );

        // 平台侧用 platform_enc 私钥解开。
        self::assertSame($plaintext, EnvelopeCodec::open(
            $envelope,
            Keys::loadPrivateKey(self::privateKeyPem('platform_enc')),
            $aad,
            $keyId
        ));
    }

    public function testWebhookShapeRoundTrip(): void
    {
        $plaintext = '{"eventId":"whevt_local_001"}';
        $keyId = 'apk_vector_0001';
        $aad = EnvelopeCodec::buildAad('whd_local_001', 'webhook', '1788142396408', $keyId);

        $envelope = EnvelopeCodec::sealWebhook(
            $plaintext,
            Keys::loadPublicKey(self::publicKeyPem('merchant_enc')),
            self::fingerprint('merchant_enc'),
            $aad
        );

        EnvelopeCodec::assertWebhookShape($envelope);
        self::assertArrayNotHasKey('encryptedPayload', $envelope);
        self::assertSame(1, $envelope['envelopeVersion']);

        self::assertSame($plaintext, EnvelopeCodec::open(
            $envelope,
            Keys::loadPrivateKey(self::privateKeyPem('merchant_enc')),
            $aad,
            self::fingerprint('merchant_enc')
        ));
    }

    public function testWebhookShapeRejectsExtraFields(): void
    {
        $this->expectException(EnvelopeException::class);
        EnvelopeCodec::assertWebhookShape([
            'envelopeVersion' => 1,
            'algorithm' => EnvelopeCodec::ALGORITHM,
            'keyFingerprint' => 'SHA256:00',
            'encryptedKey' => 'x',
            'ciphertext' => 'x',
            'aad' => 'x',
            'encryptedPayload' => 'x',
        ]);
    }

    /**
     * 敏感响应解密: routeTemplate 为空串, timestamp 从信封回显的 aad 解析后重建比对。
     */
    public function testSensitiveResponseDecryptionThroughClient(): void
    {
        $client = new PlutusClient(self::config());

        foreach (self::group('encryptedEnvelope') as $vector) {
            if ($vector['direction'] !== 'sensitive_response') {
                continue;
            }
            /** @var array<string, mixed> $components */
            $components = $vector['aadComponents'];

            self::assertSame('', $components['routeTemplate']);
            self::assertSame(
                $vector['expectedPlaintext'],
                $client->decryptSensitiveEnvelope($vector['envelope'], (string) $components['requestId'])
            );
        }
    }

    public function testSensitiveResponseRejectsWrongRequestId(): void
    {
        $client = new PlutusClient(self::config());
        $vector = self::group('encryptedEnvelope')[1];

        $this->expectException(EnvelopeException::class);
        $client->decryptSensitiveEnvelope($vector['envelope'], 'req_wrong_0001');
    }

    public function testVectorGroupIsFullyCovered(): void
    {
        self::assertCount(3, self::group('encryptedEnvelope'));
    }

    public function testFingerprintsMatchVectors(): void
    {
        foreach (['merchant_auth', 'platform_auth', 'merchant_enc', 'platform_enc'] as $name) {
            self::assertSame(
                self::fingerprint($name),
                Keys::fingerprintFromPem(self::publicKeyPem($name)),
                $name
            );
            Keys::assertRegistrablePublicKeyPem(self::publicKeyPem($name), $name);
        }
    }
}
