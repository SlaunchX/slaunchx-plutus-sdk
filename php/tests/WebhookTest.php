<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SlaunchX\Plutus\EnvelopeCodec;
use SlaunchX\Plutus\Exception\WebhookPayloadException;
use SlaunchX\Plutus\Exception\WebhookSignatureException;
use SlaunchX\Plutus\Support\Keys;
use SlaunchX\Plutus\WebhookHandler;

final class WebhookTest extends VectorTestCase
{
    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function vectorProvider(): array
    {
        $cases = [];
        foreach (self::group('webhook') as $vector) {
            $cases[(string) $vector['id']] = [$vector];
        }

        return $cases;
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testSignatureCanonicalStringAndVerification(array $vector): void
    {
        /** @var array<string, string> $headers */
        $headers = $vector['headers'];
        $body = (string) $vector['body'];

        // Webhook body 摘要是 Base64, 不是小写 hex。
        self::assertSame($vector['bodyDigestBase64'], WebhookHandler::bodyDigestBase64($body));
        self::assertNotSame(hash('sha256', $body), $vector['bodyDigestBase64']);

        $canonical = WebhookHandler::buildCanonicalString(
            $headers['X-SlaunchX-Delivery-Id'],
            $headers['X-SlaunchX-Event-Type'],
            $headers['X-SlaunchX-Timestamp'],
            (string) $vector['bodyDigestBase64'],
        );
        self::assertSame($vector['signatureCanonicalString'], $canonical);

        $verified = openssl_verify(
            $canonical,
            (string) base64_decode($headers['X-SlaunchX-Signature'], true),
            Keys::loadPublicKey(self::publicKeyPem('platform_auth')),
            OPENSSL_ALGO_SHA256
        );
        self::assertSame(1, $verified);

        $handler = new WebhookHandler(self::config());
        $handler->verifySignature($headers, $body);
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testEnvelopeShapeAndDecryption(array $vector): void
    {
        /** @var array<string, string> $headers */
        $headers = $vector['headers'];
        $handler = new WebhookHandler(self::config());

        $envelope = $handler->parseEnvelope((string) $vector['body']);
        self::assertSame(1, $envelope['envelopeVersion']);
        self::assertArrayNotHasKey('encryptedPayload', $envelope);
        self::assertSame(self::fingerprint('merchant_enc'), $envelope['keyFingerprint']);

        /** @var array<string, mixed> $components */
        $components = $vector['aadComponents'];
        $aad = WebhookHandler::buildAad(
            $headers['X-SlaunchX-Delivery-Id'],
            $headers['X-SlaunchX-Timestamp'],
            $headers['X-SlaunchX-Key-Id'],
        );

        self::assertSame($vector['aadString'], $aad);
        self::assertSame($vector['aadBase64'], base64_encode($aad));
        // AAD 第 2 位固定字面量 webhook, 第 4 位是 API Key 业务 ID 而非指纹。
        self::assertSame('webhook', $components['routeTemplate']);
        self::assertSame($headers['X-SlaunchX-Key-Id'], $components['keyId']);
        self::assertStringStartsNotWith('SHA256:', (string) $components['keyId']);

        self::assertSame($vector['expectedPlaintext'], $handler->decrypt($headers, (string) $vector['body']));
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testHandleReturnsCrossCheckedEvent(array $vector): void
    {
        /** @var array<string, string> $headers */
        $headers = $vector['headers'];
        $handler = new WebhookHandler(self::config());

        $event = $handler->handle($headers, (string) $vector['body']);

        self::assertSame($headers['X-SlaunchX-Delivery-Id'], $event->deliveryBizId);
        self::assertSame($headers['X-SlaunchX-Event-Type'], $event->eventType);
        self::assertSame($headers['X-SlaunchX-Timestamp'], $event->timestamp);
        self::assertSame($headers['X-SlaunchX-Key-Id'], $event->keyId);
        self::assertSame($vector['expectedPlaintext'], $event->plaintext);
        self::assertSame(1, $event->payloadSchemaVersion());
        self::assertSame($event->deliveryBizId, $event->payload['deliveryBizId']);
        self::assertNotNull($event->eventId());
        self::assertNotSame([], $event->data());
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testTamperedBodyFailsSignature(array $vector): void
    {
        /** @var array<string, string> $headers */
        $headers = $vector['headers'];
        $handler = new WebhookHandler(self::config());

        $this->expectException(WebhookSignatureException::class);
        $handler->verifySignature($headers, (string) $vector['body'] . ' ');
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testTamperedCanonicalComponentFailsSignature(array $vector): void
    {
        /** @var array<string, string> $headers */
        $headers = $vector['headers'];
        $handler = new WebhookHandler(self::config());

        foreach (['X-SlaunchX-Delivery-Id', 'X-SlaunchX-Event-Type', 'X-SlaunchX-Timestamp'] as $name) {
            $mutated = $headers;
            $mutated[$name] .= '1';

            try {
                $handler->verifySignature($mutated, (string) $vector['body']);
                self::fail(sprintf('篡改 %s 后验签仍然通过', $name));
            } catch (WebhookSignatureException) {
                self::assertTrue(true);
            }
        }
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectorProvider')]
    public function testTamperedAadFailsDecryption(array $vector): void
    {
        /** @var array<string, string> $headers */
        $headers = $vector['headers'];
        $handler = new WebhookHandler(self::config());

        foreach (['X-SlaunchX-Delivery-Id', 'X-SlaunchX-Timestamp', 'X-SlaunchX-Key-Id'] as $name) {
            $mutated = $headers;
            $mutated[$name] .= '9';

            try {
                $handler->decrypt($mutated, (string) $vector['body']);
                self::fail(sprintf('篡改 AAD 分量 %s 后仍然解密成功', $name));
            } catch (WebhookPayloadException) {
                self::assertTrue(true);
            }
        }
    }

    public function testApiChainEnvelopeShapeIsRejected(): void
    {
        $handler = new WebhookHandler(self::config());
        $apiEnvelope = self::group('encryptedEnvelope')[1]['envelope'];

        $this->expectException(WebhookPayloadException::class);
        $handler->parseEnvelope((string) json_encode($apiEnvelope));
    }

    public function testMissingHeaderIsRejected(): void
    {
        $vector = self::group('webhook')[0];
        /** @var array<string, string> $headers */
        $headers = $vector['headers'];
        unset($headers['X-SlaunchX-Timestamp']);

        $handler = new WebhookHandler(self::config());

        $this->expectException(WebhookSignatureException::class);
        $handler->verifySignature($headers, (string) $vector['body']);
    }

    public function testTimestampToleranceIsDisabledByDefault(): void
    {
        $vector = self::group('webhook')[0];
        /** @var array<string, string> $headers */
        $headers = $vector['headers'];

        // 向量时间戳远早于当前时间, 默认容差为 0 (关闭) 时仍应通过。
        $default = new WebhookHandler(self::config());
        $default->verifySignature($headers, (string) $vector['body']);

        $strict = new WebhookHandler(self::config(['webhookTimestampToleranceMs' => 60000]));
        $this->expectException(WebhookSignatureException::class);
        $strict->verifySignature($headers, (string) $vector['body']);
    }

    public function testCrossCheckRejectsMismatchedPlaintext(): void
    {
        $vector = self::group('webhook')[0];
        /** @var array<string, string> $headers */
        $headers = $vector['headers'];

        // 用同一 AAD 重新封装一个 deliveryBizId 不一致的明文, 签名头照旧无法通过,
        // 因此直接验证交叉校验逻辑: 构造 body 后重新签名。
        $plaintext = str_replace('whd_example_001', 'whd_other_001', (string) $vector['expectedPlaintext']);
        $aad = WebhookHandler::buildAad(
            $headers['X-SlaunchX-Delivery-Id'],
            $headers['X-SlaunchX-Timestamp'],
            $headers['X-SlaunchX-Key-Id'],
        );
        $envelope = EnvelopeCodec::sealWebhook(
            $plaintext,
            Keys::loadPublicKey(self::publicKeyPem('merchant_enc')),
            self::fingerprint('merchant_enc'),
            $aad
        );
        $body = (string) json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $canonical = WebhookHandler::buildCanonicalString(
            $headers['X-SlaunchX-Delivery-Id'],
            $headers['X-SlaunchX-Event-Type'],
            $headers['X-SlaunchX-Timestamp'],
            WebhookHandler::bodyDigestBase64($body),
        );
        $signature = '';
        openssl_sign($canonical, $signature, Keys::loadPrivateKey(self::privateKeyPem('platform_auth')), OPENSSL_ALGO_SHA256);
        $headers['X-SlaunchX-Signature'] = base64_encode($signature);

        $handler = new WebhookHandler(self::config());

        $this->expectException(WebhookPayloadException::class);
        $handler->handle($headers, $body);
    }

    public function testVectorGroupIsFullyCovered(): void
    {
        self::assertCount(2, self::group('webhook'));
    }
}
