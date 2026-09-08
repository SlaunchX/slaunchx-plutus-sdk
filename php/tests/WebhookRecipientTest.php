<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SlaunchX\Plutus\Exception\WebhookPayloadException;
use SlaunchX\Plutus\Exception\WebhookSignatureException;
use SlaunchX\Plutus\ProtocolProfile;
use SlaunchX\Plutus\WebhookHandler;

final class WebhookRecipientTest extends VectorTestCase
{
    public static function entryPoints(): array
    {
        return [
            'product handle' => ['handle', ProtocolProfile::PRODUCT_V1],
            'product decrypt' => ['decrypt', ProtocolProfile::PRODUCT_V1],
            'request-bound handle' => ['handle', ProtocolProfile::REQUEST_BOUND_V1],
            'request-bound decrypt' => ['decrypt', ProtocolProfile::REQUEST_BOUND_V1],
        ];
    }

    #[DataProvider('entryPoints')]
    public function testMatchingRecipientWithSharedEncryptionKeyPasses(string $entry, ProtocolProfile $profile): void
    {
        $vector = self::group('webhook')[0];
        $handler = new WebhookHandler(self::config(['protocolProfile' => $profile]));
        $handler->verifySignature($vector['headers'], $vector['body']);
        $result = $handler->$entry($vector['headers'], $vector['body']);
        self::assertSame($vector['expectedPlaintext'], $entry === 'handle' ? $result->plaintext : $result);
    }

    #[DataProvider('entryPoints')]
    public function testDifferentRecipientSharingSameEncryptionKeysIsRejected(string $entry, ProtocolProfile $profile): void
    {
        $vector = self::group('webhook')[0];
        $correctConfig = self::config(['protocolProfile' => $profile]);
        // API Key B shares ALL key material with A. Only its local API Key business ID differs.
        $otherConfig = self::config(['apiKey' => 'apk_other_recipient', 'protocolProfile' => $profile]);
        self::assertSame($correctConfig->merchantEncPrivateKeyPem, $otherConfig->merchantEncPrivateKeyPem);
        self::assertSame($correctConfig->merchantEncKeyFingerprint(), $otherConfig->merchantEncKeyFingerprint());
        $handler = new WebhookHandler($otherConfig);
        $handler->verifySignature($vector['headers'], $vector['body']);
        $this->expectException(WebhookPayloadException::class);
        $this->expectExceptionMessage('Webhook 接收方 API Key 不匹配');
        $handler->$entry($vector['headers'], $vector['body']);
    }

    #[DataProvider('entryPoints')]
    public function testRewritingRecipientHeaderCannotRetargetEnvelope(string $entry, ProtocolProfile $profile): void
    {
        $vector = self::group('webhook')[0];
        $headers = $vector['headers'];
        $headers[WebhookHandler::HEADER_KEY_ID] = 'apk_other_recipient';
        $handler = new WebhookHandler(self::config(['apiKey' => 'apk_other_recipient', 'protocolProfile' => $profile]));
        // Key ID is not in the signature canonical string. AAD must still bind the recipient.
        $handler->verifySignature($headers, $vector['body']);
        $this->expectException(WebhookPayloadException::class);
        $handler->$entry($headers, $vector['body']);
    }

    public function testHandleVerifiesSignatureBeforeRecipientCheck(): void
    {
        $vector = self::group('webhook')[0];
        $handler = new WebhookHandler(self::config(['apiKey' => 'apk_other_recipient']));
        $this->expectException(WebhookSignatureException::class);
        $handler->handle($vector['headers'], $vector['body'] . ' ');
    }

    #[DataProvider('entryPoints')]
    public function testRecipientIsCheckedBeforeLoadingDecryptionKey(string $entry, ProtocolProfile $profile): void
    {
        $vector = self::group('webhook')[0];
        $handler = new WebhookHandler(self::config([
            'apiKey' => 'apk_other_recipient',
            'merchantEncPrivateKeyPem' => null,
            'protocolProfile' => $profile,
        ]));
        $this->expectException(WebhookPayloadException::class);
        $this->expectExceptionMessage('Webhook 接收方 API Key 不匹配');
        $handler->$entry($vector['headers'], $vector['body']);
    }
}
