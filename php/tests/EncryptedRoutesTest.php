<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SlaunchX\Plutus\EncryptedRoutes;
use SlaunchX\Plutus\Exception\ConfigurationException;
use SlaunchX\Plutus\Http\RawResponse;
use SlaunchX\Plutus\PlutusClient;

final class EncryptedRoutesTest extends VectorTestCase
{
    /** SPEC.md 第 3 节「已知的加密请求端点」表, 六语言 SDK 共同遵守。 */
    private const EXPECTED_ROUTES = [
        '/card-products/10010105/cards/create',
        '/card-products/10010106/shared/cards/create',
        '/card-products/10010106/prepaid/cards/create',
        '/card-products/10010107/prepaid/cards/create',
        '/card-products/10010107/prepaid/cards/recharge',
        '/card-products/10010107/prepaid/cards/withdraw',
    ];

    /** 标准成功包络 (`code` 2000)。 */
    private const SUCCESS_BODY =
        '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{"ok":true}}';

    public function testConstantTableContainsExactlyTheKnownSixRoutes(): void
    {
        self::assertCount(6, EncryptedRoutes::ROUTES);
        self::assertSame(self::EXPECTED_ROUTES, EncryptedRoutes::ROUTES);

        // 逐字节匹配, 防止大小写 / 末尾斜杠等静默漂移。
        foreach (self::EXPECTED_ROUTES as $index => $route) {
            self::assertSame($route, EncryptedRoutes::ROUTES[$index]);
        }
    }

    public function testIsKnownRecognizesRegisteredRoutes(): void
    {
        foreach (self::EXPECTED_ROUTES as $route) {
            self::assertTrue(EncryptedRoutes::isKnown($route), $route);
        }
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function unknownRouteProvider(): array
    {
        return [
            '完全无关路径' => ['/card-products/cards/page'],
            '已知路径加尾斜杠' => ['/card-products/10010105/cards/create/'],
            '已知路径大小写变体' => ['/Card-Products/10010105/cards/create'],
            '已知路径前缀但更长' => ['/card-products/10010105/cards/create/extra'],
            '空串' => [''],
        ];
    }

    #[DataProvider('unknownRouteProvider')]
    public function testIsKnownRejectsUnknownRoutes(string $route): void
    {
        self::assertFalse(EncryptedRoutes::isKnown($route), $route);
    }

    /**
     * 构造一个**不**校验响应签名的传输, 只需断言请求本身是否被放行/阻断。
     */
    private function fakeTransport(int $status = 200, string $body = self::SUCCESS_BODY): FakeTransport
    {
        return new FakeTransport(static fn (): RawResponse => new RawResponse($status, [
            'Content-Type' => 'application/json;charset=UTF-8',
            'X-Request-Id' => 'req_fake_0001',
        ], $body));
    }

    /**
     * 默认 (非严格) 模式下, 未知路由不阻断加密请求, 请求仍然正常完成。
     */
    public function testDefaultModeAllowsUnknownRouteAndCompletesRequest(): void
    {
        $unknownRoute = '/card-products/unknown/cards/create';
        self::assertFalse(EncryptedRoutes::isKnown($unknownRoute));

        $transport = $this->fakeTransport();
        $client = new PlutusClient(self::config(['verifyResponseSignature' => false]), $transport);

        $response = $client->requestEncrypted(
            'POST',
            $unknownRoute,
            ['foo' => 'bar'],
            ['requestId' => 'req_local_unknown_0001']
        );

        self::assertTrue($response->isSuccess());
        self::assertCount(1, $transport->sent);
        self::assertSame($unknownRoute, $response->request->externalPath);
    }

    /**
     * 默认 (非严格) 模式下, 已知路由不受影响, 正常完成。
     */
    public function testDefaultModeAllowsKnownRoute(): void
    {
        $transport = $this->fakeTransport();
        $client = new PlutusClient(self::config(['verifyResponseSignature' => false]), $transport);

        $response = $client->requestEncrypted(
            'POST',
            '/card-products/10010106/shared/cards/create',
            ['platformCardProductBizId' => 'pcp_example_001', 'quantity' => 1],
            ['requestId' => 'req_local_known_0001']
        );

        self::assertTrue($response->isSuccess());
        self::assertCount(1, $transport->sent);
    }

    /**
     * 严格模式下, 未知路由直接拒绝, 不发出任何请求。
     */
    public function testStrictModeRejectsUnknownRoute(): void
    {
        $unknownRoute = '/card-products/unknown/cards/create';
        $transport = $this->fakeTransport();
        $client = new PlutusClient(
            self::config(['verifyResponseSignature' => false, 'strictEncryptedRouteValidation' => true]),
            $transport
        );

        $this->expectException(ConfigurationException::class);

        try {
            $client->requestEncrypted(
                'POST',
                $unknownRoute,
                ['foo' => 'bar'],
                ['requestId' => 'req_local_unknown_0002']
            );
        } finally {
            self::assertCount(0, $transport->sent, '严格模式拒绝未知路由后不应发出任何请求');
        }
    }

    /**
     * 严格模式下, 已知路由不受影响, 正常完成。
     */
    public function testStrictModeAllowsKnownRoute(): void
    {
        $transport = $this->fakeTransport();
        $client = new PlutusClient(
            self::config(['verifyResponseSignature' => false, 'strictEncryptedRouteValidation' => true]),
            $transport
        );

        $response = $client->requestEncrypted(
            'POST',
            '/card-products/10010107/prepaid/cards/recharge',
            ['platformCardProductBizId' => 'pcp_example_002', 'amount' => '10.00'],
            ['requestId' => 'req_local_known_0002']
        );

        self::assertTrue($response->isSuccess());
        self::assertCount(1, $transport->sent);
    }
}
