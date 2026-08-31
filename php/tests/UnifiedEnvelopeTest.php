<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SlaunchX\Plutus\Http\RawResponse;
use SlaunchX\Plutus\Model\ApiResponse;
use SlaunchX\Plutus\Model\ResultCodes;
use SlaunchX\Plutus\RequestSigner;

/**
 * 统一响应包络与成功判定。
 *
 * 用本地 fixture, 不依赖测试向量: 向量只固定签名字节, 不定义业务包络语义。
 */
final class UnifiedEnvelopeTest extends VectorTestCase
{
    /** 标准成功包络。 */
    private const SUCCESS_BODY =
        '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{"ok":true}}';

    private function response(int $status, string $body): ApiResponse
    {
        $signed = (new RequestSigner(self::config()))->sign('GET', '/card-products/cards/page');

        return new ApiResponse($signed, new RawResponse($status, ['Content-Type' => 'application/json'], $body), false);
    }

    /**
     * @return array<string, array{0: int, 1: string, 2: bool, 3: string|null}>
     */
    public static function envelopeProvider(): array
    {
        return [
            '标准成功' => [200, self::SUCCESS_BODY, true, null],
            '创建成功' => [
                201,
                '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2001","message":"Created","data":{}}',
                true,
                null,
            ],
            '待审批成功' => [
                200,
                '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2101","message":"Pending approval","data":{}}',
                true,
                null,
            ],
            '业务失败但 HTTP 200' => [
                200,
                '{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"4022","message":"Validation Error"}',
                false,
                '4022',
            ],
            '网关失败' => [
                401,
                '{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"API.SIGNATURE_INVALID","message":"signature mismatch"}',
                false,
                'API.SIGNATURE_INVALID',
            ],
            '无 success 字段回退到 HTTP 2xx' => [200, '{"data":{}}', true, null],
            '无 success 字段回退到 HTTP 5xx' => [500, '{"message":"boom"}', false, null],
        ];
    }

    #[DataProvider('envelopeProvider')]
    public function testSuccessJudgement(int $status, string $body, bool $expected, ?string $expectedErrorCode): void
    {
        $response = $this->response($status, $body);

        self::assertSame($expected, $response->isSuccess());
        self::assertSame($expectedErrorCode, $response->errorCode());
    }

    /**
     * 只有 JSON 布尔类型的 `success` 才是权威, 其余类型一律走 HTTP 回退。
     *
     * @return array<string, array{0: string}>
     */
    public static function nonBooleanSuccessProvider(): array
    {
        return [
            'success 缺失' => ['{"code":"2000"}'],
            'success 为 null' => ['{"success":null,"code":"2000"}'],
            'success 为字符串' => ['{"success":"true","code":"2000"}'],
            'success 为数字' => ['{"success":1,"code":"2000"}'],
        ];
    }

    #[DataProvider('nonBooleanSuccessProvider')]
    public function testNonBooleanSuccessFallsBackToHttpStatus(string $body): void
    {
        self::assertNull($this->response(200, $body)->successFlag());
        self::assertTrue($this->response(200, $body)->isSuccess());
        self::assertFalse($this->response(400, $body)->isSuccess());
    }

    /**
     * `code == 0` / `code == "0"` 不再被当作成功。
     */
    public function testLegacyZeroCodeIsNotTreatedAsSuccess(): void
    {
        self::assertFalse($this->response(500, '{"code":0}')->isSuccess());
        self::assertSame('0', $this->response(500, '{"code":0}')->errorCode());

        // HTTP 2xx 回退仍然成功, 但成功来自状态码而不是 code。
        $ok = $this->response(200, '{"code":0}');
        self::assertTrue($ok->isSuccess());
        self::assertSame('0', $ok->code());
        self::assertNull($ok->errorCode());
    }

    public function testSuccessResponseExposesEnvelopeFields(): void
    {
        $response = $this->response(200, self::SUCCESS_BODY);

        self::assertTrue($response->successFlag());
        self::assertSame('2.0.0', $response->version());
        self::assertSame(1755600000123, $response->timestampMs());
        self::assertSame('2000', $response->code());
        self::assertNull($response->errorCode());
        self::assertSame(['ok' => true], $response->data());
    }

    /**
     * 数字业务错误码是字符串, 不因"看起来是数字"而被丢弃。
     */
    public function testNumericBusinessErrorCodeIsPreserved(): void
    {
        $response = $this->response(
            200,
            '{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"4022","message":"Validation Error"}'
        );

        self::assertFalse($response->isSuccess());
        self::assertSame('4022', $response->code());
        self::assertSame('4022', $response->errorCode());
        self::assertSame('Validation Error', $response->errorMessage());
    }

    /**
     * 权威字段缺失时才走次级回退。
     */
    public function testSecondaryErrorCodeFallbacks(): void
    {
        self::assertSame('LEGACY.A', $this->response(400, '{"errorCode":"LEGACY.A"}')->errorCode());
        self::assertSame('LEGACY.B', $this->response(400, '{"error_code":"LEGACY.B"}')->errorCode());
        self::assertSame('LEGACY.C', $this->response(400, '{"error":{"code":"LEGACY.C"}}')->errorCode());

        // 权威 code 存在时次级字段不参与。
        self::assertSame(
            'API.SIGNATURE_INVALID',
            $this->response(400, '{"code":"API.SIGNATURE_INVALID","errorCode":"LEGACY.A"}')->errorCode()
        );
    }

    public function testNonJsonBodyFallsBackToHttpStatus(): void
    {
        self::assertTrue($this->response(204, '')->isSuccess());
        self::assertNull($this->response(204, '')->successFlag());
        self::assertFalse($this->response(502, 'upstream down')->isSuccess());
        self::assertNull($this->response(502, 'upstream down')->code());
    }

    public function testSuccessCodesConstantIsDocumentationOnly(): void
    {
        self::assertSame(['2000', '2001', '2002', '2004', '2006', '2101'], ResultCodes::SUCCESS_CODES);
        self::assertSame('2101', ResultCodes::ACCOUNT_PENDING_APPROVAL);

        foreach (ResultCodes::SUCCESS_CODES as $code) {
            self::assertTrue(ResultCodes::isSuccessCode($code));
        }
        self::assertFalse(ResultCodes::isSuccessCode('4022'));
        self::assertFalse(ResultCodes::isSuccessCode('API.SIGNATURE_INVALID'));
        self::assertFalse(ResultCodes::isSuccessCode('0'));

        // 成功码集合不参与判定: code 是成功码但 success:false 时仍判失败。
        $response = $this->response(
            200,
            '{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"2000","message":"forced failure"}'
        );
        self::assertTrue(ResultCodes::isSuccessCode((string) $response->code()));
        self::assertFalse($response->isSuccess());
    }
}
