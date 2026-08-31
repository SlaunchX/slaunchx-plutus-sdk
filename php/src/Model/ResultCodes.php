<?php

declare(strict_types=1);

namespace SlaunchX\Plutus\Model;

/**
 * 统一响应包络中 `code` 字段的成功码集合。
 *
 * **本类仅供文档与便利用途, 不参与成功判定。** 成功与否的唯一权威是包络里的
 * `success` 布尔字段 (见 {@see ApiResponse::isSuccess()}): 该字段存在且为 JSON 布尔时
 * 直接采用其值, 否则回退到 HTTP 2xx。请勿用 `isSuccessCode()` 代替 `isSuccess()`。
 *
 * 失败时 `code` 为字符串错误码: 网关层是 `域.名称` (如 `API.SIGNATURE_INVALID`),
 * 业务层是 4xxx/5xxx 的数字字符串 (如 `"4022"`)。
 */
final class ResultCodes
{
    /**
     * 成功族码。`"2101"` 表示账号待审批 —— 登录成功但不签发 JWT, `success` 仍为 `true`,
     * 因此它是成功码, 不是错误码。
     *
     * @var array<int, string>
     */
    public const SUCCESS_CODES = ['2000', '2001', '2002', '2004', '2006', '2101'];

    /** 账号待审批: 成功码, 但调用方需引导用户等待审批。 */
    public const ACCOUNT_PENDING_APPROVAL = '2101';

    /**
     * 该码是否属于成功族。
     *
     * 仅作文档与便利用途; **不是**成功判定依据, 判定见 {@see ApiResponse::isSuccess()}。
     */
    public static function isSuccessCode(string $code): bool
    {
        return in_array($code, self::SUCCESS_CODES, true);
    }
}
