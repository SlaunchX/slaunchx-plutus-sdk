<?php

declare(strict_types=1);

namespace SlaunchX\Plutus;

/**
 * 平台已知的强制加密请求端点常量表。
 *
 * 来源: `SPEC.md` 第 3 节「已知的加密请求端点」, 六语言 SDK 共同遵守。列出的外部路径
 * 均为字面量 (不含路径参数), 用作 {@see PlutusClient::requestEncrypted()} 混合加密信封
 * AAD 的 `routeTemplate` 分量 (见 `SPEC.md` 第 7.3 节)。
 *
 * **设计取舍: 默认不阻断未知路由。** `PlutusClient::requestEncrypted()` 对不在本表中的
 * 外部路径默认只记录一条 `error_log` 提示, 不拒绝请求——平台后续新增加密端点时,
 * 若 SDK 常量表更新滞后, 严格校验会让商户请求被 SDK 本身卡死, 这类失败远比
 * "提示一下但仍放行" 更糟。需要强校验的商户可显式打开
 * `PlutusConfig::$strictEncryptedRouteValidation`, 未知路由会抛出
 * `Exception\ConfigurationException`。
 */
final class EncryptedRoutes
{
    /**
     * 已知的强制加密请求端点外部路径, 均为 `POST`。
     *
     * @var array<int, string>
     */
    public const ROUTES = [
        '/card-products/10010105/cards/create',
        '/card-products/10010106/shared/cards/create',
        '/card-products/10010106/prepaid/cards/create',
        '/card-products/10010107/prepaid/cards/create',
        '/card-products/10010107/prepaid/cards/recharge',
        '/card-products/10010107/prepaid/cards/withdraw',
    ];

    /**
     * 判断外部路径是否在已知加密端点表中 (逐字节比对)。
     */
    public static function isKnown(string $externalPath): bool
    {
        return in_array($externalPath, self::ROUTES, true);
    }
}
