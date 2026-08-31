package com.slaunchx.plutus.sdk.crypto;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 平台已知的强制加密端点常量表(来源: SPEC 3 节「强制加密的请求体」列表,六语言 SDK 一致)。
 *
 * <p>每条记录的 {@link Route#routeTemplate()} 是端点的外部路径(签名 PATH,不含 query 与
 * {@code /api/v1/consumer} 前缀),即 {@link EncryptionAad#forEncryptedRequest} 的
 * {@code routeTemplate} 分量在正常使用下应当取到的值。本表仅用于对照与排障,不参与签名或
 * 加密计算本身。
 *
 * <p><b>设计取舍(默认不阻断, 严格模式可选)。</b> 平台新增加密端点是可预期的演进;若 SDK
 * 对表外路径直接拒绝请求, 会让尚未升级 SDK 版本的商户在平台上线新端点后集体请求失败,
 * 代价远大于收益。因此 {@code PlutusClient} 在加密分支发现未登记路由时, 默认(非严格模式)
 * 仅通过 {@code System.Logger} 打一条 WARNING 级别提示, 不阻断请求; 需要强校验的商户可通过
 * {@code PlutusConfig.Builder#strictEncryptedRouteValidation(boolean)} 开启严格模式,
 * 未登记路由直接抛异常, 已登记路由不受影响。
 */
public final class EncryptedRoutes {

    /**
     * 一条已知加密端点记录。
     *
     * @param routeTemplate 外部路径,即签名 PATH 与 AAD 的 {@code routeTemplate} 分量
     * @param method        HTTP 方法,大写
     */
    public record Route(String routeTemplate, String method) {
    }

    /** SPEC 3 节列出的 6 条强制加密端点,顺序与 SPEC 一致。 */
    private static final List<Route> ROUTES = List.of(
            new Route("/card-products/10010105/cards/create", "POST"),
            new Route("/card-products/10010106/shared/cards/create", "POST"),
            new Route("/card-products/10010106/prepaid/cards/create", "POST"),
            new Route("/card-products/10010107/prepaid/cards/create", "POST"),
            new Route("/card-products/10010107/prepaid/cards/recharge", "POST"),
            new Route("/card-products/10010107/prepaid/cards/withdraw", "POST"));

    private static final Set<String> ROUTE_TEMPLATES = ROUTES.stream()
            .map(Route::routeTemplate)
            .collect(Collectors.toUnmodifiableSet());

    private EncryptedRoutes() {
    }

    /**
     * @return 全部已知加密端点记录,不可变,顺序与 SPEC 3 节一致
     */
    public static List<Route> all() {
        return ROUTES;
    }

    /**
     * @param externalPath 外部路径(签名 PATH),{@code null} 一律判定为未知
     * @return 是否为 SPEC 3 节登记的已知加密端点
     */
    public static boolean isKnown(String externalPath) {
        return externalPath != null && ROUTE_TEMPLATES.contains(externalPath);
    }
}
