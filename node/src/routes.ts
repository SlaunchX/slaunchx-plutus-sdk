/**
 * 已知的加密请求端点(SPEC.md 第 3 节「已知的加密请求端点」表)。
 *
 * 这些外部路径同时也是混合加密信封 AAD 的 `routeTemplate` 分量(SPEC 8.1)。
 * `client.ts` 在 `options.encrypt` 为 `true`(未显式给 `routeTemplate`)时默认取请求的
 * `path` 作为 `routeTemplate`;本模块用于对该取值做一次已知性校验。
 *
 * 设计取舍:默认(非严格)模式下,未知 `routeTemplate` **不会阻断请求**,只输出一次
 * 警告——平台后续新增加密端点时,SDK 若在校验层面写死并 fail-closed,会在版本更新前
 * 让商户对新端点的调用直接失败,体验比“先放行 + 警告”更差。需要强校验的商户可在
 * {@link PlutusConfig.strictEncryptedRouteValidation} 显式开启严格模式,未知路由会
 * 抛出 {@link PlutusRequestError}。
 */

/**
 * 已知加密请求端点的外部路径列表,逐字节对应 SPEC.md 第 3 节表格。
 *
 * 当前全部为 `POST` 方法;顺序与 SPEC 表格一致。
 */
export const ENCRYPTED_ROUTE_TEMPLATES: readonly string[] = [
  '/card-products/10010105/cards/create',
  '/card-products/10010106/shared/cards/create',
  '/card-products/10010106/prepaid/cards/create',
  '/card-products/10010107/prepaid/cards/create',
  '/card-products/10010107/prepaid/cards/recharge',
  '/card-products/10010107/prepaid/cards/withdraw',
];

/**
 * 判断给定的 `routeTemplate` 是否属于 {@link ENCRYPTED_ROUTE_TEMPLATES}。
 *
 * @param routeTemplate - 待判断的外部路径(通常即加密请求的 `path`)
 * @returns 是否在已知加密端点列表中
 */
export function isKnownEncryptedRoute(routeTemplate: string): boolean {
  return ENCRYPTED_ROUTE_TEMPLATES.includes(routeTemplate);
}
