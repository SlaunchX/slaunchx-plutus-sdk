import { ProtocolProfile, resolveProfile } from './protocol.js';
/**
 * 客户端配置与规范化。
 */

import { randomBytes, type KeyObject } from 'node:crypto';
import { PlutusConfigError } from './errors.js';
import { keyFingerprint, loadPrivateKey, loadPublicKey, type KeyInput } from './keys.js';
import { DEFAULT_API_VERSION } from './signer.js';

/** 四把密钥。除 `merchantAuthPrivateKey` 外按需提供。 */
export interface PlutusKeyMaterial {
  /** 商户认证私钥,签请求。必填 */
  merchantAuthPrivateKey: KeyInput;
  /** 平台认证公钥,验响应签名与 Webhook 签名。启用响应验签时必填 */
  platformAuthPublicKey?: KeyInput;
  /** 商户加密私钥,解密敏感响应与 Webhook。使用这两条链路时必填 */
  merchantEncPrivateKey?: KeyInput;
  /** 平台加密公钥,加密请求体。调用加密端点时必填 */
  platformEncPublicKey?: KeyInput;
}

/** {@link PlutusClient} 配置。 */
export interface PlutusConfig {
  /** Explicit protocol; default preserves Alpha. */
  protocolProfile?: ProtocolProfile;
  /**
   * CONSUMER API 主机根地址,例如 `https://consumer-api.example.com`。不含链/版本/门户前缀。
   *
   * 必须是**对外 CONSUMER API 域名**(边缘/网关地址),绝不能是源站地址,也不能自行拼接
   * `/prometheus`、`/api/v1/consumer` 等内部前缀——这些改写由边缘完成,`path` 只传外部路径
   * (见 `SPEC.md` 第 3 节)。配错 `baseUrl` 是生产环境签名失败最常见的单点原因。
   *
   * ```ts
   * // 正确:baseUrl 为对外域名,path 为外部路径
   * baseUrl: 'https://consumer-api.slaunchx.example'
   * path: '/card-products/10010106/shared/cards/create'
   *
   * // 错误:baseUrl 是源站地址或自行拼接了内部前缀,签名必然失败
   * baseUrl: 'https://origin-host.internal/prometheus/api/v1/consumer'
   * ```
   */
  baseUrl: string;
  /** API Key 业务 ID,写入 `X-Api-Key` */
  apiKey: string;
  /** 密钥材料 */
  keys: PlutusKeyMaterial;
  /** API 契约主版本,默认 `1` */
  apiVersion?: string;
  /** 是否验证响应签名,默认 `true` */
  verifyResponseSignature?: boolean;
  /**
   * 非 2xx 响应缺少 `X-Response-Signature` 时是否也报错,默认 `false`。
   *
   * 默认策略:2xx 缺签名头一律抛验签异常;非 2xx 缺签名头放行,`signatureVerified` 为 `false`,
   * 按类型化 API 错误抛出。置为 `true` 后非 2xx 缺签名头同样抛验签异常。
   */
  requireSignatureOnErrorResponses?: boolean;
  /** 单次请求超时(毫秒),默认 30000;传 `0` 表示不设超时 */
  timeoutMs?: number;
  /** nonce 生成器,默认 16 字节 CSPRNG 的 hex */
  nonceGenerator?: () => string;
  /** 请求 ID 生成器,默认 `req_` + 16 字节 hex */
  requestIdGenerator?: () => string;
  /** 毫秒时钟,默认 `Date.now` */
  now?: () => number;
  /** 注入的 fetch 实现,默认全局 `fetch`(Node >= 18 内置) */
  fetch?: typeof globalThis.fetch;
  /** 附加到每个请求的默认头(不得覆盖签名相关头) */
  defaultHeaders?: Record<string, string>;
  /** `User-Agent` 头,默认 `slaunchx-plutus-sdk-node/<version>` */
  userAgent?: string;
  /**
   * 是否发送规范化后的 query 而非原始 query,默认 `true`。
   * 两者在平台侧等价(SPEC 4.2 要点 7),发送规范化结果可消除本地差异带来的验签风险。
   */
  sendCanonicalQuery?: boolean;
  /** 是否执行严格密钥格式校验,默认 `true` */
  strictKeyValidation?: boolean;
  /** 信封解密的明文长度上限,默认 1 MiB */
  maxPlaintextBytes?: number;
  /**
   * 加密请求的 `routeTemplate` 是否必须属于 {@link ENCRYPTED_ROUTE_TEMPLATES},默认 `false`。
   *
   * 默认(非严格)模式下,未知 `routeTemplate` 不阻断请求,只输出一次警告(见 `routes.ts`
   * 顶部注释的设计取舍)。置为 `true` 后未知 `routeTemplate` 会在本地抛出
   * {@link PlutusRequestError},不发出请求。
   */
  strictEncryptedRouteValidation?: boolean;
}

/** 规范化后的内部配置。 */
export interface ResolvedConfig {
  protocolProfile: ProtocolProfile;
  baseUrl: string;
  apiKey: string;
  apiVersion: string;
  merchantAuthPrivateKey: KeyObject;
  platformAuthPublicKey: KeyObject | null;
  merchantEncPrivateKey: KeyObject | null;
  merchantEncFingerprint: string | null;
  platformEncPublicKey: KeyObject | null;
  platformEncFingerprint: string | null;
  verifyResponseSignature: boolean;
  requireSignatureOnErrorResponses: boolean;
  timeoutMs: number;
  nonceGenerator: (() => string) | undefined;
  requestIdGenerator: () => string;
  now: () => number;
  fetchImpl: typeof globalThis.fetch;
  defaultHeaders: Record<string, string>;
  userAgent: string;
  sendCanonicalQuery: boolean;
  strictKeyValidation: boolean;
  maxPlaintextBytes: number | undefined;
  strictEncryptedRouteValidation: boolean;
}

/** SDK 版本号,写入默认 `User-Agent`。 */
export const SDK_VERSION = '1.0.0';

function normalizeBaseUrl(baseUrl: string): string {
  if (!baseUrl) {
    throw new PlutusConfigError('baseUrl is required');
  }
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch (cause) {
    throw new PlutusConfigError(`baseUrl is not a valid absolute URL: ${baseUrl}`, { cause });
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new PlutusConfigError('baseUrl must use http or https');
  }
  return baseUrl.replace(/\/+$/, '');
}

/**
 * 校验并规范化配置,提前装载全部密钥。
 *
 * @param config - 用户配置
 * @returns 内部使用的规范化配置
 * @throws {PlutusConfigError} 缺必填项或密钥材料非法
 */
export function resolveConfig(config: PlutusConfig): ResolvedConfig {
  if (!config || typeof config !== 'object') {
    throw new PlutusConfigError('config is required');
  }
  if (!config.apiKey) {
    throw new PlutusConfigError('apiKey is required');
  }
  if (!config.keys || !config.keys.merchantAuthPrivateKey) {
    throw new PlutusConfigError('keys.merchantAuthPrivateKey is required');
  }
  const strict = config.strictKeyValidation !== false;
  const verifyResponseSignature = config.verifyResponseSignature !== false;

  const platformAuthPublicKey = config.keys.platformAuthPublicKey
    ? loadPublicKey(config.keys.platformAuthPublicKey, { strict, label: 'platform_auth' })
    : null;
  if (verifyResponseSignature && !platformAuthPublicKey) {
    throw new PlutusConfigError(
      'keys.platformAuthPublicKey is required when verifyResponseSignature is enabled; ' +
        'set verifyResponseSignature: false only if you accept unverified responses',
    );
  }
  const merchantEncPrivateKey = config.keys.merchantEncPrivateKey
    ? loadPrivateKey(config.keys.merchantEncPrivateKey, { strict, label: 'merchant_enc' })
    : null;
  const platformEncPublicKey = config.keys.platformEncPublicKey
    ? loadPublicKey(config.keys.platformEncPublicKey, { strict, label: 'platform_enc' })
    : null;

  const fetchImpl = config.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new PlutusConfigError('global fetch is unavailable; use Node >= 18 or inject config.fetch');
  }

  return {
    protocolProfile: resolveProfile(config.protocolProfile),
    baseUrl: normalizeBaseUrl(config.baseUrl),
    apiKey: config.apiKey,
    apiVersion: config.apiVersion ?? DEFAULT_API_VERSION,
    merchantAuthPrivateKey: loadPrivateKey(config.keys.merchantAuthPrivateKey, {
      strict,
      label: 'merchant_auth',
    }),
    platformAuthPublicKey,
    merchantEncPrivateKey,
    merchantEncFingerprint: merchantEncPrivateKey ? keyFingerprint(merchantEncPrivateKey) : null,
    platformEncPublicKey,
    platformEncFingerprint: platformEncPublicKey ? keyFingerprint(platformEncPublicKey) : null,
    verifyResponseSignature,
    requireSignatureOnErrorResponses: config.requireSignatureOnErrorResponses === true,
    timeoutMs: config.timeoutMs ?? 30_000,
    nonceGenerator: config.nonceGenerator,
    requestIdGenerator: config.requestIdGenerator ?? defaultRequestIdGenerator,
    now: config.now ?? (() => Date.now()),
    fetchImpl: fetchImpl.bind(globalThis),
    defaultHeaders: config.defaultHeaders ?? {},
    userAgent: config.userAgent ?? `slaunchx-plutus-sdk-node/${SDK_VERSION}`,
    sendCanonicalQuery: config.sendCanonicalQuery !== false,
    strictKeyValidation: strict,
    maxPlaintextBytes: config.maxPlaintextBytes,
    strictEncryptedRouteValidation: config.strictEncryptedRouteValidation === true,
  };
}

/** 默认请求 ID 生成器:`req_` + 16 字节 CSPRNG 的 hex。 */
function defaultRequestIdGenerator(): string {
  return `req_${randomBytes(16).toString('hex')}`;
}
