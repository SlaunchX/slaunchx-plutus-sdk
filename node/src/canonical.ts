import { ProtocolProfile, resolveProfile, productCanonicalQuery } from './protocol.js';
/**
 * 协议原语:query 规范化、body 摘要、请求/响应规范串、AAD 构造。
 *
 * 本模块不涉及任何密钥材料,可独立用于自查与排障。
 */

import { createHash } from 'node:crypto';
import { PlutusCanonicalizationError, PlutusRequestError } from './errors.js';

/** 空 body 的 SHA-256 摘要(小写 hex)。 */
export const EMPTY_BODY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** 响应规范串首行字面量。 */
export const RESPONSE_CANONICAL_PREFIX = 'SLAUNCHX-API-RESPONSE-V1';

/** 强制使用空 body 摘要的 HTTP 方法。 */
export const FORCED_EMPTY_BODY_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'DELETE']);

/** `X-Nonce` 的合法字符集与长度约束。 */
export const NONCE_PATTERN = /^[A-Za-z0-9._~-]{16,128}$/;

/** RFC 3986 unreserved 字符集(按字节)。 */
const UNRESERVED = (() => {
  const table = new Uint8Array(256);
  const mark = (from: string, to: string): void => {
    for (let c = from.charCodeAt(0); c <= to.charCodeAt(0); c += 1) {
      table[c] = 1;
    }
  };
  mark('A', 'Z');
  mark('a', 'z');
  mark('0', '9');
  for (const ch of ['-', '.', '_', '~']) {
    table[ch.charCodeAt(0)] = 1;
  }
  return table;
})();

const HEX_UPPER = '0123456789ABCDEF';

/** 严格 UTF-8 解码器:遇到非法序列抛错,不做 U+FFFD 替换。 */
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });

function hexDigit(ch: string): number {
  const c = ch.charCodeAt(0);
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  return -1;
}

/**
 * 严格 percent-decode。
 *
 * 只接受 unreserved 字面量与合法的 `%XX`;任何裸保留字符、裸非 ASCII、
 * 截断或非法的 percent 转义、以及解码后非法的 UTF-8 序列都会被拒绝。
 *
 * @param component - query 的 key 或 value 原始片段
 * @returns 解码后的字节
 * @throws {PlutusCanonicalizationError} 片段不满足严格解码规则
 */
export function percentDecodeStrict(component: string): Buffer {
  const out: number[] = [];
  let i = 0;
  const n = component.length;
  while (i < n) {
    const ch = component.charAt(i);
    if (ch === '%') {
      if (i + 2 >= n) {
        throw new PlutusCanonicalizationError('query component contains incomplete percent encoding');
      }
      const hi = hexDigit(component.charAt(i + 1));
      const lo = hexDigit(component.charAt(i + 2));
      if (hi < 0 || lo < 0) {
        throw new PlutusCanonicalizationError('query component contains invalid percent encoding');
      }
      out.push(hi * 16 + lo);
      i += 3;
      continue;
    }
    const code = component.charCodeAt(i);
    if (code > 0x7f || UNRESERVED[code] !== 1) {
      throw new PlutusCanonicalizationError(
        'query component must use RFC 3986 percent encoding for reserved characters',
      );
    }
    out.push(code);
    i += 1;
  }
  const bytes = Buffer.from(out);
  try {
    STRICT_UTF8.decode(bytes);
  } catch (cause) {
    throw new PlutusCanonicalizationError('query component contains invalid UTF-8');
  }
  return bytes;
}

/**
 * RFC 3986 percent-encode:unreserved 字节原样输出,其余编码为大写 `%XX`。
 *
 * @param bytes - 待编码字节(通常是 UTF-8 编码后的文本)
 * @returns 纯 ASCII 的编码结果
 */
export function percentEncode(bytes: Uint8Array | string): string {
  const raw = typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : bytes;
  let out = '';
  for (const b of raw) {
    if (UNRESERVED[b] === 1) {
      out += String.fromCharCode(b);
    } else {
      out += `%${HEX_UPPER[b >> 4]}${HEX_UPPER[b & 0x0f]}`;
    }
  }
  return out;
}

/**
 * 规范化单个 query 分量:严格解码后再按 RFC 3986 重编码。
 *
 * @param component - key 或 value 原始片段
 * @returns 规范化后的 ASCII 串
 */
export function canonicalizeComponent(component: string): string {
  return percentEncode(percentDecodeStrict(component));
}

/**
 * 判断字符串是否为「Java `String.trim()` 语义」下的空白串。
 *
 * 服务端为 Java 实现,`trim()` 只裁剪码点 <= U+0020 的字符。SDK 与之对齐:
 * 只有全部由这些字符组成的 query 才视作空;其它 Unicode 空白会走严格解码从而被拒绝。
 */
function isBlankJavaTrim(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    if (value.charCodeAt(i) > 0x20) {
      return false;
    }
  }
  return true;
}

/**
 * Query 规范化(SPEC 4.2)。
 *
 * 算法:严格解码 → RFC 3986 重编码 → 按 (key, value) 字节序升序排序 → 以 `key=value` 用 `&` 重组。
 *
 * @param query - 原始 query 串,不含前导 `?`;`null` / 空 / 全空白返回空串
 * @returns 规范化后的 query 串
 * @throws {PlutusCanonicalizationError} 存在裸保留字符、非法 percent 转义或非法 UTF-8
 *
 * @example
 * canonicalizeQuery('b=2&a=1');            // 'a=1&b=2'
 * canonicalizeQuery('flag&a=1');           // 'a=1&flag='
 * canonicalizeQuery('q=a+b');              // 抛错: 裸 '+' 不表示空格
 */
export function canonicalizeQuery(query: string | null | undefined, protocolProfile: ProtocolProfile = ProtocolProfile.REQUEST_BOUND_V1): string {
  if (resolveProfile(protocolProfile) === ProtocolProfile.PRODUCT_V1) return productCanonicalQuery(query);
  if (query === null || query === undefined || isBlankJavaTrim(query)) {
    return '';
  }
  const pairs: Array<[string, string]> = [];
  for (const segment of query.split('&')) {
    const idx = segment.indexOf('=');
    const rawKey = idx < 0 ? segment : segment.slice(0, idx);
    const rawValue = idx < 0 ? '' : segment.slice(idx + 1);
    pairs.push([canonicalizeComponent(rawKey), canonicalizeComponent(rawValue)]);
  }
  pairs.sort((a, b) => {
    if (a[0] !== b[0]) {
      return a[0] < b[0] ? -1 : 1;
    }
    if (a[1] !== b[1]) {
      return a[1] < b[1] ? -1 : 1;
    }
    return 0;
  });
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
}

/** {@link encodeQueryParams} 可接受的参数值类型。 */
export type QueryParamValue = string | number | boolean | null | undefined;

/**
 * 把参数对象编码成满足严格规范化要求的 query 串。
 *
 * 全部 key/value 按 RFC 3986 编码(空格为 `%20`,`+` 为 `%2B`),因此结果一定能通过
 * {@link canonicalizeQuery}。值为 `null` / `undefined` 的键会被跳过;数组展开为重复键。
 *
 * @param params - 参数对象
 * @returns 原始 query 串;无有效参数时返回空串
 */
export function encodeQueryParams(
  params: Record<string, QueryParamValue | readonly QueryParamValue[]> | null | undefined,
): string {
  if (!params) {
    return '';
  }
  const parts: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    const values = Array.isArray(value) ? value : [value];
    for (const item of values) {
      if (item === null || item === undefined) {
        continue;
      }
      parts.push(`${percentEncode(key)}=${percentEncode(String(item))}`);
    }
  }
  return parts.join('&');
}

/**
 * 计算 body 摘要(小写 hex)。
 *
 * @param body - 原始 body 字节;`null` / 空视为空 body
 * @returns 64 位小写十六进制摘要
 */
export function bodyDigestHex(body: Uint8Array | null | undefined): string {
  if (!body || body.byteLength === 0) {
    return EMPTY_BODY_SHA256;
  }
  return createHash('sha256').update(body).digest('hex');
}

/**
 * 判断该方法是否强制使用空 body 摘要。
 *
 * @param method - HTTP 方法(不区分大小写)
 */
export function isForcedEmptyBodyMethod(method: string): boolean {
  return FORCED_EMPTY_BODY_METHODS.has(method.toUpperCase());
}

/**
 * 按方法规则计算参与签名的 body 摘要。
 *
 * `GET` / `HEAD` / `DELETE` 一律返回空 body 摘要,即使实际携带了 body。
 *
 * @param method - HTTP 方法
 * @param body - 实际发送的 body 字节
 */
export function signedBodyDigest(method: string, body: Uint8Array | null | undefined): string {
  return isForcedEmptyBodyMethod(method) ? EMPTY_BODY_SHA256 : bodyDigestHex(body);
}

/** 请求规范串的构造入参。 */
export interface RequestCanonicalInput {
  protocolProfile?: ProtocolProfile;
  /** HTTP 方法,大写 */
  method: string;
  /** 外部路径,以 `/` 开头,不含 query,不做编码变换 */
  externalPath: string;
  /** 已规范化的 query;无 query 时为空串 */
  canonicalQuery: string;
  /** `X-Timestamp` 原值(Unix 毫秒十进制串) */
  timestamp: string;
  /** `X-Nonce` 原值 */
  nonce: string;
  /** `X-API-VERSION` 原值 */
  apiVersion: string;
  /** `X-Idempotency-Key` 原值;不发送该头时为 `null` */
  idempotencyKey?: string | null;
  /** body 摘要(小写 hex) */
  bodyDigest: string;
}

/**
 * 拼装 8 行请求规范串(SPEC 4.1)。
 *
 * @param input - 各行取值
 * @returns 以 LF 连接、无尾换行的规范串
 * @throws {PlutusRequestError} 必填分量缺失
 */
export function buildRequestCanonicalString(input: RequestCanonicalInput): string {
  if (!input.method) {
    throw new PlutusRequestError('method is required');
  }
  if (!input.externalPath || !input.externalPath.startsWith('/')) {
    throw new PlutusRequestError('externalPath must start with "/"');
  }
  if (!input.timestamp) {
    throw new PlutusRequestError('timestamp is required');
  }
  if (!input.nonce) {
    throw new PlutusRequestError('nonce is required');
  }
  if (!input.apiVersion || isBlankJavaTrim(input.apiVersion)) {
    throw new PlutusRequestError('apiVersion is required');
  }
  if (!input.bodyDigest) {
    throw new PlutusRequestError('bodyDigest is required');
  }
  return [
    input.method,
    input.externalPath,
    input.canonicalQuery,
    input.timestamp,
    input.nonce,
    input.apiVersion,
    ...(resolveProfile(input.protocolProfile) === ProtocolProfile.PRODUCT_V1 ? [] : [input.idempotencyKey ?? '']),
    input.bodyDigest,
  ].join('\n');
}

/**
 * 计算请求绑定摘要(SPEC 6.1):对请求规范串本身再做一次 SHA-256。
 *
 * @param canonicalString - 8 行请求规范串
 * @returns 64 位小写十六进制摘要
 */
export function requestCanonicalSha256(canonicalString: string): string {
  return createHash('sha256').update(canonicalString, 'utf8').digest('hex');
}

/** 响应规范串的构造入参。 */
export interface ResponseCanonicalInput {
  protocolProfile?: ProtocolProfile;
  /** 本地计算的请求绑定摘要;严禁从响应头读取 */
  requestCanonicalSha256: string;
  /** 本次请求的 `X-API-VERSION` */
  apiVersion: string;
  /** 本次请求的外部路径 */
  externalPath: string;
  /** 响应头 `X-Operation-Id`;无则 `null` */
  operationId?: string | null;
  /** 响应头 `X-Request-Id`;无则 `null` */
  requestId?: string | null;
  /** HTTP 状态码 */
  httpStatus: number;
  /** 响应头 `Content-Type` 原值,不做归一化 */
  contentType?: string | null;
  /** 响应头 `X-Response-Timestamp` 原值 */
  responseTimestamp?: string | null;
  /** 响应体摘要(小写 hex) */
  responseBodyDigest: string;
}

/**
 * 拼装 10 行响应规范串(SPEC 6.2)。
 *
 * @param input - 各行取值
 * @returns 以 LF 连接、无尾换行的规范串
 */
export function buildResponseCanonicalString(input: ResponseCanonicalInput): string {
  if (resolveProfile(input.protocolProfile) === ProtocolProfile.PRODUCT_V1) {
    return [input.requestId ?? '', String(input.httpStatus), input.contentType ?? '', input.responseTimestamp ?? '', input.responseBodyDigest].join('\n');
  }
  return [
    RESPONSE_CANONICAL_PREFIX,
    input.requestCanonicalSha256,
    input.apiVersion,
    input.externalPath,
    input.operationId ?? '',
    input.requestId ?? '',
    String(input.httpStatus),
    input.contentType ?? '',
    input.responseTimestamp ?? '',
    input.responseBodyDigest,
  ].join('\n');
}

/** 混合信封 AAD 的四个分量(SPEC 7.3)。 */
export interface AadComponents {
  /** 加密请求为 `X-Request-Id`;敏感响应为关联 ID(可能为空串);Webhook 为 `deliveryBizId` */
  requestId: string | null;
  /** 加密请求为外部路径;敏感响应为空串;Webhook 为字面量 `webhook` */
  routeTemplate: string | null;
  /** 毫秒时间戳字符串 */
  timestamp: string | null;
  /** 加密请求/敏感响应为公钥指纹;Webhook 为 API Key 业务 ID */
  keyId: string | null;
}

/**
 * 构造 AAD 字节:`requestId | routeTemplate | timestamp | keyId`,分量为 `null` 时按空串处理。
 *
 * @param components - 四个分量
 * @returns UTF-8 编码的 AAD 字节
 */
export function buildAad(components: AadComponents): Buffer {
  return Buffer.from(
    [
      components.requestId ?? '',
      components.routeTemplate ?? '',
      components.timestamp ?? '',
      components.keyId ?? '',
    ].join('|'),
    'utf8',
  );
}

/**
 * Webhook 签名规范串(SPEC 10.2):4 行,LF 连接,无尾换行。
 *
 * 注意第 4 行的 body 摘要是 **Base64**,不是 API 链使用的小写 hex。
 *
 * @param deliveryBizId - `X-SlaunchX-Delivery-Id`
 * @param eventType - `X-SlaunchX-Event-Type`
 * @param timestamp - `X-SlaunchX-Timestamp`
 * @param bodyDigestBase64 - `Base64(SHA256(原始 body 字节))`
 */
export function buildWebhookCanonicalString(
  deliveryBizId: string,
  eventType: string,
  timestamp: string,
  bodyDigestBase64: string,
): string {
  return [deliveryBizId, eventType, timestamp, bodyDigestBase64].join('\n');
}

/**
 * Webhook body 摘要:`Base64(SHA256(原始 body 字节))`。
 *
 * @param body - 原始 HTTP body 字节
 */
export function webhookBodyDigestBase64(body: Uint8Array): string {
  return createHash('sha256').update(body).digest('base64');
}

/**
 * 校验 nonce 是否满足 `^[A-Za-z0-9._~-]{16,128}$`。
 *
 * @param nonce - 待校验的 nonce
 */
export function isValidNonce(nonce: string): boolean {
  return NONCE_PATTERN.test(nonce);
}
