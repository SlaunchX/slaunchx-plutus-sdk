/**
 * 统一响应包络与错误映射。
 *
 * 这里只处理传输层公共包络 `{ version, timestamp, success, code, message, data }`,
 * 不建任何业务端点模型。
 */

import { createApiError, type PlutusApiError, type PublicErrorCode } from './errors.js';

/**
 * 平台统一响应包络。
 *
 * 权威形态:
 * ```json
 * {"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{}}
 * ```
 *
 * `success` 是布尔字段,是成功与否的唯一权威;`code` 的权威形态是**字符串**
 * (成功族 `"2000"` 等;失败为 `域.名称` 或 `"4022"` 这样的数字字符串)。
 * 类型上仍允许 `number` 以宽松兼容不规范的上游实现。
 */
export interface ApiResponse<T = unknown> {
  /** 包络版本,如 `"2.0.0"` */
  version?: string;
  /** 服务端毫秒时间戳 */
  timestamp?: number;
  /** 成功与否的唯一权威字段 */
  success?: boolean;
  /** 权威形态为字符串码;成功族见 {@link SUCCESS_CODES} */
  code?: string | number;
  /** 结果或错误消息 */
  message?: string;
  /** 业务数据 */
  data?: T;
  [key: string]: unknown;
}

/**
 * 成功码集合(`"2101"` = 账号待审批:登录成功但不签发 JWT,`success` 仍为 `true`)。
 *
 * 仅供文档与便利判断使用,**不参与**成功判定 —— 成功判定以 `success` 布尔字段为准,
 * 见 {@link isSuccessResponse}。
 */
export const SUCCESS_CODES: ReadonlySet<string> = new Set([
  '2000',
  '2001',
  '2002',
  '2004',
  '2006',
  '2101',
]);

/** 账号待审批的成功码:登录成功但不签发 JWT。 */
export const ACCOUNT_PENDING_APPROVAL = '2101';

/**
 * 判断给定业务码是否属于成功码族。
 *
 * 仅供文档与便利判断使用,**不是**成功判定依据;成功判定见 {@link isSuccessResponse}。
 *
 * @param code - 业务码字符串
 */
export function isSuccessCode(code: string): boolean {
  return SUCCESS_CODES.has(code);
}

/** 限流信息(来自 `X-RateLimit-*` 头)。 */
export interface RateLimitInfo {
  limit: number | null;
  remaining: number | null;
  /** `X-RateLimit-Reset` 原值 */
  reset: string | null;
  /** `Retry-After`(秒) */
  retryAfterSeconds: number | null;
}

/** 一次调用的完整结果。 */
export interface PlutusResponse<T = unknown> {
  /** HTTP 状态码 */
  status: number;
  /** 小写头名快照 */
  headers: Record<string, string>;
  /** 原始响应体字节 */
  rawBody: Buffer;
  /** 解析后的统一响应体;非 JSON 时为 `null` */
  body: ApiResponse<T> | null;
  /** 业务数据(必要时已完成敏感响应解密) */
  data: T;
  /** `X-Request-Id` */
  requestId: string | null;
  /** `X-Operation-Id` */
  operationId: string | null;
  /** 响应签名是否已验证 */
  signatureVerified: boolean;
  /** 本地重建的响应规范串,便于排障 */
  responseCanonicalString: string | null;
  /** 本次请求的 8 行规范串 */
  requestCanonicalString: string;
  /** 请求绑定摘要 */
  requestCanonicalSha256: string;
  /** 限流信息 */
  rateLimit: RateLimitInfo;
}

/**
 * 判断一次调用是否成功。
 *
 * 算法(五语言逐字对齐):
 * 1. 若响应体是 JSON 对象且键 `success` 存在且其值是布尔类型,返回该布尔值;
 * 2. 否则回退到 HTTP 状态:`200 <= status < 300`。
 *
 * 只有**布尔类型**的 `success` 才算权威;缺失、为 `null`、为字符串或数字一律走 HTTP 回退。
 * 业务码(`code`)不参与判定。
 *
 * @param body - 已解析的响应体;非 JSON 或解析失败时传 `null`
 * @param status - HTTP 状态码
 */
export function isSuccessResponse(body: ApiResponse | null | undefined, status: number): boolean {
  if (body && typeof body === 'object' && !Array.isArray(body) && typeof body.success === 'boolean') {
    return body.success;
  }
  return status >= 200 && status < 300;
}

function parseIntOrNull(value: string | undefined): number | null {
  if (value === undefined) {
    return null;
  }
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

/**
 * 从响应头快照中提取限流信息。
 *
 * @param headers - 小写头名快照
 */
export function extractRateLimit(headers: Record<string, string>): RateLimitInfo {
  return {
    limit: parseIntOrNull(headers['x-ratelimit-limit']),
    remaining: parseIntOrNull(headers['x-ratelimit-remaining']),
    reset: headers['x-ratelimit-reset'] ?? null,
    retryAfterSeconds: parseIntOrNull(headers['retry-after']),
  };
}

/**
 * 从响应体中取权威错误码。
 *
 * 主路径是包络的 `code` 字段(数字一律字符串化 —— 业务错误码本来就是 `"4022"`
 * 这样的数字字符串,不得因此丢弃);`errorCode` / `error.code` 仅作次级回退。
 */
function extractErrorCode(body: ApiResponse | null): string | null {
  if (!body || typeof body !== 'object') {
    return null;
  }
  const primary = body.code;
  if (typeof primary === 'string' && primary !== '') {
    return primary;
  }
  if (typeof primary === 'number' && Number.isFinite(primary)) {
    return String(primary);
  }
  const errorCode = body['errorCode'];
  if (typeof errorCode === 'string' && errorCode !== '') {
    return errorCode;
  }
  const nested = body['error'];
  if (nested && typeof nested === 'object') {
    const nestedCode = (nested as Record<string, unknown>)['code'];
    if (typeof nestedCode === 'string' && nestedCode !== '') {
      return nestedCode;
    }
    if (typeof nestedCode === 'number' && Number.isFinite(nestedCode)) {
      return String(nestedCode);
    }
  }
  return null;
}

/** 从响应体中取错误消息:主路径是 `message`,`msg` 作次级回退。 */
function extractErrorMessage(body: ApiResponse | null): string | null {
  if (!body || typeof body !== 'object') {
    return null;
  }
  if (typeof body.message === 'string' && body.message !== '') {
    return body.message;
  }
  const msg = body['msg'];
  return typeof msg === 'string' && msg !== '' ? msg : null;
}

/**
 * 把失败响应映射成类型化错误。
 *
 * @param params - 状态码、响应体与头快照
 * @returns {@link PlutusApiError} 的具体子类实例
 */
export function toApiError(params: {
  status: number;
  body: ApiResponse | null;
  rawBody: Buffer;
  headers: Record<string, string>;
  /** 该错误响应是否通过了响应验签;省略时按 `false` 处理 */
  signatureVerified?: boolean;
}): PlutusApiError {
  const code = extractErrorCode(params.body) as PublicErrorCode | null;
  const message =
    extractErrorMessage(params.body) ?? `SlaunchX API request failed with HTTP ${params.status}`;
  return createApiError({
    status: params.status,
    code,
    message,
    requestId: params.headers['x-request-id'] ?? null,
    operationId: params.headers['x-operation-id'] ?? null,
    retryAfterSeconds: parseIntOrNull(params.headers['retry-after']),
    body: params.body,
    rawBody: params.rawBody,
    headers: params.headers,
    signatureVerified: params.signatureVerified === true,
  });
}
