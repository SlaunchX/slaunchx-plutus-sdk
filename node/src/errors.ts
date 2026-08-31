/**
 * SDK 错误体系。
 *
 * 分两类:
 * - 本地错误(配置、规范化、验签、信封):在请求发出前或响应处理时由 SDK 抛出;
 * - 平台错误({@link PlutusApiError} 及其子类):由平台返回的 `域.名称` 错误码映射而来。
 */

/** 平台对外错误码(SPEC 第 13 节)。允许未列出的字符串,以便平台新增码时不破坏类型。 */
export type PublicErrorCode =
  | 'API.KEY_MISSING'
  | 'API.KEY_INVALID'
  | 'API.KEY_DISABLED'
  | 'API.KEY_LOCKED'
  | 'API.TIMESTAMP_REQUIRED'
  | 'API.TIMESTAMP_INVALID'
  | 'API.TIMESTAMP_EXPIRED'
  | 'API.VERSION_REQUIRED'
  | 'API.VERSION_UNSUPPORTED'
  | 'API.ENDPOINT_RETIRED'
  | 'API.NONCE_REQUIRED'
  | 'API.NONCE_INVALID'
  | 'API.NONCE_REUSED'
  | 'API.SIGNATURE_REQUIRED'
  | 'API.SIGNATURE_ALGORITHM_INVALID'
  | 'API.SIGNATURE_INVALID'
  | 'API.IP_NOT_ALLOWED'
  | 'API.WORKSPACE_REQUIRED'
  | 'API.WORKSPACE_UNAVAILABLE'
  | 'ACCESS.PERMISSION_DENIED'
  | 'SECURE_CHANNEL.INVALID_PAYLOAD'
  | 'REQUEST.RATE_LIMITED'
  | 'REQUEST.CONFLICT'
  | 'REQUEST.STALE_VERSION'
  | 'VALIDATION.INVALID_PARAMETER'
  | 'RESOURCE.NOT_FOUND'
  | 'SYSTEM.INTERNAL_ERROR'
  | (string & {});

/** 错误码所属的族(`域.名称` 中的域)。 */
export type ErrorFamily =
  | 'API'
  | 'ACCESS'
  | 'SECURE_CHANNEL'
  | 'REQUEST'
  | 'VALIDATION'
  | 'RESOURCE'
  | 'SYSTEM'
  | 'UNKNOWN';

/** 取错误码的族;无法识别时返回 `UNKNOWN`。 */
export function errorFamily(code: string | number | null | undefined): ErrorFamily {
  if (typeof code !== 'string') {
    return 'UNKNOWN';
  }
  const domain = code.slice(0, Math.max(code.indexOf('.'), 0));
  switch (domain) {
    case 'API':
    case 'ACCESS':
    case 'SECURE_CHANNEL':
    case 'REQUEST':
    case 'VALIDATION':
    case 'RESOURCE':
    case 'SYSTEM':
      return domain;
    default:
      return 'UNKNOWN';
  }
}

/** SDK 全部错误的基类。 */
export class PlutusError extends Error {
  /** 稳定的 SDK 侧错误标识,便于日志检索。 */
  readonly sdkCode: string;

  constructor(sdkCode: string, message: string, options?: { cause?: unknown }) {
    super(message, options as ErrorOptions);
    this.name = new.target.name;
    this.sdkCode = sdkCode;
    Error.captureStackTrace?.(this, new.target);
  }
}

/** 配置非法:缺少必需密钥、baseUrl 格式错误等。 */
export class PlutusConfigError extends PlutusError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('SDK.CONFIG_INVALID', message, options);
  }
}

/** 请求在本地构造阶段即不合法:query 规范化失败、nonce 不合规、缺必填头等。 */
export class PlutusRequestError extends PlutusError {
  constructor(message: string, sdkCode = 'SDK.REQUEST_INVALID', options?: { cause?: unknown }) {
    super(sdkCode, message, options);
  }
}

/** query 规范化被拒绝(裸保留字符 / 非法 %XX / 非 ASCII / 非法 UTF-8)。 */
export class PlutusCanonicalizationError extends PlutusRequestError {
  constructor(message: string) {
    super(message, 'SDK.CANONICALIZATION_FAILED');
  }
}

/** 密钥材料非法:PEM 格式、模数位长、公开指数不满足 SPEC 第 2 节要求。 */
export class PlutusKeyError extends PlutusConfigError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** 响应验签失败或缺少签名头。按安全事故处理:响应体不得交给业务代码。 */
export class PlutusSignatureError extends PlutusError {
  /** 本地重建的响应规范串,便于排障(不含任何密钥材料)。 */
  readonly canonicalString?: string;

  constructor(message: string, canonicalString?: string) {
    super('SDK.RESPONSE_SIGNATURE_INVALID', message);
    this.canonicalString = canonicalString;
  }
}

/** 混合信封处理失败:形状非法、AAD 不匹配、GCM 认证失败、明文超限。 */
export class PlutusEnvelopeError extends PlutusError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('SDK.ENVELOPE_INVALID', message, options);
  }
}

/** Webhook 处理失败:签名不通过、信封形状不符、交叉校验不一致。 */
export class PlutusWebhookError extends PlutusError {
  constructor(message: string, sdkCode = 'SDK.WEBHOOK_INVALID', options?: { cause?: unknown }) {
    super(sdkCode, message, options);
  }
}

/** 网络层失败:连接错误、超时、被取消。 */
export class PlutusTransportError extends PlutusError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('SDK.TRANSPORT_FAILED', message, options);
  }
}

/** {@link PlutusApiError} 的构造入参。 */
export interface PlutusApiErrorInit {
  /** HTTP 状态码。 */
  status: number;
  /** 平台错误码;响应体无法解析时为 `null`。 */
  code: PublicErrorCode | null;
  /** 平台错误消息。 */
  message: string;
  /** `X-Request-Id` 回显。 */
  requestId?: string | null;
  /** `X-Operation-Id`。 */
  operationId?: string | null;
  /** `Retry-After` 头(秒)。 */
  retryAfterSeconds?: number | null;
  /** 已解析的响应体(解析失败时为 `null`)。 */
  body?: unknown;
  /** 原始响应体字节。 */
  rawBody?: Buffer;
  /** 响应头快照(小写头名)。 */
  headers?: Record<string, string>;
  /**
   * 该错误响应是否通过了响应验签。
   *
   * 非 2xx 且缺 `X-Response-Signature` 的响应默认被放行,此时为 `false`,
   * 调用方据此判断错误内容是否可信。
   */
  signatureVerified?: boolean;
}

/** 平台返回的业务/协议错误。按错误码族细分为下方子类。 */
export class PlutusApiError extends PlutusError {
  readonly status: number;
  readonly code: PublicErrorCode | null;
  readonly family: ErrorFamily;
  readonly requestId: string | null;
  readonly operationId: string | null;
  readonly retryAfterSeconds: number | null;
  readonly body: unknown;
  readonly rawBody: Buffer | undefined;
  readonly headers: Record<string, string>;
  /** 该错误响应是否通过了响应验签;非 2xx 缺签名头被放行时为 `false`。 */
  readonly signatureVerified: boolean;

  constructor(init: PlutusApiErrorInit) {
    super(init.code ?? `HTTP.${init.status}`, init.message);
    this.status = init.status;
    this.code = init.code ?? null;
    this.family = errorFamily(init.code);
    this.requestId = init.requestId ?? null;
    this.operationId = init.operationId ?? null;
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
    this.body = init.body ?? null;
    this.rawBody = init.rawBody;
    this.headers = init.headers ?? {};
    this.signatureVerified = init.signatureVerified === true;
  }

  /**
   * 是否值得重试(SPEC 第 13 节「重试建议」)。
   *
   * `TIMESTAMP_EXPIRED` / `NONCE_REUSED` 需要重新生成时间戳与 nonce 后重签,
   * SDK 不会自动复用旧签名。
   */
  get retryable(): boolean {
    if (this.status >= 500) {
      return true;
    }
    switch (this.code) {
      case 'API.TIMESTAMP_EXPIRED':
      case 'API.NONCE_REUSED':
      case 'REQUEST.RATE_LIMITED':
        return true;
      default:
        return false;
    }
  }
}

/** 认证失败:`API.KEY_*` / `API.TIMESTAMP_*` / `API.NONCE_*` / `API.SIGNATURE_*` / `API.VERSION_*`。 */
export class PlutusAuthenticationError extends PlutusApiError {}

/** 授权失败:`ACCESS.PERMISSION_DENIED`、`API.IP_NOT_ALLOWED`、`API.WORKSPACE_UNAVAILABLE`。 */
export class PlutusPermissionError extends PlutusApiError {}

/** 参数校验失败:`VALIDATION.*`。 */
export class PlutusValidationError extends PlutusApiError {}

/** 资源不存在:`RESOURCE.NOT_FOUND`。 */
export class PlutusNotFoundError extends PlutusApiError {}

/** 冲突:`REQUEST.CONFLICT` / `REQUEST.STALE_VERSION`。 */
export class PlutusConflictError extends PlutusApiError {}

/** 限流:`REQUEST.RATE_LIMITED`。按 `retryAfterSeconds` 退避。 */
export class PlutusRateLimitError extends PlutusApiError {}

/** 加密信封被平台拒绝:`SECURE_CHANNEL.INVALID_PAYLOAD`。 */
export class PlutusSecureChannelError extends PlutusApiError {}

/** 平台内部错误:`SYSTEM.*` 或 5xx。 */
export class PlutusServerError extends PlutusApiError {}

/**
 * 按错误码族构造对应的类型化错误。
 *
 * @param init - 错误构造入参
 * @returns {@link PlutusApiError} 的具体子类实例
 */
export function createApiError(init: PlutusApiErrorInit): PlutusApiError {
  const code = init.code ?? '';
  if (code === 'API.IP_NOT_ALLOWED' || code === 'API.WORKSPACE_UNAVAILABLE') {
    return new PlutusPermissionError(init);
  }
  switch (errorFamily(code)) {
    case 'API':
      return new PlutusAuthenticationError(init);
    case 'ACCESS':
      return new PlutusPermissionError(init);
    case 'VALIDATION':
      return new PlutusValidationError(init);
    case 'RESOURCE':
      return new PlutusNotFoundError(init);
    case 'SECURE_CHANNEL':
      return new PlutusSecureChannelError(init);
    case 'SYSTEM':
      return new PlutusServerError(init);
    case 'REQUEST':
      if (code === 'REQUEST.RATE_LIMITED') {
        return new PlutusRateLimitError(init);
      }
      return new PlutusConflictError(init);
    default:
      break;
  }
  // 无法识别错误码时按 HTTP 状态兜底分类。
  if (init.status === 401) {
    return new PlutusAuthenticationError(init);
  }
  if (init.status === 403) {
    return new PlutusPermissionError(init);
  }
  if (init.status === 404) {
    return new PlutusNotFoundError(init);
  }
  if (init.status === 409) {
    return new PlutusConflictError(init);
  }
  if (init.status === 429) {
    return new PlutusRateLimitError(init);
  }
  if (init.status >= 500) {
    return new PlutusServerError(init);
  }
  return new PlutusApiError(init);
}
