/**
 * 通用 HTTP 客户端:组装签名头、一次序列化 body、对同一字节签名并发送,再验签与解析响应。
 */

import type { KeyObject } from 'node:crypto';
import { canonicalizeQuery, encodeQueryParams } from './canonical.js';
import { resolveConfig, type PlutusConfig, type ResolvedConfig } from './config.js';
import { EnvelopeCodec, type HybridEnvelope } from './envelope.js';
import { PlutusConfigError, PlutusRequestError, PlutusTransportError } from './errors.js';
import { keyFingerprint } from './keys.js';
import { isKnownEncryptedRoute } from './routes.js';
import {
  extractRateLimit,
  isSuccessResponse,
  toApiError,
  type ApiResponse,
  type PlutusResponse,
} from './response.js';
import { RequestSigner, type QueryInput, type SignedRequest } from './signer.js';
import { ResponseVerifier, snapshotHeaders } from './verifier.js';

/** 单次调用的入参。 */
export interface PlutusRequestOptions {
  /** HTTP 方法 */
  method: string;
  /** 外部路径,以 `/` 开头,不含链/版本/门户前缀 */
  path: string;
  /** query:原始串或参数对象 */
  query?: QueryInput;
  /**
   * 请求体。对象会用 `JSON.stringify` 序列化一次;字符串按 UTF-8 编码;
   * `Uint8Array` 原样使用。序列化结果同时用于摘要与发送。
   */
  body?: unknown;
  /** 覆盖 `Content-Type`,默认有 body 时为 `application/json` */
  contentType?: string;
  /** 附加请求头。不得覆盖签名相关头 */
  headers?: Record<string, string>;
  /** `X-Idempotency-Key`;发送即参与签名 */
  idempotencyKey?: string;
  /** `X-Request-Id`;加密端点必填,未传时自动生成 */
  requestId?: string;
  /**
   * 是否加密请求体(SPEC 第 8 节)。传 `true` 用 `path` 作为 AAD 的 `routeTemplate`;
   * 传对象可覆盖 `routeTemplate`。
   */
  encrypt?: boolean | { routeTemplate?: string };
  /**
   * 响应 `data` 为混合信封时是否自动解密(SPEC 第 9 节),默认 `false`。
   * 启用需配置 `keys.merchantEncPrivateKey`。
   */
  decryptResponse?: boolean;
  /** 覆盖超时(毫秒);`0` 表示不设超时 */
  timeoutMs?: number;
  /** 外部取消信号 */
  signal?: AbortSignal;
  /** 覆盖 nonce(仅测试与重放排障使用) */
  nonce?: string;
  /** 覆盖时间戳(仅测试使用) */
  timestamp?: string;
}

function isPlainBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

/**
 * 把请求体序列化成**一个**不可变字节数组。
 *
 * @param body - 原始 body 入参
 * @returns 字节与推断出的 Content-Type
 */
export function serializeBody(body: unknown): { bytes: Buffer | null; contentType: string | null } {
  if (body === undefined || body === null) {
    return { bytes: null, contentType: null };
  }
  if (isPlainBytes(body)) {
    return { bytes: Buffer.from(body), contentType: null };
  }
  if (typeof body === 'string') {
    return { bytes: Buffer.from(body, 'utf8'), contentType: 'application/json' };
  }
  return { bytes: Buffer.from(JSON.stringify(body), 'utf8'), contentType: 'application/json' };
}

/**
 * SlaunchX Plutus 商户 API 客户端。
 *
 * 只负责传输层:签名、加密、验签、解密与统一错误映射;不封装任何业务端点。
 *
 * @example
 * const client = new PlutusClient({
 *   baseUrl: 'https://consumer-api.example.com',
 *   apiKey: 'apk_xxx',
 *   keys: { merchantAuthPrivateKey, platformAuthPublicKey },
 * });
 * const res = await client.request({ method: 'GET', path: '/card-products/cards/page', query: { pageSize: 20 } });
 */
export class PlutusClient {
  private readonly config: ResolvedConfig;
  private readonly signer: RequestSigner;
  private readonly verifier: ResponseVerifier | null;

  constructor(config: PlutusConfig) {
    this.config = resolveConfig(config);
    this.signer = new RequestSigner({
      apiKey: this.config.apiKey,
      merchantAuthPrivateKey: this.config.merchantAuthPrivateKey,
      apiVersion: this.config.apiVersion,
      nonceGenerator: this.config.nonceGenerator,
      now: this.config.now,
      strictKeyValidation: this.config.strictKeyValidation,
    });
    this.verifier =
      this.config.verifyResponseSignature && this.config.platformAuthPublicKey
        ? new ResponseVerifier({
            platformAuthPublicKey: this.config.platformAuthPublicKey,
            requireSignatureOnErrorResponses: this.config.requireSignatureOnErrorResponses,
            strictKeyValidation: this.config.strictKeyValidation,
          })
        : null;
  }

  /** 平台加密公钥指纹(`X-Platform-Encryption-Key-Id` 的取值);未配置时为 `null`。 */
  get platformEncryptionKeyId(): string | null {
    return this.config.platformEncFingerprint;
  }

  /** 商户加密公钥指纹,用于核对敏感响应/Webhook 信封的 `keyFingerprint`。 */
  get merchantEncryptionKeyId(): string | null {
    return this.config.merchantEncFingerprint;
  }

  /** 仅签名,不发送。用于自定义传输层或排障。 */
  signOnly(options: Omit<PlutusRequestOptions, 'decryptResponse' | 'signal' | 'timeoutMs'>): {
    signed: SignedRequest;
    url: string;
    bodyBytes: Buffer | null;
    headers: Record<string, string>;
  } {
    return this.prepare(options);
  }

  /**
   * 发起一次已签名(必要时已加密)的调用。
   *
   * @param options - 请求描述
   * @returns 已验签并解析的响应
   * @throws {PlutusApiError} 响应判定为失败(`success: false`,或缺 `success` 字段且 HTTP 非 2xx)
   * @throws {PlutusSignatureError} 响应验签失败
   * @throws {PlutusTransportError} 网络错误或超时
   */
  async request<T = unknown>(options: PlutusRequestOptions): Promise<PlutusResponse<T>> {
    const { signed, url, bodyBytes, headers } = this.prepare(options);

    const controller = new AbortController();
    const timeoutMs = options.timeoutMs ?? this.config.timeoutMs;
    const timer =
      timeoutMs > 0
        ? setTimeout(() => controller.abort(new Error(`request timed out after ${timeoutMs}ms`)), timeoutMs)
        : null;
    const onExternalAbort = (): void => controller.abort(options.signal?.reason);
    if (options.signal) {
      if (options.signal.aborted) {
        onExternalAbort();
      } else {
        options.signal.addEventListener('abort', onExternalAbort, { once: true });
      }
    }

    let raw: Response;
    try {
      raw = await this.config.fetchImpl(url, {
        method: signed.method,
        headers,
        body: bodyBytes ? new Uint8Array(bodyBytes) : undefined,
        signal: controller.signal,
      });
    } catch (cause) {
      throw new PlutusTransportError(
        cause instanceof Error ? `HTTP transport failed: ${cause.message}` : 'HTTP transport failed',
        { cause },
      );
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
      options.signal?.removeEventListener('abort', onExternalAbort);
    }

    const rawBody = Buffer.from(await raw.arrayBuffer());
    const headerSnapshot = snapshotHeaders(raw.headers);

    let responseCanonicalString: string | null = null;
    let signatureVerified = false;
    if (this.verifier) {
      const result = this.verifier.verify({
        requestCanonicalSha256: signed.requestCanonicalSha256,
        apiVersion: signed.apiVersion,
        externalPath: signed.externalPath,
        status: raw.status,
        headers: raw.headers,
        body: rawBody,
      });
      responseCanonicalString = result.canonicalString;
      signatureVerified = result.verified;
    }

    let body: ApiResponse<T> | null = null;
    if (rawBody.byteLength > 0) {
      try {
        body = JSON.parse(rawBody.toString('utf8')) as ApiResponse<T>;
      } catch {
        body = null;
      }
    }

    if (!isSuccessResponse(body as ApiResponse | null, raw.status)) {
      throw toApiError({
        status: raw.status,
        body: body as ApiResponse | null,
        rawBody,
        headers: headerSnapshot,
        signatureVerified,
      });
    }

    let data = body?.data as T;
    if (options.decryptResponse && isEnvelopeLike(data)) {
      data = this.decryptSensitiveResponse<T>(data as unknown as HybridEnvelope, {
        requestId: headerSnapshot['x-request-id'] ?? null,
      });
    }

    return {
      status: raw.status,
      headers: headerSnapshot,
      rawBody,
      body,
      data,
      requestId: headerSnapshot['x-request-id'] ?? null,
      operationId: headerSnapshot['x-operation-id'] ?? null,
      signatureVerified,
      responseCanonicalString,
      requestCanonicalString: signed.canonicalString,
      requestCanonicalSha256: signed.requestCanonicalSha256,
      rateLimit: extractRateLimit(headerSnapshot),
    };
  }

  /**
   * 解密响应中的敏感信封(SPEC 第 9 节)。
   *
   * @param envelope - 响应体中的混合信封
   * @param params - 期望的关联请求 ID(`undefined` 表示不校验)
   * @returns 解析后的明文对象
   */
  decryptSensitiveResponse<T = unknown>(
    envelope: HybridEnvelope,
    params: { requestId?: string | null } = {},
  ): T {
    const privateKey = this.requireMerchantEncPrivateKey();
    const { plaintext } = EnvelopeCodec.openSensitiveResponse(envelope, {
      merchantEncPrivateKey: privateKey,
      requestId: params.requestId,
      expectedKeyFingerprint: this.config.merchantEncFingerprint ?? undefined,
      maxPlaintextBytes: this.config.maxPlaintextBytes,
      strictKeyValidation: this.config.strictKeyValidation,
    });
    return JSON.parse(plaintext.toString('utf8')) as T;
  }

  private requireMerchantEncPrivateKey(): KeyObject {
    if (!this.config.merchantEncPrivateKey) {
      throw new PlutusConfigError('keys.merchantEncPrivateKey is required to decrypt sensitive responses');
    }
    return this.config.merchantEncPrivateKey;
  }

  private prepare(options: PlutusRequestOptions): {
    signed: SignedRequest;
    url: string;
    bodyBytes: Buffer | null;
    headers: Record<string, string>;
  } {
    const method = options.method.toUpperCase();
    const rawQuery =
      typeof options.query === 'string' || options.query == null
        ? options.query ?? ''
        : encodeQueryParams(options.query);
    const canonicalQuery = canonicalizeQuery(rawQuery);

    // 时间戳必须先于加密生成:AAD 第三分量与签名第 4 行必须是同一个值。
    const timestamp = options.timestamp ?? String(this.config.now());
    const requestId = options.requestId ?? (options.encrypt ? this.config.requestIdGenerator() : undefined);

    let bodyBytes: Buffer | null;
    let inferredContentType: string | null;
    let platformEncryptionKeyId: string | undefined;

    if (options.encrypt) {
      if (!this.config.platformEncPublicKey) {
        throw new PlutusConfigError('keys.platformEncPublicKey is required for encrypted endpoints');
      }
      if (!requestId) {
        throw new PlutusRequestError('requestId is required for encrypted endpoints');
      }
      if (options.body === undefined || options.body === null) {
        throw new PlutusRequestError('encrypted endpoints require a request body');
      }
      const routeTemplate =
        typeof options.encrypt === 'object' && options.encrypt.routeTemplate
          ? options.encrypt.routeTemplate
          : options.path;
      if (!isKnownEncryptedRoute(routeTemplate)) {
        if (this.config.strictEncryptedRouteValidation) {
          throw new PlutusRequestError(
            `routeTemplate "${routeTemplate}" is not a known encrypted endpoint (see ENCRYPTED_ROUTE_TEMPLATES / SPEC.md §3)`,
          );
        }
        process.emitWarning(
          `Plutus SDK: routeTemplate "${routeTemplate}" is not in the known encrypted endpoint list ` +
            '(ENCRYPTED_ROUTE_TEMPLATES / SPEC.md §3). Proceeding because strictEncryptedRouteValidation ' +
            'is disabled; set it to true to reject unknown routes instead.',
          { code: 'PLUTUS_UNKNOWN_ENCRYPTED_ROUTE' },
        );
      }
      const plaintext = serializeBody(options.body).bytes as Buffer;
      const sealed = EnvelopeCodec.sealRequest(plaintext, {
        requestId,
        routeTemplate,
        timestamp,
        platformEncPublicKey: this.config.platformEncPublicKey,
        keyId: this.config.platformEncFingerprint ?? keyFingerprint(this.config.platformEncPublicKey),
        strictKeyValidation: this.config.strictKeyValidation,
      });
      bodyBytes = sealed.bodyBytes;
      inferredContentType = 'application/json';
      platformEncryptionKeyId = sealed.keyId;
    } else {
      const serialized = serializeBody(options.body);
      bodyBytes = serialized.bytes;
      inferredContentType = serialized.contentType;
    }

    const signed = this.signer.sign({
      method,
      path: options.path,
      query: rawQuery,
      body: bodyBytes,
      timestamp,
      nonce: options.nonce,
      idempotencyKey: options.idempotencyKey ?? null,
      apiVersion: this.config.apiVersion,
      requestId: requestId ?? null,
      platformEncryptionKeyId: platformEncryptionKeyId ?? null,
    });

    const headers: Record<string, string> = {
      ...this.config.defaultHeaders,
      ...(options.headers ?? {}),
      ...signed.headers,
      Accept: options.headers?.['Accept'] ?? this.config.defaultHeaders['Accept'] ?? 'application/json',
      'User-Agent': this.config.userAgent,
    };
    const contentType = options.contentType ?? inferredContentType;
    if (bodyBytes && contentType) {
      headers['Content-Type'] = contentType;
    }
    if (requestId && !headers['X-Request-Id']) {
      headers['X-Request-Id'] = requestId;
    }

    const sentQuery = this.config.sendCanonicalQuery ? canonicalQuery : rawQuery;
    const url = `${this.config.baseUrl}${options.path}${sentQuery ? `?${sentQuery}` : ''}`;
    return { signed, url, bodyBytes, headers };
  }
}

function isEnvelopeLike(value: unknown): boolean {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record['algorithm'] === 'string' &&
    typeof record['encryptedKey'] === 'string' &&
    typeof record['ciphertext'] === 'string' &&
    typeof record['aad'] === 'string'
  );
}
