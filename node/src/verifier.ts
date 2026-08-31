/**
 * 响应验签:重建 10 行 `SLAUNCHX-API-RESPONSE-V1` 规范串并校验 `X-Response-Signature`。
 */

import type { KeyObject } from 'node:crypto';
import { bodyDigestHex, buildResponseCanonicalString } from './canonical.js';
import { PlutusSignatureError } from './errors.js';
import { loadPublicKey, type KeyInput } from './keys.js';
import { verifyCanonicalSignature } from './signer.js';

/** 可传入的响应头形态:`Headers`、Node 原生 `IncomingHttpHeaders` 或普通对象。 */
export type HeaderSource =
  | Headers
  | Record<string, string | string[] | number | undefined>
  | Map<string, string>;

/**
 * 大小写不敏感地读取头值;数组取第一项。
 *
 * @param headers - 头集合
 * @param name - 头名
 * @returns 头值;不存在时为 `null`
 */
export function readHeader(headers: HeaderSource | null | undefined, name: string): string | null {
  if (!headers) {
    return null;
  }
  const lower = name.toLowerCase();
  if (typeof (headers as Headers).get === 'function') {
    return (headers as Headers).get(name) ?? null;
  }
  for (const [key, value] of Object.entries(headers as Record<string, unknown>)) {
    if (key.toLowerCase() !== lower) {
      continue;
    }
    if (Array.isArray(value)) {
      return value.length > 0 ? String(value[0]) : null;
    }
    return value === undefined || value === null ? null : String(value);
  }
  return null;
}

/**
 * 把任意头形态转成小写键的普通对象快照。
 *
 * @param headers - 头集合
 */
export function snapshotHeaders(headers: HeaderSource | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) {
    return out;
  }
  if (typeof (headers as Headers).forEach === 'function' && typeof (headers as Headers).get === 'function') {
    (headers as Headers).forEach((value, key) => {
      out[key.toLowerCase()] = value;
    });
    return out;
  }
  for (const [key, value] of Object.entries(headers as Record<string, unknown>)) {
    if (value === undefined || value === null) {
      continue;
    }
    out[key.toLowerCase()] = Array.isArray(value) ? String(value[0] ?? '') : String(value);
  }
  return out;
}

/** 响应验签入参。 */
export interface ResponseVerificationInput {
  /** 本地计算的请求绑定摘要(来自 {@link SignedRequest.requestCanonicalSha256}) */
  requestCanonicalSha256: string;
  /** 本次请求的 `X-API-VERSION` */
  apiVersion: string;
  /** 本次请求的外部路径 */
  externalPath: string;
  /** HTTP 状态码 */
  status: number;
  /** 响应头 */
  headers: HeaderSource;
  /** 原始响应体字节 */
  body: Uint8Array | null | undefined;
}

/** 响应验签结果。 */
export interface ResponseVerificationResult {
  /** 是否完成了验签(签名头缺失且被允许跳过时为 `false`) */
  verified: boolean;
  /** 本地重建的 10 行响应规范串;跳过验签时为 `null` */
  canonicalString: string | null;
  /** `X-Response-Signature` 原值 */
  signature: string | null;
  /** `X-Request-Id` 回显 */
  requestId: string | null;
  /** `X-Operation-Id` */
  operationId: string | null;
  /** `X-Platform-Signing-Key-Id` */
  signingKeyId: string | null;
}

/** {@link ResponseVerifier} 构造选项。 */
export interface ResponseVerifierOptions {
  /** 平台认证公钥(`platform_auth`) */
  platformAuthPublicKey: KeyInput;
  /**
   * 非 2xx 响应缺少 `X-Response-Signature` 时是否也报错,默认 `false`。
   *
   * 缺签名头的默认策略见 SPEC「SDK 约定(非平台契约)」一节:2xx 缺签名头一律报错;
   * 非 2xx 缺签名头默认放行,由调用方按错误响应处理。平台契约并未穷举哪些状态码不带签名头,
   * 因此 SDK 不做状态码白名单,只按 2xx / 非 2xx 区分。
   */
  requireSignatureOnErrorResponses?: boolean;
  /** 是否执行严格密钥格式校验,默认 `true` */
  strictKeyValidation?: boolean;
}

/**
 * 响应验签器。
 *
 * 规范串第 2 行的请求绑定摘要必须由本地计算,绝不能从响应头读取 —— 否则等于放弃绑定。
 */
export class ResponseVerifier {
  private readonly publicKey: KeyObject;
  private readonly requireSignatureOnErrorResponses: boolean;

  constructor(options: ResponseVerifierOptions) {
    this.publicKey = loadPublicKey(options.platformAuthPublicKey, {
      strict: options.strictKeyValidation !== false,
      label: 'platform_auth',
    });
    this.requireSignatureOnErrorResponses = options.requireSignatureOnErrorResponses === true;
  }

  /**
   * 校验响应签名。
   *
   * 缺签名头时:HTTP 2xx 抛验签异常;非 2xx 默认放行并返回 `verified: false`,
   * 除非构造时开启了 {@link ResponseVerifierOptions.requireSignatureOnErrorResponses}。
   *
   * @param input - 请求上下文与响应快照
   * @returns 验签结果
   * @throws {PlutusSignatureError} 验签失败,或按策略必须有签名却缺失
   */
  verify(input: ResponseVerificationInput): ResponseVerificationResult {
    const signature = readHeader(input.headers, 'X-Response-Signature');
    const requestId = readHeader(input.headers, 'X-Request-Id');
    const operationId = readHeader(input.headers, 'X-Operation-Id');
    const signingKeyId = readHeader(input.headers, 'X-Platform-Signing-Key-Id');

    if (!signature) {
      const isSuccessStatus = input.status >= 200 && input.status < 300;
      if (isSuccessStatus || this.requireSignatureOnErrorResponses) {
        throw new PlutusSignatureError(
          `response is missing X-Response-Signature (HTTP ${input.status})`,
        );
      }
      return { verified: false, canonicalString: null, signature: null, requestId, operationId, signingKeyId };
    }

    const canonicalString = buildResponseCanonicalString({
      requestCanonicalSha256: input.requestCanonicalSha256,
      apiVersion: input.apiVersion,
      externalPath: input.externalPath,
      operationId,
      requestId,
      httpStatus: input.status,
      contentType: readHeader(input.headers, 'Content-Type'),
      responseTimestamp: readHeader(input.headers, 'X-Response-Timestamp'),
      responseBodyDigest: bodyDigestHex(input.body),
    });

    if (!verifyCanonicalSignature(canonicalString, signature, this.publicKey)) {
      throw new PlutusSignatureError('response signature verification failed', canonicalString);
    }
    return { verified: true, canonicalString, signature, requestId, operationId, signingKeyId };
  }
}
