import { ProtocolProfile, resolveProfile, productRequestId } from './protocol.js';
/**
 * 请求签名器:构造 8 行规范串、生成 RSA-SHA256(PKCS#1 v1.5)签名与全部签名头。
 */

import { constants, randomBytes, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import {
  buildRequestCanonicalString,
  canonicalizeQuery,
  encodeQueryParams,
  isValidNonce,
  requestCanonicalSha256,
  signedBodyDigest,
  type QueryParamValue,
} from './canonical.js';
import { PlutusRequestError } from './errors.js';
import { loadPrivateKey, loadPublicKey, type KeyInput } from './keys.js';

/** `X-Signature-Algorithm` 的字面量取值。 */
export const SIGNATURE_ALGORITHM = 'RSA-SHA256';

/** 默认 API 契约主版本。 */
export const DEFAULT_API_VERSION = '1';

/** query 入参:原始串或参数对象。对象会按 RFC 3986 编码。 */
export type QueryInput =
  | string
  | null
  | undefined
  | Record<string, QueryParamValue | readonly QueryParamValue[]>;

/**
 * 生成默认 nonce:16 字节 CSPRNG 的小写 hex(32 字符),满足 `[A-Za-z0-9._~-]{16,128}`。
 *
 * @param byteLength - 随机字节数,默认 16(输出长度为其两倍)
 */
export function generateNonce(byteLength = 16): string {
  if (byteLength < 8 || byteLength > 64) {
    throw new PlutusRequestError('nonce byteLength must be within 8..64 to satisfy the 16..128 char constraint');
  }
  return randomBytes(byteLength).toString('hex');
}

/** 待签名请求的描述。 */
export interface SignableRequest {
  /** HTTP 方法,大小写不敏感,内部统一转大写 */
  method: string;
  /** 外部路径,以 `/` 开头,不含链/版本/门户前缀,不含 query */
  path: string;
  /** 原始 query 串或参数对象;不传表示无 query */
  query?: QueryInput;
  /** 实际发送的 body 字节。必须与真正写入网络的字节一致 */
  body?: Uint8Array | null;
  /** 覆盖时间戳(Unix 毫秒十进制串);默认由 clock 生成 */
  timestamp?: string;
  /** 覆盖 nonce;默认由 nonce 生成器生成 */
  nonce?: string;
  /** `X-Idempotency-Key`;不传则该头不发送且规范串第 7 行为空 */
  idempotencyKey?: string | null;
  /** 覆盖 API 版本 */
  apiVersion?: string;
  /** 加密请求必填的 `X-Request-Id`;不参与请求签名 */
  requestId?: string | null;
  /** 加密请求必填的 `X-Platform-Encryption-Key-Id`;不参与请求签名 */
  platformEncryptionKeyId?: string | null;
}

/** 签名结果。 */
export interface SignedRequest {
  /** 大写 HTTP 方法 */
  method: string;
  /** 外部路径 */
  externalPath: string;
  /** 规范化后的 query(可直接作为实际发送的 query) */
  canonicalQuery: string;
  /** 商户传入的原始 query 串 */
  rawQuery: string;
  /** `X-Timestamp` 值 */
  timestamp: string;
  /** `X-Nonce` 值 */
  nonce: string;
  /** `X-API-VERSION` 值 */
  apiVersion: string;
  /** `X-Idempotency-Key` 值;未使用时为 `null` */
  idempotencyKey: string | null;
  /** 参与签名的 body 摘要(小写 hex) */
  bodyDigest: string;
  /** 8 行请求规范串 */
  canonicalString: string;
  /** 请求绑定摘要,用于响应验签第 2 行 */
  requestCanonicalSha256: string;
  /** Base64 签名 */
  signature: string;
  /** 应发送的全部签名相关请求头 */
  headers: Record<string, string>;
}

/** {@link RequestSigner} 构造选项。 */
export interface RequestSignerOptions {
  protocolProfile?: ProtocolProfile;
  /** API Key 业务 ID,写入 `X-Api-Key` */
  apiKey: string;
  /** 商户认证私钥(`merchant_auth`,PKCS#8 PEM) */
  merchantAuthPrivateKey: KeyInput;
  /** API 契约主版本,默认 `1` */
  apiVersion?: string;
  /** nonce 生成器,默认 {@link generateNonce} */
  nonceGenerator?: () => string;
  /** 毫秒时钟,默认 `Date.now` */
  now?: () => number;
  /** 是否执行严格密钥格式校验,默认 `true` */
  strictKeyValidation?: boolean;
}

/**
 * 请求签名器。
 *
 * 使用要点:body 必须先序列化成一个不可变的字节数组,再把**同一个数组**同时用于
 * 摘要计算与网络发送;否则两次序列化的差异会导致 `API.SIGNATURE_INVALID`。
 *
 * @example
 * const signer = new RequestSigner({ apiKey, merchantAuthPrivateKey: pem });
 * const body = Buffer.from(JSON.stringify({ quantity: 2 }), 'utf8');
 * const signed = signer.sign({ method: 'POST', path: '/card-products/cards/freeze', body });
 * await fetch(url, { method: 'POST', headers: signed.headers, body });
 */
export class RequestSigner {
  private readonly protocolProfile: ProtocolProfile;
  private readonly apiKey: string;
  private readonly privateKey: KeyObject;
  private readonly apiVersion: string;
  private readonly nonceGenerator: () => string;
  private readonly now: () => number;

  constructor(options: RequestSignerOptions) {
    if (!options.apiKey) {
      throw new PlutusRequestError('apiKey is required');
    }
    this.protocolProfile = resolveProfile(options.protocolProfile);
    this.apiKey = options.apiKey;
    this.privateKey = loadPrivateKey(options.merchantAuthPrivateKey, {
      strict: options.strictKeyValidation !== false,
      label: 'merchant_auth',
    });
    this.apiVersion = options.apiVersion ?? DEFAULT_API_VERSION;
    this.nonceGenerator = options.nonceGenerator ?? (() => generateNonce());
    this.now = options.now ?? (() => Date.now());
  }

  /**
   * 对请求签名并返回全部签名头。
   *
   * @param request - 待签名请求
   * @returns 规范串、绑定摘要、签名与请求头
   * @throws {PlutusRequestError} nonce 不合规、路径非法、加密请求缺必填头
   * @throws {PlutusCanonicalizationError} query 无法通过严格规范化
   */
  sign(request: SignableRequest): SignedRequest {
    const method = request.method.toUpperCase();
    const rawQuery = typeof request.query === 'string' || request.query == null
      ? request.query ?? ''
      : encodeQueryParams(request.query);
    const canonicalQuery = canonicalizeQuery(rawQuery, this.protocolProfile);
    const timestamp = request.timestamp ?? String(this.now());
    if (!/^\d+$/.test(timestamp)) {
      throw new PlutusRequestError('timestamp must be a Unix milliseconds decimal string');
    }
    const nonce = request.nonce ?? this.nonceGenerator();
    if (!isValidNonce(nonce)) {
      throw new PlutusRequestError('nonce must match ^[A-Za-z0-9._~-]{16,128}$');
    }
    const apiVersion = request.apiVersion ?? this.apiVersion;
    const idempotencyKey = request.idempotencyKey ?? null;
    const bodyDigest = signedBodyDigest(method, request.body);

    const canonicalString = buildRequestCanonicalString({
      protocolProfile: this.protocolProfile,
      method,
      externalPath: request.path,
      canonicalQuery,
      timestamp,
      nonce,
      apiVersion,
      idempotencyKey,
      bodyDigest,
    });
    const signature = signCanonicalString(canonicalString, this.privateKey);

    const headers: Record<string, string> = {
      'X-Api-Key': this.apiKey,
      'X-API-VERSION': apiVersion,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
      'X-Signature-Algorithm': SIGNATURE_ALGORITHM,
    };
    if (idempotencyKey !== null && idempotencyKey !== '') {
      headers['X-Idempotency-Key'] = idempotencyKey;
    }
    const requestId = this.protocolProfile === ProtocolProfile.PRODUCT_V1 ? productRequestId(request.requestId) : request.requestId;
    if (requestId) headers['X-Request-Id'] = requestId;
    if (request.platformEncryptionKeyId) {
      headers['X-Platform-Encryption-Key-Id'] = request.platformEncryptionKeyId;
    }

    return {
      method,
      externalPath: request.path,
      canonicalQuery,
      rawQuery,
      timestamp,
      nonce,
      apiVersion,
      idempotencyKey,
      bodyDigest,
      canonicalString,
      requestCanonicalSha256: requestCanonicalSha256(canonicalString),
      signature,
      headers,
    };
  }
}

/**
 * 对规范串做 RSASSA-PKCS1-v1_5 + SHA-256 签名。
 *
 * @param canonicalString - 规范串(UTF-8)
 * @param privateKey - RSA 私钥
 * @returns 标准 Base64 签名
 */
export function signCanonicalString(canonicalString: string, privateKey: KeyObject): string {
  return cryptoSign('RSA-SHA256', Buffer.from(canonicalString, 'utf8'), {
    key: privateKey,
    padding: constants.RSA_PKCS1_PADDING,
  }).toString('base64');
}

/**
 * 校验规范串签名(RSASSA-PKCS1-v1_5 + SHA-256)。
 *
 * @param canonicalString - 规范串(UTF-8)
 * @param signatureBase64 - Base64 签名
 * @param publicKey - RSA 公钥或其 PEM
 * @returns 验签是否通过;Base64 非法时返回 `false`
 */
export function verifyCanonicalSignature(
  canonicalString: string,
  signatureBase64: string,
  publicKey: KeyInput,
): boolean {
  const key = loadPublicKey(publicKey, { strict: false });
  let signature: Buffer;
  try {
    signature = Buffer.from(signatureBase64, 'base64');
  } catch {
    return false;
  }
  if (signature.byteLength === 0) {
    return false;
  }
  return cryptoVerify(
    'RSA-SHA256',
    Buffer.from(canonicalString, 'utf8'),
    { key, padding: constants.RSA_PKCS1_PADDING },
    signature,
  );
}
