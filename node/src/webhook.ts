/**
 * Webhook 接收:验签(Base64 body 摘要)+ 信封解密(AAD 第二分量固定 `webhook`)。
 *
 * 顺序不可颠倒:签名覆盖的是**加密信封 JSON 的原始字节**,必须先验签、后解密。
 */

import { timingSafeEqual, type KeyObject } from 'node:crypto';
import { buildWebhookCanonicalString, webhookBodyDigestBase64 } from './canonical.js';
import { EnvelopeCodec, ENVELOPE_ALGORITHM, type WebhookEnvelope } from './envelope.js';
import { PlutusWebhookError } from './errors.js';
import { keyFingerprint, loadPrivateKey, loadPublicKey, type KeyInput } from './keys.js';
import { verifyCanonicalSignature } from './signer.js';
import { readHeader, type HeaderSource } from './verifier.js';

/** AAD 第二分量的字面量。 */
export const WEBHOOK_ROUTE_TEMPLATE = 'webhook';

/** Webhook 传输头。 */
export interface WebhookHeaders {
  /** `X-SlaunchX-Delivery-Id`,投递 ID,重试与重放保持不变,是去重键 */
  deliveryBizId: string;
  /** `X-SlaunchX-Event-Type` */
  eventType: string;
  /** `X-SlaunchX-Timestamp`,Unix 毫秒 */
  timestamp: string;
  /** `X-SlaunchX-Key-Id`,接收方 API Key 业务 ID(不是指纹) */
  keyId: string;
  /** `X-SlaunchX-Signature`,Base64 */
  signature: string;
}

/** 明文通知载荷的顶层结构(SPEC 10.5)。 */
export interface WebhookPayload {
  eventId: string;
  eventType: string;
  payloadSchemaVersion: number;
  /** UTC RFC 3339,带 `Z` */
  occurredAt: string;
  workspaceBizId: string;
  deliveryBizId: string;
  resource: { type: string; bizId: string } & Record<string, unknown>;
  data: Record<string, unknown>;
  [key: string]: unknown;
}

/** 完整的 Webhook 处理结果。 */
export interface WebhookDelivery<T = WebhookPayload> {
  /** 已校验的传输头 */
  headers: WebhookHeaders;
  /** 解析后的信封 */
  envelope: WebhookEnvelope;
  /** 解密后的明文通知载荷 */
  payload: T;
  /** 明文原文,便于原样落库 */
  plaintext: string;
}

/** {@link WebhookHandler} 构造选项。 */
export interface WebhookHandlerOptions {
  /** 平台认证公钥(`platform_auth`),用于验签 */
  platformAuthPublicKey: KeyInput;
  /** 商户加密私钥(`merchant_enc`),用于解密 */
  merchantEncPrivateKey: KeyInput;
  /**
   * 本商户的 API Key 业务 ID，必填。强制校验 `X-SlaunchX-Key-Id` 与之相等,
   * 并用于构造 AAD 的第四分量。
   */
  apiKeyBizId: string;
  /**
   * 允许的时间戳偏差(毫秒)。SPEC 第 16 节明确该窗口未在契约中规定,
   * 因此**默认关闭**(`undefined`)。启用后既拒绝过旧也拒绝过新的投递。
   */
  timestampToleranceMs?: number;
  /** 毫秒时钟,默认 `Date.now` */
  now?: () => number;
  /** 是否交叉校验明文与传输头(SPEC 10.6),默认 `true` */
  crossCheckPayload?: boolean;
  /** 明文长度上限,默认 1 MiB */
  maxPlaintextBytes?: number;
  /** 是否执行严格密钥格式校验,默认 `true` */
  strictKeyValidation?: boolean;
}

function requireHeader(headers: HeaderSource, name: string): string {
  const value = readHeader(headers, name);
  if (!value) {
    throw new PlutusWebhookError(`missing webhook header ${name}`, 'SDK.WEBHOOK_HEADER_MISSING');
  }
  return value;
}

/**
 * 从传输头中提取并校验 Webhook 头集合。
 *
 * @param headers - HTTP 头
 * @returns 五个必需头的取值
 * @throws {PlutusWebhookError} 缺少必需头
 */
export function extractWebhookHeaders(headers: HeaderSource): WebhookHeaders {
  return {
    deliveryBizId: requireHeader(headers, 'X-SlaunchX-Delivery-Id'),
    eventType: requireHeader(headers, 'X-SlaunchX-Event-Type'),
    timestamp: requireHeader(headers, 'X-SlaunchX-Timestamp'),
    keyId: requireHeader(headers, 'X-SlaunchX-Key-Id'),
    signature: requireHeader(headers, 'X-SlaunchX-Signature'),
  };
}

/**
 * 校验 Webhook 信封形状(SPEC 10.3)。
 *
 * 必需字段:`envelopeVersion`(恰为 1)、`algorithm`、`keyFingerprint`、`encryptedKey`、
 * `ciphertext`、`aad`;schema 声明 `additionalProperties: false`,因此出现
 * `encryptedPayload` 等额外字段一律拒绝。
 *
 * @param value - 已解析的 body JSON
 * @returns 通过校验的信封
 * @throws {PlutusWebhookError} 形状不符
 */
export function assertWebhookEnvelope(value: unknown): WebhookEnvelope {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new PlutusWebhookError('webhook body must be a JSON object');
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set(['envelopeVersion', 'algorithm', 'keyFingerprint', 'encryptedKey', 'ciphertext', 'aad']);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new PlutusWebhookError(`webhook envelope contains an unexpected field: ${key}`);
    }
  }
  if (record['envelopeVersion'] !== 1) {
    throw new PlutusWebhookError(`webhook envelopeVersion must be exactly 1, got ${String(record['envelopeVersion'])}`);
  }
  if (record['algorithm'] !== ENVELOPE_ALGORITHM) {
    throw new PlutusWebhookError(`webhook envelope algorithm must be ${ENVELOPE_ALGORITHM}`);
  }
  for (const key of ['keyFingerprint', 'encryptedKey', 'ciphertext', 'aad'] as const) {
    if (typeof record[key] !== 'string' || (record[key] as string).length === 0) {
      throw new PlutusWebhookError(`webhook envelope field "${key}" must be a non-empty string`);
    }
  }
  return record as unknown as WebhookEnvelope;
}

/**
 * Webhook 处理器。
 *
 * @example
 * const handler = new WebhookHandler({ platformAuthPublicKey, merchantEncPrivateKey, apiKeyBizId });
 * // Express: 必须拿到未被解析器改写的 raw body
 * app.post('/webhooks/slaunchx', express.raw({ type: 'application/json' }), (req, res) => {
 *   const delivery = handler.handle(req.body, req.headers);
 *   res.status(204).end();
 * });
 */
export class WebhookHandler {
  private readonly publicKey: KeyObject;
  private readonly privateKey: KeyObject;
  private readonly merchantEncFingerprint: string;
  private readonly apiKeyBizId: string;
  private readonly timestampToleranceMs: number | undefined;
  private readonly now: () => number;
  private readonly crossCheckPayload: boolean;
  private readonly maxPlaintextBytes: number | undefined;

  constructor(options: WebhookHandlerOptions) {
    if (typeof options.apiKeyBizId !== 'string' || !options.apiKeyBizId.trim()) {
      throw new PlutusWebhookError('apiKeyBizId is required');
    }
    const strict = options.strictKeyValidation !== false;
    this.publicKey = loadPublicKey(options.platformAuthPublicKey, { strict, label: 'platform_auth' });
    this.privateKey = loadPrivateKey(options.merchantEncPrivateKey, { strict, label: 'merchant_enc' });
    this.merchantEncFingerprint = keyFingerprint(this.privateKey);
    this.apiKeyBizId = options.apiKeyBizId;
    this.timestampToleranceMs = options.timestampToleranceMs;
    this.now = options.now ?? (() => Date.now());
    this.crossCheckPayload = options.crossCheckPayload !== false;
    this.maxPlaintextBytes = options.maxPlaintextBytes;
  }

  /** 商户加密公钥指纹,应与信封 `keyFingerprint` 相等。 */
  get keyFingerprint(): string {
    return this.merchantEncFingerprint;
  }

  /**
   * 只验签,不解密。
   *
   * @param rawBody - **未经任何解析器改写**的原始 HTTP body 字节
   * @param headers - HTTP 头
   * @returns 已校验的传输头
   * @throws {PlutusWebhookError} 头缺失、Key-Id 不匹配、时间戳超窗、验签失败
   */
  verify(rawBody: Uint8Array, headers: HeaderSource): WebhookHeaders {
    const parsed = extractWebhookHeaders(headers);
    if (this.timestampToleranceMs !== undefined) {
      if (!/^\d+$/.test(parsed.timestamp)) {
        throw new PlutusWebhookError('X-SlaunchX-Timestamp must be a Unix milliseconds decimal string');
      }
      const skew = Math.abs(this.now() - Number(parsed.timestamp));
      if (skew > this.timestampToleranceMs) {
        throw new PlutusWebhookError(
          `webhook timestamp skew ${skew}ms exceeds the configured tolerance ${this.timestampToleranceMs}ms`,
          'SDK.WEBHOOK_TIMESTAMP_SKEW',
        );
      }
    }
    const canonical = buildWebhookCanonicalString(
      parsed.deliveryBizId,
      parsed.eventType,
      parsed.timestamp,
      webhookBodyDigestBase64(rawBody),
    );
    if (!verifyCanonicalSignature(canonical, parsed.signature, this.publicKey)) {
      throw new PlutusWebhookError('webhook signature verification failed', 'SDK.WEBHOOK_SIGNATURE_INVALID');
    }
    const expected = Buffer.from(this.apiKeyBizId, 'utf8');
    const received = Buffer.from(parsed.keyId, 'utf8');
    if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
      throw new PlutusWebhookError('X-SlaunchX-Key-Id does not match the configured API key business id');
    }
    return parsed;
  }

  /**
   * 完整处理:验签 → 解析信封 → 重建 AAD → 解密 → 交叉校验明文。
   *
   * 调用方仍需按 `deliveryBizId` 去重(自动重试与人工重放共用同一个 `deliveryBizId`)。
   *
   * @param rawBody - 原始 HTTP body 字节
   * @param headers - HTTP 头
   * @returns 头、信封、明文载荷
   */
  handle<T = WebhookPayload>(rawBody: Uint8Array, headers: HeaderSource): WebhookDelivery<T> {
    const parsedHeaders = this.verify(rawBody, headers);

    let json: unknown;
    try {
      json = JSON.parse(Buffer.from(rawBody).toString('utf8'));
    } catch (cause) {
      throw new PlutusWebhookError('webhook body is not valid JSON', 'SDK.WEBHOOK_INVALID', { cause });
    }
    const envelope = assertWebhookEnvelope(json);
    if (envelope.keyFingerprint !== this.merchantEncFingerprint) {
      throw new PlutusWebhookError(
        'webhook envelope keyFingerprint does not match the configured merchant_enc key',
      );
    }

    const plaintext = EnvelopeCodec.open(envelope, {
      privateKey: this.privateKey,
      aad: {
        requestId: parsedHeaders.deliveryBizId,
        routeTemplate: WEBHOOK_ROUTE_TEMPLATE,
        timestamp: parsedHeaders.timestamp,
        keyId: this.apiKeyBizId,
      },
      expectedKeyFingerprint: this.merchantEncFingerprint,
      maxPlaintextBytes: this.maxPlaintextBytes,
    }).toString('utf8');

    let payload: T;
    try {
      payload = JSON.parse(plaintext) as T;
    } catch (cause) {
      throw new PlutusWebhookError('decrypted webhook payload is not valid JSON', 'SDK.WEBHOOK_INVALID', { cause });
    }
    if (this.crossCheckPayload) {
      assertPayloadMatchesHeaders(payload as unknown as Partial<WebhookPayload>, parsedHeaders);
    }
    return { headers: parsedHeaders, envelope, payload, plaintext };
  }
}

/**
 * 交叉校验明文与传输头(SPEC 10.6)。
 *
 * @param payload - 解密后的明文载荷
 * @param headers - 传输头
 * @throws {PlutusWebhookError} `deliveryBizId` / `eventType` 不一致,或 `payloadSchemaVersion` 不为 1
 */
export function assertPayloadMatchesHeaders(
  payload: Partial<WebhookPayload>,
  headers: WebhookHeaders,
): void {
  if (payload.deliveryBizId !== headers.deliveryBizId) {
    throw new PlutusWebhookError('payload deliveryBizId does not match X-SlaunchX-Delivery-Id');
  }
  if (payload.eventType !== headers.eventType) {
    throw new PlutusWebhookError('payload eventType does not match X-SlaunchX-Event-Type');
  }
  if (payload.payloadSchemaVersion !== 1) {
    throw new PlutusWebhookError(
      `unsupported payloadSchemaVersion: ${String(payload.payloadSchemaVersion)}`,
      'SDK.WEBHOOK_SCHEMA_UNSUPPORTED',
    );
  }
}
