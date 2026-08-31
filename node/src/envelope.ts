/**
 * 混合加密信封:RSA-OAEP-SHA256 包装一次性 AES-256-GCM 密钥(SPEC 第 7 节)。
 *
 * 三处使用同一算法,只有 AAD 组成与信封字段集不同:
 * - 加密请求:`routeTemplate` = 端点外部路径,`keyId` = 平台加密公钥指纹;
 * - 敏感响应:`routeTemplate` = 空串,`keyId` = 商户加密公钥指纹;
 * - Webhook:`routeTemplate` = 字面量 `webhook`,`keyId` = API Key 业务 ID,信封多 `envelopeVersion` 且无 `encryptedPayload`。
 */

import {
  constants,
  createCipheriv,
  createDecipheriv,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
} from 'node:crypto';
import { buildAad, type AadComponents } from './canonical.js';
import { PlutusEnvelopeError } from './errors.js';
import { constantTimeEquals, keyFingerprint, loadPrivateKey, loadPublicKey, type KeyInput } from './keys.js';

/** 信封算法标识字面量。 */
export const ENVELOPE_ALGORITHM = 'RSA-OAEP-AES-256-GCM';
/** AES 密钥字节数。 */
export const AES_KEY_BYTES = 32;
/** GCM IV 字节数。 */
export const IV_BYTES = 12;
/** GCM 认证标签字节数。 */
export const TAG_BYTES = 16;
/** 解密后明文长度上限(1 MiB),与平台一致。 */
export const MAX_PLAINTEXT_BYTES = 1024 * 1024;

/** API 链(加密请求 / 敏感响应)信封。 */
export interface HybridEnvelope {
  algorithm: string;
  keyFingerprint: string;
  encryptedKey: string;
  ciphertext: string;
  aad: string;
  /** 历史兼容字段,值恒等于 `ciphertext`;解密时应读 `ciphertext` */
  encryptedPayload?: string;
}

/** Webhook 信封(`additionalProperties: false`,无 `encryptedPayload`)。 */
export interface WebhookEnvelope {
  envelopeVersion: number;
  algorithm: string;
  keyFingerprint: string;
  encryptedKey: string;
  ciphertext: string;
  aad: string;
}

/** 加密入参。 */
export interface SealOptions {
  /** 接收方公钥:加密请求用 `platform_enc`,平台侧加密用 `merchant_enc` */
  recipientPublicKey: KeyInput;
  /** AAD 四分量 */
  aad: AadComponents;
  /** 覆盖信封 `keyFingerprint`;默认取接收方公钥指纹 */
  keyFingerprint?: string;
  /** 是否写出 `encryptedPayload` 兼容字段,默认 `true`(API 链)。Webhook 形状必须为 `false` */
  includeEncryptedPayload?: boolean;
  /** 写出 `envelopeVersion`(Webhook 形状为 `1`);默认不写 */
  envelopeVersion?: number;
  /** 是否执行严格密钥格式校验,默认 `true` */
  strictKeyValidation?: boolean;
}

/** 解密入参。 */
export interface OpenOptions {
  /** 接收方私钥:敏感响应与 Webhook 均为 `merchant_enc` 私钥 */
  privateKey: KeyInput;
  /** 由调用方**自行重建**的 AAD 四分量;不会使用信封里回显的 `aad` */
  aad: AadComponents;
  /** 期望的 `keyFingerprint`;传入则强制比对 */
  expectedKeyFingerprint?: string;
  /** 明文长度上限,默认 1 MiB */
  maxPlaintextBytes?: number;
  /** 是否执行严格密钥格式校验,默认 `true` */
  strictKeyValidation?: boolean;
}

function decodeBase64Strict(value: string, field: string): Buffer {
  if (typeof value !== 'string' || value.length === 0) {
    throw new PlutusEnvelopeError(`envelope field "${field}" must be a non-empty Base64 string`);
  }
  const buf = Buffer.from(value, 'base64');
  if (buf.byteLength === 0) {
    throw new PlutusEnvelopeError(`envelope field "${field}" is not valid Base64`);
  }
  return buf;
}

/**
 * 混合信封编解码器。
 *
 * 解密流程严格遵循 SPEC 7.3:调用方重建 AAD → 与信封回显的 `aad` 常量时间比对 →
 * 用**重建的** AAD 做 GCM 解密。信封里的 `aad` 只作回显核对,绝不直接使用。
 */
export class EnvelopeCodec {
  /**
   * 加密明文,生成信封。
   *
   * @param plaintext - 业务明文(字符串按 UTF-8 编码)
   * @param options - 接收方公钥与 AAD
   * @returns 信封对象;`envelopeVersion` / `encryptedPayload` 按选项决定是否出现
   */
  static seal(plaintext: string | Uint8Array, options: SealOptions): HybridEnvelope & Partial<WebhookEnvelope> {
    const publicKey = loadPublicKey(options.recipientPublicKey, {
      strict: options.strictKeyValidation !== false,
      label: 'recipient encryption key',
    });
    const aadBytes = buildAad(options.aad);
    const plaintextBytes = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : Buffer.from(plaintext);

    const aesKey = randomBytes(AES_KEY_BYTES);
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', aesKey, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(aadBytes);
    const encrypted = Buffer.concat([cipher.update(plaintextBytes), cipher.final()]);
    const blob = Buffer.concat([iv, encrypted, cipher.getAuthTag()]);

    const encryptedKey = publicEncrypt(
      { key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      aesKey,
    );
    aesKey.fill(0);

    const ciphertext = blob.toString('base64');
    const envelope: HybridEnvelope & Partial<WebhookEnvelope> = {
      algorithm: ENVELOPE_ALGORITHM,
      keyFingerprint: options.keyFingerprint ?? keyFingerprint(publicKey),
      encryptedKey: encryptedKey.toString('base64'),
      ciphertext,
      aad: aadBytes.toString('base64'),
    };
    if (options.envelopeVersion !== undefined) {
      envelope.envelopeVersion = options.envelopeVersion;
    }
    if (options.includeEncryptedPayload !== false) {
      envelope.encryptedPayload = ciphertext;
    }
    return envelope;
  }

  /**
   * 解密信封,返回明文字节。
   *
   * @param envelope - 收到的信封(API 链或 Webhook 形状均可)
   * @param options - 私钥与自行重建的 AAD
   * @returns 明文字节
   * @throws {PlutusEnvelopeError} 算法/字段非法、AAD 回显不匹配、GCM 认证失败、明文超限
   */
  static open(envelope: HybridEnvelope | WebhookEnvelope, options: OpenOptions): Buffer {
    if (!envelope || typeof envelope !== 'object') {
      throw new PlutusEnvelopeError('envelope must be an object');
    }
    if (envelope.algorithm !== ENVELOPE_ALGORITHM) {
      throw new PlutusEnvelopeError(`unsupported envelope algorithm: ${String(envelope.algorithm)}`);
    }
    const privateKey = loadPrivateKey(options.privateKey, {
      strict: options.strictKeyValidation !== false,
      label: 'recipient encryption key',
    });

    const expected = options.expectedKeyFingerprint ?? keyFingerprint(privateKey);
    if (envelope.keyFingerprint !== expected) {
      throw new PlutusEnvelopeError(
        `envelope keyFingerprint does not match the expected recipient key (${String(envelope.keyFingerprint)})`,
      );
    }

    const rebuiltAad = buildAad(options.aad);
    const echoedAad = decodeBase64Strict(envelope.aad, 'aad');
    if (!constantTimeEquals(rebuiltAad, echoedAad)) {
      throw new PlutusEnvelopeError('rebuilt AAD does not match the AAD echoed in the envelope');
    }

    const encryptedKey = decodeBase64Strict(envelope.encryptedKey, 'encryptedKey');
    const blob = decodeBase64Strict(envelope.ciphertext, 'ciphertext');
    if (blob.byteLength < IV_BYTES + TAG_BYTES) {
      throw new PlutusEnvelopeError('ciphertext is shorter than IV + authentication tag');
    }

    let aesKey: Buffer;
    try {
      aesKey = privateDecrypt(
        { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        encryptedKey,
      );
    } catch (cause) {
      throw new PlutusEnvelopeError('failed to unwrap the AES key with RSA-OAEP-SHA256', { cause });
    }
    if (aesKey.byteLength !== AES_KEY_BYTES) {
      aesKey.fill(0);
      throw new PlutusEnvelopeError(`unwrapped AES key must be ${AES_KEY_BYTES} bytes`);
    }

    const iv = blob.subarray(0, IV_BYTES);
    const tag = blob.subarray(blob.byteLength - TAG_BYTES);
    const body = blob.subarray(IV_BYTES, blob.byteLength - TAG_BYTES);
    const limit = options.maxPlaintextBytes ?? MAX_PLAINTEXT_BYTES;
    if (body.byteLength > limit) {
      aesKey.fill(0);
      throw new PlutusEnvelopeError(`plaintext exceeds the ${limit} byte limit`);
    }

    try {
      const decipher = createDecipheriv('aes-256-gcm', aesKey, iv, { authTagLength: TAG_BYTES });
      decipher.setAAD(rebuiltAad);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(body), decipher.final()]);
    } catch (cause) {
      throw new PlutusEnvelopeError('AES-GCM authentication failed', { cause });
    } finally {
      aesKey.fill(0);
    }
  }

  /**
   * 解密并按 UTF-8 返回文本。
   *
   * @param envelope - 收到的信封
   * @param options - 私钥与自行重建的 AAD
   */
  static openText(envelope: HybridEnvelope | WebhookEnvelope, options: OpenOptions): string {
    return EnvelopeCodec.open(envelope, options).toString('utf8');
  }

  /**
   * 解密并按 JSON 解析。
   *
   * @param envelope - 收到的信封
   * @param options - 私钥与自行重建的 AAD
   */
  static openJson<T = unknown>(envelope: HybridEnvelope | WebhookEnvelope, options: OpenOptions): T {
    const text = EnvelopeCodec.openText(envelope, options);
    try {
      return JSON.parse(text) as T;
    } catch (cause) {
      throw new PlutusEnvelopeError('decrypted plaintext is not valid JSON', { cause });
    }
  }

  /**
   * 构造加密请求信封(SPEC 第 8 节)。
   *
   * AAD 为 `X-Request-Id | 端点外部路径 | X-Timestamp | 平台加密公钥指纹`。
   *
   * @param plaintext - 业务明文 JSON(字符串或对象)
   * @param params - 请求上下文与平台加密公钥
   * @returns 信封与其序列化字节;**必须**用返回的 `bodyBytes` 同时算摘要与发送
   */
  static sealRequest(
    plaintext: string | Uint8Array | Record<string, unknown>,
    params: {
      /** `X-Request-Id`,必填非空 */
      requestId: string;
      /** 端点外部路径 */
      routeTemplate: string;
      /** `X-Timestamp`,与签名使用同一值 */
      timestamp: string;
      /** 平台加密公钥(`platform_enc`) */
      platformEncPublicKey: KeyInput;
      /** 覆盖 `X-Platform-Encryption-Key-Id`;默认取公钥指纹 */
      keyId?: string;
      /** 是否执行严格密钥格式校验,默认 `true` */
      strictKeyValidation?: boolean;
    },
  ): { envelope: HybridEnvelope; bodyBytes: Buffer; keyId: string } {
    if (!params.requestId) {
      throw new PlutusEnvelopeError('requestId is required for an encrypted request');
    }
    if (!params.timestamp) {
      throw new PlutusEnvelopeError('timestamp is required for an encrypted request');
    }
    const publicKey = loadPublicKey(params.platformEncPublicKey, {
      strict: params.strictKeyValidation !== false,
      label: 'platform_enc',
    });
    const keyId = params.keyId ?? keyFingerprint(publicKey);
    const text =
      typeof plaintext === 'string' || plaintext instanceof Uint8Array
        ? plaintext
        : JSON.stringify(plaintext);
    const envelope = EnvelopeCodec.seal(text, {
      recipientPublicKey: publicKey,
      keyFingerprint: keyId,
      aad: {
        requestId: params.requestId,
        routeTemplate: params.routeTemplate,
        timestamp: params.timestamp,
        keyId,
      },
      includeEncryptedPayload: true,
    }) as HybridEnvelope;
    return { envelope, bodyBytes: Buffer.from(JSON.stringify(envelope), 'utf8'), keyId };
  }

  /**
   * 解密敏感响应信封(SPEC 第 9 节)。
   *
   * 敏感响应的时间戳没有独立传输通道,只能从信封回显的 `aad` 中解析。因此本方法:
   * 1. 解析 `aad` 得到四分量,并要求 `routeTemplate` 为空串;
   * 2. 校验 `requestId`(传入 `requestId` 时)与 `keyId`(等于商户加密公钥指纹);
   * 3. 用解析出的分量**重建** AAD 并与回显值常量时间比对;
   * 4. 用重建的 AAD 解密。
   *
   * 安全边界:时间戳本身来自对端,SDK 无法独立验证;绑定强度由 `requestId` 与 `keyId` 提供。
   *
   * @param envelope - 响应体中的信封
   * @param params - 商户加密私钥与期望的关联 ID
   * @returns 明文字节与解析出的 AAD 分量
   */
  static openSensitiveResponse(
    envelope: HybridEnvelope,
    params: {
      /** 商户加密私钥(`merchant_enc`) */
      merchantEncPrivateKey: KeyInput;
      /** 期望的关联请求 ID;传 `null` / 省略表示不校验(无 AccessContext 时平台使用空串) */
      requestId?: string | null;
      /** 期望的商户加密公钥指纹;默认由私钥推导 */
      expectedKeyFingerprint?: string;
      /** 明文长度上限,默认 1 MiB */
      maxPlaintextBytes?: number;
      /** 是否执行严格密钥格式校验,默认 `true` */
      strictKeyValidation?: boolean;
    },
  ): { plaintext: Buffer; aad: AadComponents } {
    const privateKey = loadPrivateKey(params.merchantEncPrivateKey, {
      strict: params.strictKeyValidation !== false,
      label: 'merchant_enc',
    });
    const expectedFingerprint = params.expectedKeyFingerprint ?? keyFingerprint(privateKey);
    const parsed = parseSensitiveResponseAad(envelope.aad);

    if (parsed.routeTemplate !== '') {
      throw new PlutusEnvelopeError('sensitive response AAD routeTemplate must be an empty string');
    }
    if (parsed.keyId !== expectedFingerprint) {
      throw new PlutusEnvelopeError('sensitive response AAD keyId does not match the merchant_enc fingerprint');
    }
    if (params.requestId !== undefined && params.requestId !== null && parsed.requestId !== params.requestId) {
      throw new PlutusEnvelopeError('sensitive response AAD requestId does not match the request context');
    }

    const plaintext = EnvelopeCodec.open(envelope, {
      privateKey,
      aad: parsed,
      expectedKeyFingerprint: expectedFingerprint,
      maxPlaintextBytes: params.maxPlaintextBytes,
      strictKeyValidation: params.strictKeyValidation,
    });
    return { plaintext, aad: parsed };
  }
}

/**
 * 解析敏感响应信封回显的 Base64 AAD。
 *
 * AAD 形如 `requestId||timestamp|keyId`(`routeTemplate` 固定为空串)。为了容忍
 * `requestId` 中可能出现的 `|`,从右向左切分:最后一段是 `keyId`,倒数第二段是
 * `timestamp`,再前一段必须为空(即 `routeTemplate`)。
 *
 * @param aadBase64 - 信封的 `aad` 字段
 * @returns AAD 四分量
 * @throws {PlutusEnvelopeError} Base64 非法或分量数量不足
 */
export function parseSensitiveResponseAad(aadBase64: string): AadComponents {
  const text = decodeBase64Strict(aadBase64, 'aad').toString('utf8');
  const keyIdSep = text.lastIndexOf('|');
  if (keyIdSep < 0) {
    throw new PlutusEnvelopeError('envelope aad is not a 4-component AAD string');
  }
  const timestampSep = text.lastIndexOf('|', keyIdSep - 1);
  if (timestampSep < 0) {
    throw new PlutusEnvelopeError('envelope aad is not a 4-component AAD string');
  }
  const routeSep = text.lastIndexOf('|', timestampSep - 1);
  if (routeSep < 0) {
    throw new PlutusEnvelopeError('envelope aad is not a 4-component AAD string');
  }
  return {
    requestId: text.slice(0, routeSep),
    routeTemplate: text.slice(routeSep + 1, timestampSep),
    timestamp: text.slice(timestampSep + 1, keyIdSep),
    keyId: text.slice(keyIdSep + 1),
  };
}
