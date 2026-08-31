/**
 * RSA 密钥装载、格式校验与指纹计算(SPEC 第 2 节)。
 */

import { createHash, createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { PlutusKeyError } from './errors.js';

/** 允许的 RSA 模数位长下限。 */
export const MIN_MODULUS_BITS = 2048;
/** 允许的 RSA 模数位长上限。 */
export const MAX_MODULUS_BITS = 4096;
/** 唯一允许的公开指数。 */
export const REQUIRED_PUBLIC_EXPONENT = 65537n;

const PUBLIC_PEM_HEADER = '-----BEGIN PUBLIC KEY-----';
const PUBLIC_PEM_FOOTER = '-----END PUBLIC KEY-----';
const PRIVATE_PEM_HEADER = '-----BEGIN PRIVATE KEY-----';
const PRIVATE_PEM_FOOTER = '-----END PRIVATE KEY-----';

/** SDK 接受的密钥入参:PEM 文本、DER 字节或已装载的 {@link KeyObject}。 */
export type KeyInput = string | Buffer | KeyObject;

/** 公钥装载选项。 */
export interface PublicKeyOptions {
  /**
   * 是否执行 SPEC 第 2 节的完整格式校验(SPKI PEM 形状、位长、指数、DER 规范性)。
   * 默认 `true`。
   */
  strict?: boolean;
  /** 出错信息中用于定位的密钥名,例如 `platform_auth`。 */
  label?: string;
}

function describe(label: string | undefined): string {
  return label ? `${label} ` : '';
}

function splitPemBody(pem: string, header: string, footer: string, label?: string): string {
  const normalized = pem.replace(/\r\n/g, '\n').trim();
  const lines = normalized.split('\n');
  if (lines.length < 3 || lines[0]?.trim() !== header || lines[lines.length - 1]?.trim() !== footer) {
    throw new PlutusKeyError(
      `${describe(label)}public key must be a PEM block delimited by "${header}" / "${footer}" on their own lines`,
    );
  }
  const body = lines.slice(1, -1).join('');
  if (!/^[A-Za-z0-9+/=]*$/.test(body) || body.length === 0) {
    throw new PlutusKeyError(`${describe(label)}PEM body may only contain A-Za-z0-9+/= and line breaks`);
  }
  return body;
}

/**
 * 装载并校验 RSA 公钥。
 *
 * 强制要求(SPEC 2):SPKI PEM(`BEGIN PUBLIC KEY`,非 PKCS#1)、正文只含 Base64 字符、
 * 模数位长 2048–4096、公开指数恰为 65537、DER 重新编码后与原 DER 逐字节相等。
 *
 * @param input - PEM 文本 / DER 字节 / 已装载的 KeyObject
 * @param options - 装载选项
 * @returns Node 公钥对象
 * @throws {PlutusKeyError} 格式或参数不满足要求
 */
export function loadPublicKey(input: KeyInput, options: PublicKeyOptions = {}): KeyObject {
  const strict = options.strict !== false;
  let key: KeyObject;
  let originalDer: Buffer | null = null;

  if (typeof input === 'object' && !Buffer.isBuffer(input)) {
    key = input.type === 'private' ? createPublicKey(input) : input;
  } else if (Buffer.isBuffer(input)) {
    key = createPublicKey({ key: input, format: 'der', type: 'spki' });
    originalDer = input;
  } else {
    const body = strict
      ? splitPemBody(input, PUBLIC_PEM_HEADER, PUBLIC_PEM_FOOTER, options.label)
      : null;
    if (body !== null) {
      originalDer = Buffer.from(body, 'base64');
    }
    try {
      key = createPublicKey(input);
    } catch (cause) {
      throw new PlutusKeyError(`${describe(options.label)}public key PEM could not be parsed`, { cause });
    }
  }

  if (key.asymmetricKeyType !== 'rsa') {
    throw new PlutusKeyError(`${describe(options.label)}key must be RSA, got ${String(key.asymmetricKeyType)}`);
  }
  if (!strict) {
    return key;
  }

  const details = key.asymmetricKeyDetails;
  const bits = details?.modulusLength ?? 0;
  if (bits < MIN_MODULUS_BITS || bits > MAX_MODULUS_BITS) {
    throw new PlutusKeyError(
      `${describe(options.label)}RSA modulus must be ${MIN_MODULUS_BITS}..${MAX_MODULUS_BITS} bits, got ${bits}`,
    );
  }
  const exponent = details?.publicExponent;
  if (exponent === undefined || BigInt(exponent) !== REQUIRED_PUBLIC_EXPONENT) {
    throw new PlutusKeyError(
      `${describe(options.label)}RSA public exponent must be exactly ${REQUIRED_PUBLIC_EXPONENT}, got ${String(exponent)}`,
    );
  }
  const reencoded = key.export({ type: 'spki', format: 'der' });
  if (originalDer && !reencoded.equals(originalDer)) {
    throw new PlutusKeyError(`${describe(options.label)}SPKI DER is not canonically encoded`);
  }
  return key;
}

/**
 * 装载 RSA 私钥(PKCS#8 PEM,`BEGIN PRIVATE KEY`)。
 *
 * @param input - PEM 文本 / DER 字节 / 已装载的 KeyObject
 * @param options - 装载选项(`strict` 控制 PEM 形状检查)
 * @returns Node 私钥对象
 * @throws {PlutusKeyError} 格式非法或不是 RSA 私钥
 */
export function loadPrivateKey(input: KeyInput, options: PublicKeyOptions = {}): KeyObject {
  const strict = options.strict !== false;
  let key: KeyObject;
  if (typeof input === 'object' && !Buffer.isBuffer(input)) {
    if (input.type !== 'private') {
      throw new PlutusKeyError(`${describe(options.label)}expected a private key object`);
    }
    key = input;
  } else if (Buffer.isBuffer(input)) {
    key = createPrivateKey({ key: input, format: 'der', type: 'pkcs8' });
  } else {
    if (strict) {
      splitPemBody(input, PRIVATE_PEM_HEADER, PRIVATE_PEM_FOOTER, options.label);
    }
    try {
      key = createPrivateKey(input);
    } catch (cause) {
      throw new PlutusKeyError(`${describe(options.label)}private key PEM could not be parsed`, { cause });
    }
  }
  if (key.asymmetricKeyType !== 'rsa') {
    throw new PlutusKeyError(`${describe(options.label)}key must be RSA, got ${String(key.asymmetricKeyType)}`);
  }
  return key;
}

/**
 * 计算密钥指纹:`"SHA256:" + 小写hex( SHA256( SPKI DER ) )`。
 *
 * 传入私钥时会先导出对应公钥再计算,结果与公钥指纹一致。
 *
 * @param key - 公钥或私钥
 * @returns 形如 `SHA256:b23147f2...` 的指纹
 */
export function keyFingerprint(key: KeyObject): string {
  const publicKey = key.type === 'private' ? createPublicKey(key) : key;
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return `SHA256:${createHash('sha256').update(der).digest('hex')}`;
}

/**
 * 常量时间比较两段字节,长度不同直接返回 `false`。
 *
 * @param a - 左值
 * @param b - 右值
 */
export function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.byteLength; i += 1) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}
