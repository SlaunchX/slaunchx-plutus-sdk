/** 黄金测试向量的加载与类型声明。向量文件是协议的最高权威。 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export interface KeyPairVector {
  purpose: string;
  algorithm: string;
  modulusBits: number;
  publicExponent: number;
  fingerprint: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

export type KeyName = 'merchant_auth' | 'platform_auth' | 'merchant_enc' | 'platform_enc';

export interface CanonicalQueryVector {
  id: string;
  description: string;
  input: string | null;
  expected: string | null;
  expectError: boolean;
  errorReason?: string;
}

export interface BodyHashVector {
  id: string;
  description: string;
  method: string | null;
  body: string | null;
  forcedEmptyBody: boolean;
  expected: string;
}

export interface RequestSignatureVector {
  id: string;
  description: string;
  signingKey: KeyName;
  request: {
    method: string;
    externalPath: string;
    queryString: string | null;
    timestamp: string;
    nonce: string;
    apiVersion: string;
    idempotencyKey: string | null;
    body: string | null;
  };
  canonicalQuery: string;
  forcedEmptyBody: boolean;
  bodyHash: string;
  canonicalString: string;
  canonicalStringLines: string[];
  requestCanonicalSha256: string;
  signature: string;
  headers: Record<string, string>;
}

export interface ResponseSignatureVector {
  id: string;
  description: string;
  signingKey: KeyName;
  requestVectorId: string;
  requestCanonicalSha256: string;
  apiVersion: string;
  externalPath: string;
  operationId: string | null;
  requestId: string | null;
  httpStatus: number;
  contentType: string | null;
  responseTimestamp: string;
  responseBody: string;
  responseBodyHash: string;
  canonicalString: string;
  canonicalStringLines: string[];
  signature: string;
  headers: Record<string, string>;
}

export interface EnvelopeVector {
  id: string;
  description: string;
  direction: 'request' | 'sensitive_response';
  decryptionKey: KeyName;
  aadComponents: { requestId: string; routeTemplate: string; timestamp: string; keyId: string };
  aadString: string;
  aadBase64: string;
  envelope: {
    algorithm: string;
    keyFingerprint: string;
    encryptedKey: string;
    ciphertext: string;
    aad: string;
    encryptedPayload?: string;
  };
  expectedPlaintext: string;
  requestHeaders?: Record<string, string>;
}

export interface WebhookVector {
  id: string;
  description: string;
  decryptionKey: KeyName;
  signatureVerificationKey: KeyName;
  headers: Record<string, string>;
  body: string;
  bodyDigestBase64: string;
  signatureCanonicalString: string;
  aadComponents: { requestId: string; routeTemplate: string; timestamp: string; keyId: string };
  aadString: string;
  aadBase64: string;
  expectedPlaintext: string;
}

export interface TestVectors {
  meta: { protocol: string; counts: Record<string, number> } & Record<string, unknown>;
  keys: Record<KeyName, KeyPairVector>;
  vectors: {
    canonicalQuery: CanonicalQueryVector[];
    bodyHash: BodyHashVector[];
    requestSignature: RequestSignatureVector[];
    responseSignature: ResponseSignatureVector[];
    encryptedEnvelope: EnvelopeVector[];
    webhook: WebhookVector[];
  };
}

const VECTORS_PATH = fileURLToPath(new URL('../../shared/test-vectors.json', import.meta.url));

/** 加载 `shared/test-vectors.json`。 */
export const vectors: TestVectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as TestVectors;

/** 按名字取测试密钥对。 */
export function key(name: KeyName): KeyPairVector {
  return vectors.keys[name];
}
