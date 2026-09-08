import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  RequestSigner,
  ResponseVerifier,
  PlutusSignatureError,
  buildRequestCanonicalString,
  buildResponseCanonicalString,
  bodyDigestHex,
  canonicalizeQuery,
  requestCanonicalSha256,
  signedBodyDigest,
  verifyCanonicalSignature,
} from '../src/index.js';
import { key, vectors } from './vectors.js';

const merchantAuth = key('merchant_auth');
const platformAuth = key('platform_auth');

describe('requestSignature 向量组', () => {
  it('向量数量为 7', () => {
    expect(vectors.vectors.requestSignature).toHaveLength(7);
  });

  for (const vector of vectors.vectors.requestSignature) {
    describe(`${vector.id}: ${vector.description}`, () => {
      const req = vector.request;
      const bodyBytes = req.body === null ? null : Buffer.from(req.body, 'utf8');

      it('query 规范化结果一致', () => {
        expect(canonicalizeQuery(req.queryString)).toBe(vector.canonicalQuery);
      });

      it('body 摘要与强制空体规则一致', () => {
        expect(signedBodyDigest(req.method, bodyBytes)).toBe(vector.bodyHash);
        expect(vector.forcedEmptyBody).toBe(['GET', 'HEAD', 'DELETE'].includes(req.method));
      });

      it('规范串逐行与整串比对', () => {
        const canonical = buildRequestCanonicalString({
          method: req.method,
          externalPath: req.externalPath,
          canonicalQuery: canonicalizeQuery(req.queryString),
          timestamp: req.timestamp,
          nonce: req.nonce,
          apiVersion: req.apiVersion,
          idempotencyKey: req.idempotencyKey,
          bodyDigest: signedBodyDigest(req.method, bodyBytes),
        });
        expect(canonical.split('\n')).toEqual(vector.canonicalStringLines);
        expect(canonical).toBe(vector.canonicalString);
      });

      it('请求绑定摘要一致', () => {
        expect(requestCanonicalSha256(vector.canonicalString)).toBe(vector.requestCanonicalSha256);
      });

      it('向量签名可用 merchant_auth 公钥验证', () => {
        expect(verifyCanonicalSignature(vector.canonicalString, vector.signature, merchantAuth.publicKeyPem)).toBe(
          true,
        );
      });

      it('RequestSigner 重签结果与向量逐字节相等(PKCS#1 v1.5 确定性)', () => {
        const signer = new RequestSigner({
          apiKey: vector.headers['X-Api-Key'] as string,
          merchantAuthPrivateKey: merchantAuth.privateKeyPem,
          apiVersion: req.apiVersion,
        });
        const signed = signer.sign({
          method: req.method,
          path: req.externalPath,
          query: req.queryString,
          body: bodyBytes,
          timestamp: req.timestamp,
          nonce: req.nonce,
          idempotencyKey: req.idempotencyKey,
        });
        expect(signed.canonicalString).toBe(vector.canonicalString);
        expect(signed.signature).toBe(vector.signature);
        expect(signed.requestCanonicalSha256).toBe(vector.requestCanonicalSha256);
        expect(signed.headers).toEqual(vector.headers);
      });
    });
  }
});

describe('requestSignature 负向', () => {
  const vector = vectors.vectors.requestSignature.find((v) => v.id === 'rq-04-post-body-idempotency');

  it('篡改规范串任意一行都会验签失败', () => {
    const lines = [...(vector as NonNullable<typeof vector>).canonicalStringLines];
    for (let i = 0; i < lines.length; i += 1) {
      const mutated = [...lines];
      mutated[i] = `${mutated[i]}x`;
      expect(
        verifyCanonicalSignature(
          mutated.join('\n'),
          (vector as NonNullable<typeof vector>).signature,
          merchantAuth.publicKeyPem,
        ),
      ).toBe(false);
    }
  });

  it('用另一把公钥验签必然失败', () => {
    expect(
      verifyCanonicalSignature(
        (vector as NonNullable<typeof vector>).canonicalString,
        (vector as NonNullable<typeof vector>).signature,
        platformAuth.publicKeyPem,
      ),
    ).toBe(false);
  });

  it('省略幂等键会改变规范串第 7 行,导致签名不同', () => {
    const signer = new RequestSigner({
      apiVersion: '1',
      apiKey: 'apk_vector_0001',
      merchantAuthPrivateKey: merchantAuth.privateKeyPem,
    });
    const v = vector as NonNullable<typeof vector>;
    const signed = signer.sign({
      method: v.request.method,
      path: v.request.externalPath,
      body: Buffer.from(v.request.body as string, 'utf8'),
      timestamp: v.request.timestamp,
      nonce: v.request.nonce,
    });
    expect(signed.signature).not.toBe(v.signature);
    expect(signed.headers['X-Idempotency-Key']).toBeUndefined();
  });

  it('nonce 不合规时本地抛错', () => {
    const signer = new RequestSigner({
      apiVersion: '1',
      apiKey: 'apk_vector_0001',
      merchantAuthPrivateKey: merchantAuth.privateKeyPem,
    });
    expect(() => signer.sign({ method: 'GET', path: '/x', nonce: 'short+/=' })).toThrowError(
      /nonce must match/,
    );
  });

  it('秒级时间戳不会被自动纠正,但格式非数字时抛错', () => {
    const signer = new RequestSigner({
      apiVersion: '1',
      apiKey: 'apk_vector_0001',
      merchantAuthPrivateKey: merchantAuth.privateKeyPem,
    });
    expect(() => signer.sign({ method: 'GET', path: '/x', timestamp: '2026-08-30T00:00:00Z' })).toThrowError(
      /Unix milliseconds/,
    );
  });

  it('默认生成的 nonce 与时间戳满足协议约束', () => {
    const signer = new RequestSigner({
      apiVersion: '1',
      apiKey: 'apk_vector_0001',
      merchantAuthPrivateKey: merchantAuth.privateKeyPem,
    });
    const signed = signer.sign({ method: 'GET', path: '/card-products/cards/page' });
    expect(signed.nonce).toMatch(/^[A-Za-z0-9._~-]{16,128}$/);
    expect(signed.timestamp).toMatch(/^\d{13}$/);
    expect(signed.headers['X-Signature-Algorithm']).toBe('RSA-SHA256');
  });
});

describe('responseSignature 向量组', () => {
  it('向量数量为 3', () => {
    expect(vectors.vectors.responseSignature).toHaveLength(3);
  });

  for (const vector of vectors.vectors.responseSignature) {
    describe(`${vector.id}: ${vector.description}`, () => {
      const bodyBytes = Buffer.from(vector.responseBody, 'utf8');

      it('绑定摘要来自关联的请求向量,而非响应头', () => {
        const requestVector = vectors.vectors.requestSignature.find((v) => v.id === vector.requestVectorId);
        expect(requestVector).toBeDefined();
        expect(requestCanonicalSha256((requestVector as NonNullable<typeof requestVector>).canonicalString)).toBe(
          vector.requestCanonicalSha256,
        );
      });

      it('响应体摘要一致', () => {
        expect(bodyDigestHex(bodyBytes)).toBe(vector.responseBodyHash);
      });

      it('10 行规范串逐行与整串比对', () => {
        const canonical = buildResponseCanonicalString({
          requestCanonicalSha256: vector.requestCanonicalSha256,
          apiVersion: vector.apiVersion,
          externalPath: vector.externalPath,
          operationId: vector.operationId,
          requestId: vector.requestId,
          httpStatus: vector.httpStatus,
          contentType: vector.contentType,
          responseTimestamp: vector.responseTimestamp,
          responseBodyDigest: vector.responseBodyHash,
        });
        expect(canonical.split('\n')).toEqual(vector.canonicalStringLines);
        expect(canonical).toBe(vector.canonicalString);
      });

      it('ResponseVerifier 通过 platform_auth 公钥验签', () => {
        const verifier = new ResponseVerifier({ platformAuthPublicKey: platformAuth.publicKeyPem });
        const headers: Record<string, string> = {
          'X-Response-Signature': vector.signature,
          'X-Response-Timestamp': vector.responseTimestamp,
          'X-Response-Signature-Algorithm': 'RSA-SHA256',
        };
        if (vector.contentType) headers['Content-Type'] = vector.contentType;
        if (vector.requestId) headers['X-Request-Id'] = vector.requestId;
        if (vector.operationId) headers['X-Operation-Id'] = vector.operationId;

        const result = verifier.verify({
          requestCanonicalSha256: vector.requestCanonicalSha256,
          apiVersion: vector.apiVersion,
          externalPath: vector.externalPath,
          status: vector.httpStatus,
          headers,
          body: bodyBytes,
        });
        expect(result.verified).toBe(true);
        expect(result.canonicalString).toBe(vector.canonicalString);
      });
    });
  }
});

describe('responseSignature 负向', () => {
  const vector = vectors.vectors.responseSignature[0] as NonNullable<
    (typeof vectors.vectors.responseSignature)[0]
  >;
  const bodyBytes = Buffer.from(vector.responseBody, 'utf8');

  function verifyWith(overrides: Record<string, unknown>): void {
    const verifier = new ResponseVerifier({ platformAuthPublicKey: platformAuth.publicKeyPem });
    verifier.verify({
      requestCanonicalSha256: vector.requestCanonicalSha256,
      apiVersion: vector.apiVersion,
      externalPath: vector.externalPath,
      status: vector.httpStatus,
      headers: {
        'X-Response-Signature': vector.signature,
        'X-Response-Timestamp': vector.responseTimestamp,
        'Content-Type': vector.contentType as string,
        'X-Request-Id': vector.requestId as string,
      },
      body: bodyBytes,
      ...overrides,
    });
  }

  it('绑定摘要不匹配(响应被挪用到别的请求)时抛错', () => {
    expect(() => verifyWith({ requestCanonicalSha256: 'f'.repeat(64) })).toThrowError(PlutusSignatureError);
  });

  it('Content-Type 被归一化后验签失败', () => {
    expect(() =>
      verifyWith({
        headers: {
          'X-Response-Signature': vector.signature,
          'X-Response-Timestamp': vector.responseTimestamp,
          'Content-Type': 'application/json;charset=UTF-8',
          'X-Request-Id': vector.requestId as string,
        },
      }),
    ).toThrowError(PlutusSignatureError);
  });

  it('响应体被改动一个字节即验签失败', () => {
    const tampered = Buffer.from(`${vector.responseBody} `, 'utf8');
    expect(() => verifyWith({ body: tampered })).toThrowError(PlutusSignatureError);
  });

  it('状态码不同即验签失败', () => {
    expect(() => verifyWith({ status: 200 === vector.httpStatus ? 201 : 200 })).toThrowError(
      PlutusSignatureError,
    );
  });

  it('默认策略:2xx 缺签名头抛错,非 2xx 缺签名头放行', () => {
    const verifier = new ResponseVerifier({ platformAuthPublicKey: platformAuth.publicKeyPem });
    for (const status of [200, 201, 204]) {
      expect(() =>
        verifier.verify({
          requestCanonicalSha256: vector.requestCanonicalSha256,
          apiVersion: '1',
          externalPath: '/x',
          status,
          headers: {},
          body: null,
        }),
      ).toThrowError(PlutusSignatureError);
    }

    for (const status of [401, 403, 404, 429, 500]) {
      const passed = verifier.verify({
        requestCanonicalSha256: vector.requestCanonicalSha256,
        apiVersion: '1',
        externalPath: '/x',
        status,
        headers: {},
        body: null,
      });
      expect(passed.verified).toBe(false);
      expect(passed.canonicalString).toBeNull();
    }
  });

  it('requireSignatureOnErrorResponses: true 时非 2xx 缺签名头也抛错', () => {
    const verifier = new ResponseVerifier({
      platformAuthPublicKey: platformAuth.publicKeyPem,
      requireSignatureOnErrorResponses: true,
    });
    for (const status of [401, 500]) {
      expect(() =>
        verifier.verify({
          requestCanonicalSha256: vector.requestCanonicalSha256,
          apiVersion: '1',
          externalPath: '/x',
          status,
          headers: {},
          body: null,
        }),
      ).toThrowError(PlutusSignatureError);
    }
  });
});

describe('密钥指纹', () => {
  it('四把密钥的指纹与向量一致,私钥推导结果相同', async () => {
    const { keyFingerprint, loadPrivateKey, loadPublicKey } = await import('../src/index.js');
    for (const name of ['merchant_auth', 'platform_auth', 'merchant_enc', 'platform_enc'] as const) {
      const pair = key(name);
      expect(keyFingerprint(loadPublicKey(pair.publicKeyPem))).toBe(pair.fingerprint);
      expect(keyFingerprint(loadPrivateKey(pair.privateKeyPem))).toBe(pair.fingerprint);
      expect(pair.publicExponent).toBe(65537);
      expect(pair.modulusBits).toBe(2048);
    }
  });

  it('指纹是 SHA256: 前缀加小写 hex', () => {
    const der = Buffer.from(
      key('platform_auth').publicKeyPem
        .split('\n')
        .filter((line) => !line.startsWith('-----'))
        .join(''),
      'base64',
    );
    expect(key('platform_auth').fingerprint).toBe(`SHA256:${createHash('sha256').update(der).digest('hex')}`);
  });
});
