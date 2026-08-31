import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  EnvelopeCodec,
  PlutusApiError,
  PlutusAuthenticationError,
  PlutusClient,
  PlutusConfigError,
  PlutusRateLimitError,
  PlutusSecureChannelError,
  PlutusSignatureError,
  PlutusValidationError,
  ResponseVerifier,
  bodyDigestHex,
  buildResponseCanonicalString,
  loadPrivateKey,
  signCanonicalString,
  type HybridEnvelope,
  type PlutusConfig,
} from '../src/index.js';
import { key } from './vectors.js';

const merchantAuth = key('merchant_auth');
const platformAuth = key('platform_auth');
const merchantEnc = key('merchant_enc');
const platformEnc = key('platform_enc');

const BASE_URL = 'https://consumer-api.example.test';

/** 平台统一响应包络的标准成功形态。 */
const SUCCESS_BODY =
  '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{"ok":true}}';

/** 构造一个成功包络,`data` 由调用方给出。 */
function successEnvelope(data: unknown, code = '2000'): string {
  return JSON.stringify({
    version: '2.0.0',
    timestamp: 1755600000123,
    success: true,
    code,
    message: 'Success',
    data,
  });
}

type FetchInput = Parameters<typeof globalThis.fetch>[0];

interface Capture {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: Buffer | null;
}

/**
 * 构造一个模拟平台的 fetch:按收到的请求本地重建响应规范串并用 platform_auth 私钥签名,
 * 因此客户端的验签路径被真实执行。
 */
function makeFetch(options: {
  capture: Capture[];
  status?: number;
  responseBody?: string;
  contentType?: string;
  operationId?: string | null;
  requestId?: string | null;
  sign?: boolean;
  extraHeaders?: Record<string, string>;
  externalPath?: string;
  apiVersion?: string;
}): typeof globalThis.fetch {
  return (async (input: FetchInput, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const headers = init?.headers as Record<string, string>;
    const bodyBytes = init?.body ? Buffer.from(init.body as Uint8Array) : null;
    options.capture.push({ url, method: init?.method ?? 'GET', headers, body: bodyBytes });

    const status = options.status ?? 200;
    const responseBody = options.responseBody ?? SUCCESS_BODY;
    const contentType = options.contentType ?? 'application/json';
    const responseTimestamp = '1755600000123';
    const requestId = options.requestId === undefined ? 'req_test_0001' : options.requestId;
    const operationId = options.operationId ?? null;

    const parsed = new URL(url);
    const canonical = buildResponseCanonicalString({
      requestCanonicalSha256: rebuildRequestCanonicalSha({
        method: init?.method ?? 'GET',
        headers,
        url: parsed,
        externalPath: options.externalPath,
        body: bodyBytes,
      }),
      apiVersion: options.apiVersion ?? '1',
      externalPath: options.externalPath ?? parsed.pathname,
      operationId,
      requestId,
      httpStatus: status,
      contentType,
      responseTimestamp,
      responseBodyDigest: bodyDigestHex(Buffer.from(responseBody, 'utf8')),
    });

    const responseHeaders: Record<string, string> = {
      'Content-Type': contentType,
      'X-Response-Timestamp': responseTimestamp,
      ...(requestId ? { 'X-Request-Id': requestId } : {}),
      ...(operationId ? { 'X-Operation-Id': operationId } : {}),
      ...(options.extraHeaders ?? {}),
    };
    if (options.sign !== false) {
      responseHeaders['X-Response-Signature'] = signCanonicalString(
        canonical,
        loadPrivateKey(platformAuth.privateKeyPem),
      );
      responseHeaders['X-Response-Signature-Algorithm'] = 'RSA-SHA256';
      responseHeaders['X-Platform-Signing-Key-Id'] = platformAuth.fingerprint;
    }
    return new Response(responseBody, { status, headers: responseHeaders });
  }) as typeof globalThis.fetch;
}

/**
 * 模拟平台侧重算请求绑定摘要:只用客户端实际发出的请求行、头与 body 复原 8 行规范串。
 * 因此若 SDK 发送的字节与签名的字节不一致,响应验签会立即失败。
 */
function rebuildRequestCanonicalSha(params: {
  method: string;
  headers: Record<string, string>;
  url: URL;
  externalPath?: string;
  body: Buffer | null;
}): string {
  const method = params.method.toUpperCase();
  const digest = ['GET', 'HEAD', 'DELETE'].includes(method)
    ? 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    : bodyDigestHex(params.body);
  const canonical = [
    method,
    params.externalPath ?? params.url.pathname,
    params.url.search.startsWith('?') ? params.url.search.slice(1) : '',
    params.headers['X-Timestamp'] as string,
    params.headers['X-Nonce'] as string,
    params.headers['X-API-VERSION'] as string,
    params.headers['X-Idempotency-Key'] ?? '',
    digest,
  ].join('\n');
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function baseConfig(overrides: Partial<PlutusConfig> = {}): PlutusConfig {
  return {
    baseUrl: BASE_URL,
    apiKey: 'apk_vector_0001',
    keys: {
      merchantAuthPrivateKey: merchantAuth.privateKeyPem,
      platformAuthPublicKey: platformAuth.publicKeyPem,
      merchantEncPrivateKey: merchantEnc.privateKeyPem,
      platformEncPublicKey: platformEnc.publicKeyPem,
    },
    ...overrides,
  };
}

describe('PlutusClient 请求组装', () => {
  it('GET:发送规范化 query,携带全部签名头,响应验签通过', async () => {
    const capture: Capture[] = [];
    const client = new PlutusClient(baseConfig({ fetch: makeFetch({ capture }) }));
    const res = await client.request({
      method: 'GET',
      path: '/card-products/cards/page',
      query: 'pageSize=20&status=IN_USE&cursor=',
    });

    expect(capture).toHaveLength(1);
    const sent = capture[0] as Capture;
    expect(sent.url).toBe(`${BASE_URL}/card-products/cards/page?cursor=&pageSize=20&status=IN_USE`);
    expect(sent.body).toBeNull();
    expect(Object.keys(sent.headers)).toEqual(
      expect.arrayContaining([
        'X-Api-Key',
        'X-API-VERSION',
        'X-Timestamp',
        'X-Nonce',
        'X-Signature',
        'X-Signature-Algorithm',
      ]),
    );
    expect(sent.headers['X-Signature-Algorithm']).toBe('RSA-SHA256');
    expect(sent.headers['X-Timestamp']).toMatch(/^\d{13}$/);
    expect(res.signatureVerified).toBe(true);
    expect(res.data).toEqual({ ok: true });
    expect(res.status).toBe(200);
  });

  it('POST:body 只序列化一次,签名与发送使用同一字节', async () => {
    const capture: Capture[] = [];
    const client = new PlutusClient(baseConfig({ fetch: makeFetch({ capture }) }));
    const res = await client.request({
      method: 'POST',
      path: '/card-products/cards/freeze',
      body: { reasonCategory: 'USER_REQUESTED' },
      idempotencyKey: 'idem-vector-0000000004',
    });

    const sent = capture[0] as Capture;
    expect((sent.body as Buffer).toString('utf8')).toBe('{"reasonCategory":"USER_REQUESTED"}');
    expect(sent.headers['X-Idempotency-Key']).toBe('idem-vector-0000000004');
    expect(sent.headers['Content-Type']).toBe('application/json');
    expect(res.requestCanonicalString.split('\n')[7]).toBe(bodyDigestHex(sent.body));
    expect(res.signatureVerified).toBe(true);
  });

  it('签名字节 == 发送字节:body 恰好序列化一次,摘要取自同一份字节', async () => {
    const capture: Capture[] = [];
    let serializations = 0;
    const body = {
      reasonCategory: 'USER_REQUESTED',
      toJSON(): Record<string, string> {
        serializations += 1;
        return { reasonCategory: 'USER_REQUESTED', seq: String(serializations) };
      },
    };
    const client = new PlutusClient(baseConfig({ fetch: makeFetch({ capture }) }));
    const res = await client.request({
      method: 'POST',
      path: '/card-products/cards/freeze',
      body,
    });

    // 序列化多于一次会导致 seq 递增,发送字节与签名字节必然不一致。
    expect(serializations).toBe(1);
    const sent = capture[0] as Capture;
    expect((sent.body as Buffer).toString('utf8')).toBe('{"reasonCategory":"USER_REQUESTED","seq":"1"}');
    // 规范串第 8 行的摘要就是实际发出的字节的摘要。
    expect(res.requestCanonicalString.split('\n')[7]).toBe(bodyDigestHex(sent.body));
    // 平台侧 mock 用收到的字节重算绑定摘要;验签通过即证明两者逐字节相等。
    expect(res.signatureVerified).toBe(true);
    expect(Number(sent.headers['Content-Length'] ?? (sent.body as Buffer).byteLength)).toBe(
      (sent.body as Buffer).byteLength,
    );
  });

  it('DELETE 携带 body 时仍按空 body 摘要签名', async () => {
    const capture: Capture[] = [];
    const client = new PlutusClient(baseConfig({ fetch: makeFetch({ capture }) }));
    const res = await client.request({
      method: 'DELETE',
      path: '/card-products/cards/cancel',
      query: { reason: 'CLOSED_BY_MERCHANT' },
      body: { ignored: true },
    });
    expect(res.requestCanonicalString.split('\n')[7]).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('signOnly 不发请求,只产出签名与 URL', () => {
    const client = new PlutusClient(baseConfig({ fetch: makeFetch({ capture: [] }) }));
    const prepared = client.signOnly({ method: 'GET', path: '/card-products/cards/page' });
    expect(prepared.url).toBe(`${BASE_URL}/card-products/cards/page`);
    expect(prepared.signed.canonicalString.split('\n')).toHaveLength(8);
  });

  it('非法 query 在本地抛错,不发出必然被拒的请求', async () => {
    const capture: Capture[] = [];
    const client = new PlutusClient(baseConfig({ fetch: makeFetch({ capture }) }));
    await expect(client.request({ method: 'GET', path: '/x', query: 'q=a+b' })).rejects.toThrowError(
      /percent encoding/,
    );
    expect(capture).toHaveLength(0);
  });
});

describe('PlutusClient 加密端点', () => {
  it('发送的 body 是信封 JSON,平台侧可用 platform_enc 私钥解开', async () => {
    const capture: Capture[] = [];
    const path = '/card-products/10010106/shared/cards/create';
    const client = new PlutusClient(baseConfig({ fetch: makeFetch({ capture }) }));
    const plaintext = { platformCardProductBizId: 'pcp_example_001', quantity: 2 };

    const res = await client.request({
      method: 'POST',
      path,
      body: plaintext,
      encrypt: true,
      idempotencyKey: 'idem-enc-0001',
    });

    const sent = capture[0] as Capture;
    expect(sent.headers['X-Request-Id']).toMatch(/^req_[0-9a-f]{32}$/);
    expect(sent.headers['X-Platform-Encryption-Key-Id']).toBe(platformEnc.fingerprint);

    const envelope = JSON.parse((sent.body as Buffer).toString('utf8')) as HybridEnvelope;
    expect(envelope.algorithm).toBe('RSA-OAEP-AES-256-GCM');
    expect(envelope.encryptedPayload).toBe(envelope.ciphertext);

    const decrypted = EnvelopeCodec.openText(envelope, {
      privateKey: platformEnc.privateKeyPem,
      aad: {
        requestId: sent.headers['X-Request-Id'] as string,
        routeTemplate: path,
        timestamp: sent.headers['X-Timestamp'] as string,
        keyId: platformEnc.fingerprint,
      },
    });
    expect(JSON.parse(decrypted)).toEqual(plaintext);
    // 签名的 body 摘要必须是信封字节的摘要,不是明文的摘要。
    expect(res.requestCanonicalString.split('\n')[7]).toBe(bodyDigestHex(sent.body));
    expect(res.requestCanonicalString.split('\n')[7]).not.toBe(
      bodyDigestHex(Buffer.from(JSON.stringify(plaintext), 'utf8')),
    );
  });

  it('未配置 platform_enc 公钥时拒绝加密请求', async () => {
    const client = new PlutusClient(
      baseConfig({
        fetch: makeFetch({ capture: [] }),
        keys: {
          merchantAuthPrivateKey: merchantAuth.privateKeyPem,
          platformAuthPublicKey: platformAuth.publicKeyPem,
        },
      }),
    );
    await expect(
      client.request({ method: 'POST', path: '/x', body: { a: 1 }, encrypt: true }),
    ).rejects.toThrowError(PlutusConfigError);
  });

  it('敏感响应自动解密', async () => {
    const requestId = 'req_sensitive_0001';
    const secret = { cardNumber: '4111111111111111', cvv: '123' };
    const envelope = EnvelopeCodec.seal(JSON.stringify(secret), {
      recipientPublicKey: merchantEnc.publicKeyPem,
      aad: {
        requestId,
        routeTemplate: '',
        timestamp: '1755600011000',
        keyId: merchantEnc.fingerprint,
      },
    });
    const client = new PlutusClient(
      baseConfig({
        fetch: makeFetch({
          capture: [],
          requestId,
          responseBody: successEnvelope(envelope),
        }),
      }),
    );
    const res = await client.request<typeof secret>({
      method: 'GET',
      path: '/card-products/cards/sensitive',
      decryptResponse: true,
    });
    expect(res.data).toEqual(secret);
  });
});

describe('PlutusClient 错误映射', () => {
  async function expectError(status: number, code: string): Promise<unknown> {
    const client = new PlutusClient(
      baseConfig({
        fetch: makeFetch({
          capture: [],
          status,
          responseBody: JSON.stringify({
            version: '2.0.0',
            timestamp: 1755600000123,
            success: false,
            code,
            message: 'boom',
          }),
          extraHeaders: status === 429 ? { 'Retry-After': '7' } : {},
        }),
      }),
    );
    return client.request({ method: 'GET', path: '/card-products/cards/page' }).catch((e: unknown) => e);
  }

  it('API.* 映射为认证错误', async () => {
    const err = await expectError(401, 'API.SIGNATURE_INVALID');
    expect(err).toBeInstanceOf(PlutusAuthenticationError);
    expect((err as PlutusAuthenticationError).retryable).toBe(false);
    expect((err as PlutusAuthenticationError).code).toBe('API.SIGNATURE_INVALID');
  });

  it('VALIDATION.* 映射为参数校验错误', async () => {
    expect(await expectError(400, 'VALIDATION.INVALID_PARAMETER')).toBeInstanceOf(PlutusValidationError);
  });

  it('SECURE_CHANNEL.* 映射为加密通道错误', async () => {
    expect(await expectError(400, 'SECURE_CHANNEL.INVALID_PAYLOAD')).toBeInstanceOf(PlutusSecureChannelError);
  });

  it('REQUEST.RATE_LIMITED 映射为限流错误并带 Retry-After', async () => {
    const err = await expectError(429, 'REQUEST.RATE_LIMITED');
    expect(err).toBeInstanceOf(PlutusRateLimitError);
    expect((err as PlutusRateLimitError).retryAfterSeconds).toBe(7);
    expect((err as PlutusRateLimitError).retryable).toBe(true);
  });

  it('HTTP 200 但 success:false 视为失败', async () => {
    const err = await expectError(200, 'REQUEST.CONFLICT');
    expect((err as PlutusAuthenticationError).status).toBe(200);
    expect((err as PlutusAuthenticationError).code).toBe('REQUEST.CONFLICT');
  });

  it('HTTP 200 + success:false + 数字业务码,抛类型化 API 错误且错误码不丢失', async () => {
    const client = new PlutusClient(
      baseConfig({
        fetch: makeFetch({
          capture: [],
          status: 200,
          responseBody: JSON.stringify({
            version: '2.0.0',
            timestamp: 1755600000123,
            success: false,
            code: '4022',
            message: 'Validation Error',
          }),
        }),
      }),
    );
    const err = await client
      .request({ method: 'GET', path: '/card-products/cards/page' })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PlutusApiError);
    expect((err as PlutusApiError).status).toBe(200);
    expect((err as PlutusApiError).code).toBe('4022');
    expect((err as PlutusApiError).message).toBe('Validation Error');
  });
});

describe('PlutusClient 响应验签策略', () => {
  it('HTTP 2xx 缺签名头抛验签错误', async () => {
    const client = new PlutusClient(baseConfig({ fetch: makeFetch({ capture: [], sign: false }) }));
    await expect(client.request({ method: 'GET', path: '/card-products/cards/page' })).rejects.toThrowError(
      PlutusSignatureError,
    );
  });

  it('HTTP 201 缺签名头同样抛验签错误', async () => {
    const client = new PlutusClient(
      baseConfig({
        fetch: makeFetch({
          capture: [],
          sign: false,
          status: 201,
          responseBody: successEnvelope({ ok: true }, '2001'),
        }),
      }),
    );
    await expect(client.request({ method: 'GET', path: '/card-products/cards/page' })).rejects.toThrowError(
      PlutusSignatureError,
    );
  });

  it('非 2xx 缺签名头默认放行,按类型化 API 错误抛出', async () => {
    const client = new PlutusClient(
      baseConfig({
        fetch: makeFetch({
          capture: [],
          sign: false,
          status: 401,
          responseBody: JSON.stringify({
            version: '2.0.0',
            timestamp: 1755600000123,
            success: false,
            code: 'API.KEY_INVALID',
            message: 'invalid',
          }),
        }),
      }),
    );
    const err = await client
      .request({ method: 'GET', path: '/card-products/cards/page' })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PlutusAuthenticationError);
    expect((err as PlutusAuthenticationError).code).toBe('API.KEY_INVALID');
    // 被放行的响应必须让调用方看到未验签。
    expect((err as PlutusAuthenticationError).signatureVerified).toBe(false);
  });

  it('带签名头的错误响应,错误对象上 signatureVerified 为 true', async () => {
    const err = await (async (): Promise<unknown> => {
      const client = new PlutusClient(
        baseConfig({
          fetch: makeFetch({
            capture: [],
            status: 404,
            responseBody: JSON.stringify({ success: false, code: 'RESOURCE.NOT_FOUND', message: 'missing' }),
          }),
        }),
      );
      return client.request({ method: 'GET', path: '/card-products/cards/page' }).catch((e: unknown) => e);
    })();
    expect(err).toBeInstanceOf(PlutusApiError);
    expect((err as PlutusApiError).signatureVerified).toBe(true);
  });

  it('非 2xx 缺签名头被放行时,验签器返回未验签', () => {
    const verifier = new ResponseVerifier({ platformAuthPublicKey: platformAuth.publicKeyPem });
    const result = verifier.verify({
      requestCanonicalSha256: '0'.repeat(64),
      apiVersion: '1',
      externalPath: '/card-products/cards/page',
      status: 500,
      headers: {},
      body: null,
    });
    expect(result.verified).toBe(false);
    expect(result.canonicalString).toBeNull();
  });

  it('requireSignatureOnErrorResponses: true 时非 2xx 缺签名头抛验签错误', async () => {
    const client = new PlutusClient(
      baseConfig({
        fetch: makeFetch({
          capture: [],
          sign: false,
          status: 401,
          responseBody: JSON.stringify({ success: false, code: 'API.KEY_INVALID', message: 'invalid' }),
        }),
        requireSignatureOnErrorResponses: true,
      }),
    );
    await expect(client.request({ method: 'GET', path: '/card-products/cards/page' })).rejects.toThrowError(
      PlutusSignatureError,
    );
  });

  it('签名被篡改时抛验签错误,响应体不会返回给业务代码', async () => {
    const client = new PlutusClient(
      baseConfig({
        fetch: makeFetch({ capture: [], extraHeaders: {} }),
      }),
    );
    const tampering = new PlutusClient(
      baseConfig({
        fetch: (async (input: FetchInput, init?: RequestInit) => {
          const original = await makeFetch({ capture: [] })(input, init);
          const headers = new Headers(original.headers);
          headers.set('X-Response-Timestamp', '1755600000999');
          return new Response(await original.arrayBuffer(), { status: original.status, headers });
        }) as typeof globalThis.fetch,
      }),
    );
    await expect(client.request({ method: 'GET', path: '/card-products/cards/page' })).resolves.toBeTruthy();
    await expect(
      tampering.request({ method: 'GET', path: '/card-products/cards/page' }),
    ).rejects.toThrowError(PlutusSignatureError);
  });

  it('verifyResponseSignature: false 时跳过验签', async () => {
    const client = new PlutusClient(
      baseConfig({
        fetch: makeFetch({ capture: [], sign: false }),
        verifyResponseSignature: false,
        keys: { merchantAuthPrivateKey: merchantAuth.privateKeyPem },
      }),
    );
    const res = await client.request({ method: 'GET', path: '/card-products/cards/page' });
    expect(res.signatureVerified).toBe(false);
  });
});

describe('配置校验', () => {
  it('启用响应验签却未提供 platform_auth 公钥时报错', () => {
    expect(
      () =>
        new PlutusClient({
          baseUrl: BASE_URL,
          apiKey: 'apk',
          keys: { merchantAuthPrivateKey: merchantAuth.privateKeyPem },
        }),
    ).toThrowError(PlutusConfigError);
  });

  it('baseUrl 非法时报错', () => {
    expect(() => new PlutusClient(baseConfig({ baseUrl: 'not-a-url' }))).toThrowError(PlutusConfigError);
  });

  it('PKCS#1 公钥被拒绝(必须是 SPKI)', () => {
    const pkcs1 = platformAuth.publicKeyPem
      .replace('BEGIN PUBLIC KEY', 'BEGIN RSA PUBLIC KEY')
      .replace('END PUBLIC KEY', 'END RSA PUBLIC KEY');
    expect(() =>
      new PlutusClient(
        baseConfig({
          keys: {
            merchantAuthPrivateKey: merchantAuth.privateKeyPem,
            platformAuthPublicKey: pkcs1,
          },
        }),
      ),
    ).toThrowError(/PEM block delimited/);
  });

  it('暴露平台与商户加密公钥指纹', () => {
    const client = new PlutusClient(baseConfig({ fetch: makeFetch({ capture: [] }) }));
    expect(client.platformEncryptionKeyId).toBe(platformEnc.fingerprint);
    expect(client.merchantEncryptionKeyId).toBe(merchantEnc.fingerprint);
  });
});
