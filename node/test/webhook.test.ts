import { describe, expect, it } from 'vitest';
import {
  EnvelopeCodec,
  PlutusWebhookError,
  WebhookHandler,
  assertWebhookEnvelope,
  buildAad,
  buildWebhookCanonicalString,
  loadPrivateKey,
  signCanonicalString,
  verifyCanonicalSignature,
  webhookBodyDigestBase64,
} from '../src/index.js';
import { key, vectors } from './vectors.js';

const platformAuth = key('platform_auth');
const merchantEnc = key('merchant_enc');

function handler(overrides: Record<string, unknown> = {}): WebhookHandler {
  return new WebhookHandler({
    platformAuthPublicKey: platformAuth.publicKeyPem,
    merchantEncPrivateKey: merchantEnc.privateKeyPem,
    apiKeyBizId: 'apk_vector_0001',
    ...overrides,
  });
}

describe('webhook 向量组', () => {
  it('向量数量为 2', () => {
    expect(vectors.vectors.webhook).toHaveLength(2);
  });

  for (const vector of vectors.vectors.webhook) {
    describe(`${vector.id}: ${vector.description}`, () => {
      const rawBody = Buffer.from(vector.body, 'utf8');

      it('body 摘要是 Base64 而非 hex', () => {
        const digest = webhookBodyDigestBase64(rawBody);
        expect(digest).toBe(vector.bodyDigestBase64);
        expect(digest).toMatch(/=$|[A-Za-z0-9+/]$/);
        expect(digest).not.toMatch(/^[0-9a-f]{64}$/);
      });

      it('4 行签名规范串一致', () => {
        const canonical = buildWebhookCanonicalString(
          vector.headers['X-SlaunchX-Delivery-Id'] as string,
          vector.headers['X-SlaunchX-Event-Type'] as string,
          vector.headers['X-SlaunchX-Timestamp'] as string,
          webhookBodyDigestBase64(rawBody),
        );
        expect(canonical).toBe(vector.signatureCanonicalString);
        expect(canonical.split('\n')).toHaveLength(4);
      });

      it('用 platform_auth 公钥验签通过', () => {
        expect(
          verifyCanonicalSignature(
            vector.signatureCanonicalString,
            vector.headers['X-SlaunchX-Signature'] as string,
            platformAuth.publicKeyPem,
          ),
        ).toBe(true);
      });

      it('AAD 第二分量固定为 webhook,第四分量是 API Key 业务 ID', () => {
        expect(vector.aadComponents.routeTemplate).toBe('webhook');
        expect(vector.aadComponents.keyId).toBe(vector.headers['X-SlaunchX-Key-Id']);
        expect(vector.aadComponents.keyId).not.toMatch(/^SHA256:/);
        const aad = buildAad(vector.aadComponents);
        expect(aad.toString('utf8')).toBe(vector.aadString);
        expect(aad.toString('base64')).toBe(vector.aadBase64);
      });

      it('信封形状:有 envelopeVersion,无 encryptedPayload', () => {
        const envelope = assertWebhookEnvelope(JSON.parse(vector.body));
        expect(envelope.envelopeVersion).toBe(1);
        expect('encryptedPayload' in envelope).toBe(false);
        expect(envelope.keyFingerprint).toBe(merchantEnc.fingerprint);
      });

      it('WebhookHandler 验签并解密,明文与向量一致', () => {
        const delivery = handler().handle(rawBody, vector.headers);
        expect(delivery.plaintext).toBe(vector.expectedPlaintext);
        expect(delivery.headers.deliveryBizId).toBe(vector.headers['X-SlaunchX-Delivery-Id']);
        expect(delivery.payload.eventType).toBe(vector.headers['X-SlaunchX-Event-Type']);
        expect(delivery.payload.payloadSchemaVersion).toBe(1);
      });

      it('直接用信封与重建 AAD 解密,结果相同', () => {
        const envelope = assertWebhookEnvelope(JSON.parse(vector.body));
        expect(
          EnvelopeCodec.openText(envelope, {
            privateKey: merchantEnc.privateKeyPem,
            aad: vector.aadComponents,
          }),
        ).toBe(vector.expectedPlaintext);
      });

      it('金额字段保持十进制字符串,不被解析为浮点数', () => {
        const payload = JSON.parse(vector.expectedPlaintext) as Record<string, unknown>;
        const stack: unknown[] = [payload];
        while (stack.length > 0) {
          const node = stack.pop();
          if (!node || typeof node !== 'object') continue;
          for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
            if (k === 'amount') expect(typeof v).toBe('string');
            if (v && typeof v === 'object') stack.push(v);
          }
        }
      });
    });
  }
});

describe('webhook 负向', () => {
  const vector = vectors.vectors.webhook[0] as NonNullable<(typeof vectors.vectors.webhook)[0]>;
  const rawBody = Buffer.from(vector.body, 'utf8');

  it('body 多一个字节即验签失败', () => {
    expect(() => handler().verify(Buffer.concat([rawBody, Buffer.from(' ')]), vector.headers)).toThrowError(
      /signature verification failed/,
    );
  });

  it('篡改 Delivery-Id 头即验签失败', () => {
    const headers = { ...vector.headers, 'X-SlaunchX-Delivery-Id': 'whd_forged_001' };
    expect(() => handler().verify(rawBody, headers)).toThrowError(/signature verification failed/);
  });

  it('篡改事件类型头即验签失败', () => {
    const headers = { ...vector.headers, 'X-SlaunchX-Event-Type': 'card.status' };
    expect(() => handler().verify(rawBody, headers)).toThrowError(/signature verification failed/);
  });

  it('缺少必需头时抛错', () => {
    const headers: Record<string, string> = { ...vector.headers };
    delete headers['X-SlaunchX-Signature'];
    expect(() => handler().verify(rawBody, headers)).toThrowError(/missing webhook header/);
  });

  it('Key-Id 与配置不符时抛错', () => {
    expect(() => handler({ apiKeyBizId: 'apk_other_0002' }).verify(rawBody, vector.headers)).toThrowError(
      /does not match the configured API key/,
    );
  });

  it('用 hex 摘要构造的规范串验签必然失败', () => {
    const hexDigest = Buffer.from(vector.bodyDigestBase64, 'base64').toString('hex');
    const canonical = buildWebhookCanonicalString(
      vector.aadComponents.requestId,
      vector.headers['X-SlaunchX-Event-Type'] as string,
      vector.aadComponents.timestamp,
      hexDigest,
    );
    expect(
      verifyCanonicalSignature(canonical, vector.headers['X-SlaunchX-Signature'] as string, platformAuth.publicKeyPem),
    ).toBe(false);
  });

  it('信封多出 encryptedPayload 字段即被拒绝(additionalProperties: false)', () => {
    const envelope = JSON.parse(vector.body) as Record<string, unknown>;
    envelope['encryptedPayload'] = envelope['ciphertext'];
    expect(() => assertWebhookEnvelope(envelope)).toThrowError(/unexpected field: encryptedPayload/);
  });

  it('envelopeVersion 不为 1 即被拒绝', () => {
    const envelope = JSON.parse(vector.body) as Record<string, unknown>;
    envelope['envelopeVersion'] = 2;
    expect(() => assertWebhookEnvelope(envelope)).toThrowError(/envelopeVersion must be exactly 1/);
  });

  it('AAD routeTemplate 用外部路径而非 webhook 字面量时解密失败', () => {
    const envelope = assertWebhookEnvelope(JSON.parse(vector.body));
    expect(() =>
      EnvelopeCodec.openText(envelope, {
        privateKey: merchantEnc.privateKeyPem,
        aad: { ...vector.aadComponents, routeTemplate: '/webhooks/card' },
      }),
    ).toThrowError(/rebuilt AAD does not match/);
  });

  it('AAD keyId 用指纹而非 API Key 业务 ID 时解密失败', () => {
    const envelope = assertWebhookEnvelope(JSON.parse(vector.body));
    expect(() =>
      EnvelopeCodec.openText(envelope, {
        privateKey: merchantEnc.privateKeyPem,
        aad: { ...vector.aadComponents, keyId: merchantEnc.fingerprint },
      }),
    ).toThrowError(/rebuilt AAD does not match/);
  });

  it('时间戳容差默认关闭,启用后可拒绝过旧投递', () => {
    expect(() => handler().verify(rawBody, vector.headers)).not.toThrow();
    const strict = handler({ timestampToleranceMs: 60_000, now: () => 1788142396408 + 120_000 });
    expect(() => strict.verify(rawBody, vector.headers)).toThrowError(/timestamp skew/);
    const lenient = handler({ timestampToleranceMs: 300_000, now: () => 1788142396408 + 120_000 });
    expect(() => lenient.verify(rawBody, vector.headers)).not.toThrow();
  });

  it('明文与传输头交叉校验失败时抛错', () => {
    const forgedHeaders = { ...vector.headers };
    const delivery = handler().handle(rawBody, vector.headers);
    expect(delivery.payload.deliveryBizId).toBe(forgedHeaders['X-SlaunchX-Delivery-Id']);

    const custom = new WebhookHandler({
      platformAuthPublicKey: platformAuth.publicKeyPem,
      merchantEncPrivateKey: merchantEnc.privateKeyPem,
    });
    // 用错配的 deliveryBizId 重新封装一份合法信封,但明文里的 deliveryBizId 保持原值。
    const mismatched = EnvelopeCodec.seal(vector.expectedPlaintext, {
      recipientPublicKey: merchantEnc.publicKeyPem,
      aad: {
        requestId: 'whd_mismatch_999',
        routeTemplate: 'webhook',
        timestamp: vector.aadComponents.timestamp,
        keyId: vector.aadComponents.keyId,
      },
      envelopeVersion: 1,
      includeEncryptedPayload: false,
    });
    const body = Buffer.from(JSON.stringify(mismatched), 'utf8');
    const canonical = buildWebhookCanonicalString(
      'whd_mismatch_999',
      vector.headers['X-SlaunchX-Event-Type'] as string,
      vector.aadComponents.timestamp,
      webhookBodyDigestBase64(body),
    );
    // 用 platform_auth 私钥重新签名,模拟一次合法投递但明文 deliveryBizId 不一致。
    const signature = signWith(canonical);
    expect(() =>
      custom.handle(body, {
        'X-SlaunchX-Delivery-Id': 'whd_mismatch_999',
        'X-SlaunchX-Event-Type': vector.headers['X-SlaunchX-Event-Type'] as string,
        'X-SlaunchX-Timestamp': vector.aadComponents.timestamp,
        'X-SlaunchX-Key-Id': vector.aadComponents.keyId,
        'X-SlaunchX-Signature': signature,
      }),
    ).toThrowError(PlutusWebhookError);
  });
});

/** 测试内联签名:仅用于构造负向用例,生产侧商户不持有 platform_auth 私钥。 */
function signWith(canonical: string): string {
  return signCanonicalString(canonical, loadPrivateKey(platformAuth.privateKeyPem));
}
