import { describe, expect, it } from 'vitest';
import {
  EnvelopeCodec,
  PlutusEnvelopeError,
  buildAad,
  keyFingerprint,
  loadPrivateKey,
  parseSensitiveResponseAad,
} from '../src/index.js';
import { key, vectors } from './vectors.js';

describe('encryptedEnvelope 向量组', () => {
  it('向量数量为 3', () => {
    expect(vectors.vectors.encryptedEnvelope).toHaveLength(3);
  });

  for (const vector of vectors.vectors.encryptedEnvelope) {
    describe(`${vector.id}: ${vector.description}`, () => {
      const pair = key(vector.decryptionKey);

      it('重建的 AAD 与向量的 aadString / aadBase64 / 信封回显逐字节一致', () => {
        const aad = buildAad(vector.aadComponents);
        expect(aad.toString('utf8')).toBe(vector.aadString);
        expect(aad.toString('base64')).toBe(vector.aadBase64);
        expect(vector.envelope.aad).toBe(vector.aadBase64);
      });

      it('信封 keyFingerprint 等于解密私钥对应的公钥指纹', () => {
        expect(vector.envelope.keyFingerprint).toBe(pair.fingerprint);
        expect(vector.aadComponents.keyId).toBe(pair.fingerprint);
      });

      it('API 链信封含 encryptedPayload 兼容字段且等于 ciphertext', () => {
        expect(vector.envelope.encryptedPayload).toBe(vector.envelope.ciphertext);
      });

      it('用向量指定的私钥解密并比对明文', () => {
        const plaintext = EnvelopeCodec.openText(vector.envelope, {
          privateKey: pair.privateKeyPem,
          aad: vector.aadComponents,
        });
        expect(plaintext).toBe(vector.expectedPlaintext);
      });
    });
  }

  it('en-01 的 routeTemplate 是端点外部路径', () => {
    const v = vectors.vectors.encryptedEnvelope.find((x) => x.id === 'en-01-encrypted-request');
    expect(v?.aadComponents.routeTemplate).toBe('/card-products/10010106/shared/cards/create');
    expect(v?.decryptionKey).toBe('platform_enc');
  });

  it('敏感响应的 routeTemplate 固定为空串,AAD 中出现连续两个竖线', () => {
    for (const v of vectors.vectors.encryptedEnvelope.filter((x) => x.direction === 'sensitive_response')) {
      expect(v.aadComponents.routeTemplate).toBe('');
      expect(v.aadString).toContain('||');
      expect(v.decryptionKey).toBe('merchant_enc');
    }
  });
});

describe('encryptedEnvelope 负向', () => {
  const vector = vectors.vectors.encryptedEnvelope[1] as NonNullable<
    (typeof vectors.vectors.encryptedEnvelope)[1]
  >;
  const pair = key(vector.decryptionKey);

  it('篡改 AAD 任一分量都必须解密失败', () => {
    for (const field of ['requestId', 'routeTemplate', 'timestamp', 'keyId'] as const) {
      const aad = { ...vector.aadComponents, [field]: `${vector.aadComponents[field]}x` };
      expect(() =>
        EnvelopeCodec.open(vector.envelope, { privateKey: pair.privateKeyPem, aad }),
      ).toThrowError(PlutusEnvelopeError);
    }
  });

  it('直接使用信封回显的 aad 而不重建时,回显被篡改也应被拒绝', () => {
    const tampered = {
      ...vector.envelope,
      aad: Buffer.from(`${vector.aadString}x`, 'utf8').toString('base64'),
    };
    expect(() =>
      EnvelopeCodec.open(tampered, { privateKey: pair.privateKeyPem, aad: vector.aadComponents }),
    ).toThrowError(/rebuilt AAD does not match/);
  });

  it('篡改 ciphertext 触发 GCM 认证失败', () => {
    const blob = Buffer.from(vector.envelope.ciphertext, 'base64');
    blob[blob.length - 1] = (blob[blob.length - 1] as number) ^ 0xff;
    const tampered = { ...vector.envelope, ciphertext: blob.toString('base64') };
    expect(() =>
      EnvelopeCodec.open(tampered, { privateKey: pair.privateKeyPem, aad: vector.aadComponents }),
    ).toThrowError(/AES-GCM authentication failed/);
  });

  it('用错误的私钥解密失败', () => {
    expect(() =>
      EnvelopeCodec.open(vector.envelope, {
        privateKey: key('platform_enc').privateKeyPem,
        aad: vector.aadComponents,
      }),
    ).toThrowError(PlutusEnvelopeError);
  });

  it('算法标识不符时拒绝', () => {
    expect(() =>
      EnvelopeCodec.open(
        { ...vector.envelope, algorithm: 'RSA-OAEP-AES-128-GCM' },
        { privateKey: pair.privateKeyPem, aad: vector.aadComponents },
      ),
    ).toThrowError(/unsupported envelope algorithm/);
  });

  it('明文长度上限被强制执行', () => {
    expect(() =>
      EnvelopeCodec.open(vector.envelope, {
        privateKey: pair.privateKeyPem,
        aad: vector.aadComponents,
        maxPlaintextBytes: 4,
      }),
    ).toThrowError(/exceeds the 4 byte limit/);
  });
});

describe('敏感响应解密:从信封 aad 重建时间戳', () => {
  for (const vector of vectors.vectors.encryptedEnvelope.filter((v) => v.direction === 'sensitive_response')) {
    it(`${vector.id} 解析 AAD 分量并解密`, () => {
      const parsed = parseSensitiveResponseAad(vector.envelope.aad);
      expect(parsed).toEqual(vector.aadComponents);

      const { plaintext, aad } = EnvelopeCodec.openSensitiveResponse(vector.envelope, {
        merchantEncPrivateKey: key('merchant_enc').privateKeyPem,
        requestId: vector.aadComponents.requestId,
      });
      expect(plaintext.toString('utf8')).toBe(vector.expectedPlaintext);
      expect(aad.timestamp).toBe(vector.aadComponents.timestamp);
    });
  }

  it('关联请求 ID 不符时拒绝', () => {
    const vector = vectors.vectors.encryptedEnvelope.find((v) => v.id === 'en-02-sensitive-response');
    expect(() =>
      EnvelopeCodec.openSensitiveResponse((vector as NonNullable<typeof vector>).envelope, {
        merchantEncPrivateKey: key('merchant_enc').privateKeyPem,
        requestId: 'req_someone_elses_request',
      }),
    ).toThrowError(/requestId does not match/);
  });

  it('requestId 为空串的向量可在不传 requestId 时解密', () => {
    const vector = vectors.vectors.encryptedEnvelope.find(
      (v) => v.id === 'en-03-sensitive-response-empty-request-id',
    ) as NonNullable<(typeof vectors.vectors.encryptedEnvelope)[0]>;
    const { plaintext } = EnvelopeCodec.openSensitiveResponse(vector.envelope, {
      merchantEncPrivateKey: key('merchant_enc').privateKeyPem,
    });
    expect(plaintext.toString('utf8')).toBe(vector.expectedPlaintext);
  });
});

describe('加密方向 round-trip', () => {
  const platformEnc = key('platform_enc');
  const merchantEnc = key('merchant_enc');

  it('加密请求:sealRequest 产出的信封可由平台加密私钥解开', () => {
    const plaintext = '{"platformCardProductBizId":"pcp_example_001","quantity":2}';
    const { envelope, bodyBytes, keyId } = EnvelopeCodec.sealRequest(plaintext, {
      requestId: 'req_roundtrip_0001',
      routeTemplate: '/card-products/10010106/shared/cards/create',
      timestamp: '1755600010000',
      platformEncPublicKey: platformEnc.publicKeyPem,
    });

    expect(keyId).toBe(platformEnc.fingerprint);
    expect(envelope.algorithm).toBe('RSA-OAEP-AES-256-GCM');
    expect(envelope.encryptedPayload).toBe(envelope.ciphertext);
    expect(JSON.parse(bodyBytes.toString('utf8'))).toEqual(envelope);
    // IV(12) + 明文 + 标签(16)
    expect(Buffer.from(envelope.ciphertext, 'base64').byteLength).toBe(12 + plaintext.length + 16);

    const decrypted = EnvelopeCodec.openText(envelope, {
      privateKey: platformEnc.privateKeyPem,
      aad: {
        requestId: 'req_roundtrip_0001',
        routeTemplate: '/card-products/10010106/shared/cards/create',
        timestamp: '1755600010000',
        keyId,
      },
    });
    expect(decrypted).toBe(plaintext);
  });

  it('每次加密使用不同的一次性密钥与 IV', () => {
    const seal = (): string =>
      EnvelopeCodec.seal('{"a":1}', {
        recipientPublicKey: platformEnc.publicKeyPem,
        aad: { requestId: 'r', routeTemplate: '/p', timestamp: '1', keyId: platformEnc.fingerprint },
      }).ciphertext;
    expect(seal()).not.toBe(seal());
  });

  it('敏感响应方向:平台用商户加密公钥封装,商户私钥解开', () => {
    const plaintext = '{"cardNumber":"4111111111111111"}';
    const aad = {
      requestId: 'req_roundtrip_0002',
      routeTemplate: '',
      timestamp: '1755600011000',
      keyId: merchantEnc.fingerprint,
    };
    const envelope = EnvelopeCodec.seal(plaintext, {
      recipientPublicKey: merchantEnc.publicKeyPem,
      aad,
    });
    const { plaintext: decrypted } = EnvelopeCodec.openSensitiveResponse(envelope, {
      merchantEncPrivateKey: merchantEnc.privateKeyPem,
      requestId: aad.requestId,
    });
    expect(decrypted.toString('utf8')).toBe(plaintext);
  });

  it('Webhook 形状:含 envelopeVersion 且不含 encryptedPayload', () => {
    const envelope = EnvelopeCodec.seal('{"eventId":"x"}', {
      recipientPublicKey: merchantEnc.publicKeyPem,
      aad: { requestId: 'whd_1', routeTemplate: 'webhook', timestamp: '1', keyId: 'apk_vector_0001' },
      envelopeVersion: 1,
      includeEncryptedPayload: false,
    });
    expect(envelope.envelopeVersion).toBe(1);
    expect('encryptedPayload' in envelope).toBe(false);
    expect(Object.keys(envelope).sort()).toEqual(
      ['aad', 'algorithm', 'ciphertext', 'encryptedKey', 'envelopeVersion', 'keyFingerprint'].sort(),
    );
  });

  it('信封 keyFingerprint 与接收方公钥指纹一致', () => {
    const envelope = EnvelopeCodec.seal('x', {
      recipientPublicKey: merchantEnc.publicKeyPem,
      aad: { requestId: '', routeTemplate: '', timestamp: '1', keyId: merchantEnc.fingerprint },
    });
    expect(envelope.keyFingerprint).toBe(keyFingerprint(loadPrivateKey(merchantEnc.privateKeyPem)));
  });
});
