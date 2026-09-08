import { describe, expect, it, vi } from 'vitest';
import {
  ENCRYPTED_ROUTE_TEMPLATES,
  PlutusClient,
  PlutusRequestError,
  isKnownEncryptedRoute,
  type PlutusConfig,
} from '../src/index.js';
import { key } from './vectors.js';

const merchantAuth = key('merchant_auth');
const platformAuth = key('platform_auth');
const platformEnc = key('platform_enc');

const BASE_URL = 'https://consumer-api.example.test';

const SUCCESS_BODY =
  '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{"ok":true}}';

/** 不做任何验签的最简 fetch mock:只用于校验 `encrypt` 分支是否被阻断,不关心响应真实性。 */
function unsignedFetch(): typeof globalThis.fetch {
  return (async () =>
    new Response(SUCCESS_BODY, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })) as typeof globalThis.fetch;
}

function baseConfig(overrides: Partial<PlutusConfig> = {}): PlutusConfig {
  return {
    apiVersion: '1',
    baseUrl: BASE_URL,
    apiKey: 'apk_vector_0001',
    verifyResponseSignature: false,
    keys: {
      merchantAuthPrivateKey: merchantAuth.privateKeyPem,
      platformAuthPublicKey: platformAuth.publicKeyPem,
      platformEncPublicKey: platformEnc.publicKeyPem,
    },
    fetch: unsignedFetch(),
    ...overrides,
  };
}

describe('ENCRYPTED_ROUTE_TEMPLATES', () => {
  it('恰好包含且仅包含 SPEC.md 第 3 节列出的 6 条外部路径,逐字节匹配', () => {
    expect(ENCRYPTED_ROUTE_TEMPLATES).toEqual([
      '/card-products/10010105/cards/create',
      '/card-products/10010106/shared/cards/create',
      '/card-products/10010106/prepaid/cards/create',
      '/card-products/10010107/prepaid/cards/create',
      '/card-products/10010107/prepaid/cards/recharge',
      '/card-products/10010107/prepaid/cards/withdraw',
    ]);
    expect(ENCRYPTED_ROUTE_TEMPLATES).toHaveLength(6);
  });
});

describe('isKnownEncryptedRoute', () => {
  it('已知路径返回 true', () => {
    for (const route of ENCRYPTED_ROUTE_TEMPLATES) {
      expect(isKnownEncryptedRoute(route)).toBe(true);
    }
  });

  it('未知路径返回 false', () => {
    expect(isKnownEncryptedRoute('/card-products/cards/freeze')).toBe(false);
    expect(isKnownEncryptedRoute('/card-products/10010106/shared/cards/create/extra')).toBe(false);
    expect(isKnownEncryptedRoute('')).toBe(false);
    // 大小写与末尾斜杠必须逐字节匹配,不做归一化。
    expect(isKnownEncryptedRoute('/card-products/10010105/cards/create/')).toBe(false);
  });
});

describe('PlutusClient 加密端点 routeTemplate 校验', () => {
  it('默认(非严格)模式:未知路由不抛异常,请求正常完成,但会发出一次警告', async () => {
    const warnSpy = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
    const client = new PlutusClient(baseConfig());

    const res = await client.request({
      method: 'POST',
      path: '/card-products/unknown/route',
      body: { a: 1 },
      encrypt: true,
    });

    expect(res.status).toBe(200);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(String(warnSpy.mock.calls[0]?.[0])).toMatch(/routeTemplate/);
    warnSpy.mockRestore();
  });

  it('默认(非严格)模式:已知路由不触发警告', async () => {
    const warnSpy = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);
    const client = new PlutusClient(baseConfig());

    await client.request({
      method: 'POST',
      path: ENCRYPTED_ROUTE_TEMPLATES[1] as string,
      body: { a: 1 },
      encrypt: true,
    });

    expect(warnSpy).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it('严格模式:未知路由抛出 PlutusRequestError,请求不会发出', async () => {
    const capture: unknown[] = [];
    const client = new PlutusClient(
      baseConfig({
        strictEncryptedRouteValidation: true,
        fetch: (async (...args: unknown[]) => {
          capture.push(args);
          return unsignedFetch()(...(args as [never, never]));
        }) as typeof globalThis.fetch,
      }),
    );

    await expect(
      client.request({
        method: 'POST',
        path: '/card-products/unknown/route',
        body: { a: 1 },
        encrypt: true,
      }),
    ).rejects.toThrowError(PlutusRequestError);
    expect(capture).toHaveLength(0);
  });

  it('严格模式:已知路由不受影响,请求正常完成', async () => {
    const client = new PlutusClient(
      baseConfig({
        strictEncryptedRouteValidation: true,
      }),
    );

    const res = await client.request({
      method: 'POST',
      path: ENCRYPTED_ROUTE_TEMPLATES[0] as string,
      body: { a: 1 },
      encrypt: true,
    });
    expect(res.status).toBe(200);
  });

  it('严格模式:显式传 routeTemplate 覆盖 path 时,按 routeTemplate 校验', async () => {
    const client = new PlutusClient(
      baseConfig({
        strictEncryptedRouteValidation: true,
      }),
    );

    // path 本身不在列表中,但显式给出的 routeTemplate 在列表中,应当放行。
    const res = await client.request({
      method: 'POST',
      path: '/internal/alias/create',
      body: { a: 1 },
      encrypt: { routeTemplate: ENCRYPTED_ROUTE_TEMPLATES[2] as string },
    });
    expect(res.status).toBe(200);

    await expect(
      client.request({
        method: 'POST',
        path: ENCRYPTED_ROUTE_TEMPLATES[0] as string,
        body: { a: 1 },
        encrypt: { routeTemplate: '/internal/alias/unknown' },
      }),
    ).rejects.toThrowError(PlutusRequestError);
  });
});
