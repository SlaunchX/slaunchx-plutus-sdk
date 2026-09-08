/**
 * 统一响应包络的成功判定测试。
 *
 * 使用本地 fixture,不依赖 `shared/test-vectors.json`。
 */

import { describe, expect, it } from 'vitest';
import {
  ACCOUNT_PENDING_APPROVAL,
  PlutusApiError,
  PlutusClient,
  SUCCESS_CODES,
  isSuccessCode,
  isSuccessResponse,
  toApiError,
  type ApiResponse,
  type PlutusConfig,
} from '../src/index.js';
import { key } from './vectors.js';

const merchantAuth = key('merchant_auth');
const BASE_URL = 'https://consumer-api.example.test';

/** 契约给出的标准成功包络。 */
const STANDARD_SUCCESS =
  '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{"ok":true}}';

interface Fixture {
  name: string;
  status: number;
  body: string;
  success: boolean;
  code?: string | null;
}

const FIXTURES: Fixture[] = [
  { name: '标准成功', status: 200, body: STANDARD_SUCCESS, success: true },
  {
    name: '创建成功',
    status: 201,
    body: '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2001","message":"Created","data":{"id":"c_1"}}',
    success: true,
  },
  {
    name: '待审批成功',
    status: 200,
    body: '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2101","message":"Pending approval","data":{}}',
    success: true,
  },
  {
    name: '业务失败但 HTTP 200',
    status: 200,
    body: '{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"4022","message":"Validation Error"}',
    success: false,
    code: '4022',
  },
  {
    name: '网关失败',
    status: 401,
    body: '{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"API.SIGNATURE_INVALID","message":"bad signature"}',
    success: false,
    code: 'API.SIGNATURE_INVALID',
  },
  { name: '无 success 字段 + HTTP 200', status: 200, body: '{"data":{}}', success: true },
  { name: '无 success 字段 + HTTP 500', status: 500, body: '{"message":"boom"}', success: false, code: null },
];

function parse(body: string): ApiResponse {
  return JSON.parse(body) as ApiResponse;
}

function clientWith(status: number, body: string): PlutusClient {
  const config: PlutusConfig = {
    apiVersion: '1',
    baseUrl: BASE_URL,
    apiKey: 'apk_vector_0001',
    keys: { merchantAuthPrivateKey: merchantAuth.privateKeyPem },
    // 本组用例只考察成功判定,验签路径由 client.test.ts 覆盖。
    verifyResponseSignature: false,
    fetch: (async () =>
      new Response(body, {
        status,
        headers: { 'Content-Type': 'application/json' },
      })) as typeof globalThis.fetch,
  };
  return new PlutusClient(config);
}

describe('isSuccessResponse 契约表', () => {
  for (const fixture of FIXTURES) {
    it(`${fixture.name}:HTTP ${fixture.status} -> ${fixture.success ? '成功' : '失败'}`, () => {
      expect(isSuccessResponse(parse(fixture.body), fixture.status)).toBe(fixture.success);
    });

    if (!fixture.success) {
      it(`${fixture.name}:错误码为 ${String(fixture.code)}`, () => {
        const err = toApiError({
          status: fixture.status,
          body: parse(fixture.body),
          rawBody: Buffer.from(fixture.body, 'utf8'),
          headers: {},
        });
        expect(err.code).toBe(fixture.code ?? null);
      });
    }
  }
});

describe('isSuccessResponse 边界', () => {
  it('body 为 null 时回退到 HTTP 状态', () => {
    expect(isSuccessResponse(null, 204)).toBe(true);
    expect(isSuccessResponse(null, 500)).toBe(false);
  });

  it('success 为非布尔值时一律回退到 HTTP 状态', () => {
    for (const value of ['true', 1, 0, null, undefined, {}, []]) {
      expect(isSuccessResponse({ success: value } as unknown as ApiResponse, 200)).toBe(true);
      expect(isSuccessResponse({ success: value } as unknown as ApiResponse, 502)).toBe(false);
    }
  });

  it('code 不参与判定:HTTP 200 + code "2000" + success:false 判为失败', () => {
    expect(isSuccessResponse({ success: false, code: '2000' }, 200)).toBe(false);
  });

  it('code 不参与判定:HTTP 500 + success:true 判为成功', () => {
    expect(isSuccessResponse({ success: true, code: '2000' }, 500)).toBe(true);
  });

  it('不再把 code 0 视为成功标志', () => {
    expect(isSuccessResponse({ success: false, code: 0 }, 200)).toBe(false);
    expect(isSuccessResponse({ success: false, code: '0' }, 200)).toBe(false);
  });
});

describe('成功码常量', () => {
  it('集合与契约一致', () => {
    expect([...SUCCESS_CODES].sort()).toEqual(['2000', '2001', '2002', '2004', '2006', '2101']);
  });

  it('2101 是账号待审批的成功码', () => {
    expect(ACCOUNT_PENDING_APPROVAL).toBe('2101');
    expect(isSuccessCode(ACCOUNT_PENDING_APPROVAL)).toBe(true);
  });

  it('非成功码返回 false', () => {
    for (const code of ['4022', '5001', 'API.SIGNATURE_INVALID', '0', '']) {
      expect(isSuccessCode(code)).toBe(false);
    }
  });
});

describe('PlutusClient 端到端成功判定', () => {
  for (const fixture of FIXTURES) {
    it(`${fixture.name}:HTTP ${fixture.status}`, async () => {
      const client = clientWith(fixture.status, fixture.body);
      const outcome = await client
        .request({ method: 'GET', path: '/card-products/cards/page' })
        .then((res) => ({ ok: true as const, res }))
        .catch((err: unknown) => ({ ok: false as const, err }));

      expect(outcome.ok).toBe(fixture.success);
      if (outcome.ok) {
        expect(outcome.res.status).toBe(fixture.status);
        expect(outcome.res.body).toEqual(parse(fixture.body));
      } else {
        expect(outcome.err).toBeInstanceOf(PlutusApiError);
        expect((outcome.err as PlutusApiError).status).toBe(fixture.status);
        expect((outcome.err as PlutusApiError).code).toBe(fixture.code ?? null);
      }
    });
  }

  it('待审批成功仍返回 data,不抛错', async () => {
    const client = clientWith(
      200,
      '{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2101","message":"Pending approval","data":{"status":"PENDING_APPROVAL"}}',
    );
    const res = await client.request<{ status: string }>({ method: 'GET', path: '/auth/login' });
    expect(res.body?.code).toBe(ACCOUNT_PENDING_APPROVAL);
    expect(res.data).toEqual({ status: 'PENDING_APPROVAL' });
  });
});
