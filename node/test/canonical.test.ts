import { describe, expect, it } from 'vitest';
import {
  EMPTY_BODY_SHA256,
  PlutusCanonicalizationError,
  bodyDigestHex,
  canonicalizeQuery,
  encodeQueryParams,
  isValidNonce,
  signedBodyDigest,
} from '../src/index.js';
import { vectors } from './vectors.js';

describe('canonicalQuery 向量组', () => {
  it('向量数量与 meta.counts 一致', () => {
    expect(vectors.vectors.canonicalQuery).toHaveLength(vectors.meta.counts['canonicalQuery'] as number);
    expect(vectors.vectors.canonicalQuery).toHaveLength(21);
  });

  for (const vector of vectors.vectors.canonicalQuery) {
    it(`${vector.id}: ${vector.description}`, () => {
      if (vector.expectError) {
        expect(() => canonicalizeQuery(vector.input)).toThrowError(PlutusCanonicalizationError);
      } else {
        expect(canonicalizeQuery(vector.input)).toBe(vector.expected);
      }
    });
  }

  it('6 条拒绝用例全部覆盖', () => {
    const rejected = vectors.vectors.canonicalQuery.filter((v) => v.expectError);
    expect(rejected).toHaveLength(6);
    expect(rejected.map((v) => v.id)).toEqual([
      'cq-16-raw-plus-rejected',
      'cq-17-raw-reserved-rejected',
      'cq-18-invalid-percent-rejected',
      'cq-19-truncated-percent-rejected',
      'cq-20-invalid-utf8-rejected',
      'cq-21-raw-non-ascii-rejected',
    ]);
  });
});

describe('canonicalQuery 附加不变量', () => {
  it('undefined 与 null 同样返回空串', () => {
    expect(canonicalizeQuery(undefined)).toBe('');
  });

  it('过度编码的 unreserved 字符与裸写法等价', () => {
    expect(canonicalizeQuery('x=a%2Db')).toBe(canonicalizeQuery('x=a-b'));
  });

  it('排序按 (key, value) 二元组的字节序,大写在小写之前', () => {
    expect(canonicalizeQuery('a=b&A=b&a=a')).toBe('A=b&a=a&a=b');
  });

  it('空片段保留,不被丢弃', () => {
    expect(canonicalizeQuery('&&')).toBe('=&=&=');
  });

  it('encodeQueryParams 产出的串必定能通过严格规范化', () => {
    const raw = encodeQueryParams({ q: 'hello world+中文', tilde: '~-._', plus: '+', empty: '' });
    expect(() => canonicalizeQuery(raw)).not.toThrow();
    expect(canonicalizeQuery(raw)).toBe(
      'empty=&plus=%2B&q=hello%20world%2B%E4%B8%AD%E6%96%87&tilde=~-._',
    );
  });

  it('数组参数展开为重复键', () => {
    expect(canonicalizeQuery(encodeQueryParams({ status: ['IN_USE', 'FROZEN'] }))).toBe(
      'status=FROZEN&status=IN_USE',
    );
  });
});

describe('bodyHash 向量组', () => {
  it('向量数量为 7', () => {
    expect(vectors.vectors.bodyHash).toHaveLength(7);
  });

  for (const vector of vectors.vectors.bodyHash) {
    it(`${vector.id}: ${vector.description}`, () => {
      const bytes = vector.body === null ? null : Buffer.from(vector.body, 'utf8');
      const actual = vector.method
        ? signedBodyDigest(vector.method, bytes)
        : bodyDigestHex(bytes);
      expect(actual).toBe(vector.expected);
      if (vector.forcedEmptyBody) {
        expect(actual).toBe(EMPTY_BODY_SHA256);
      }
    });
  }

  it('HEAD 同样强制空 body 摘要', () => {
    expect(signedBodyDigest('HEAD', Buffer.from('{"ignored":true}', 'utf8'))).toBe(EMPTY_BODY_SHA256);
  });

  it('方法名大小写不影响强制空体判定', () => {
    expect(signedBodyDigest('delete', Buffer.from('x', 'utf8'))).toBe(EMPTY_BODY_SHA256);
  });
});

describe('nonce 约束', () => {
  it('接受 UUID 与 hex,拒绝 Base64 与超短串', () => {
    expect(isValidNonce('3f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8')).toBe(true);
    expect(isValidNonce('a'.repeat(16))).toBe(true);
    expect(isValidNonce('a'.repeat(128))).toBe(true);
    expect(isValidNonce('a'.repeat(15))).toBe(false);
    expect(isValidNonce('a'.repeat(129))).toBe(false);
    expect(isValidNonce('YWJjZGVmZ2hpamts+/=')).toBe(false);
  });
});
