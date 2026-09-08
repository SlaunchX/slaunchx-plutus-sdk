import { readFileSync } from 'node:fs';
import { sign, constants, createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { PlutusClient, ProtocolProfile, RequestSigner, ResponseVerifier, canonicalizeQuery, verifyCanonicalSignature } from '../src/index.js';
import { key } from './vectors.js';
const profile = ProtocolProfile.PRODUCT_V1;
const queries = JSON.parse(readFileSync(new URL('../../shared/product-query-vectors.json', import.meta.url), 'utf8')) as { valid: [string | null, string][]; invalid: string[] };
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const signed = (value: string) => sign('RSA-SHA256', Buffer.from(value), {key:key('platform_auth').privateKeyPem, padding:constants.RSA_PKCS1_PADDING}).toString('base64');
const keys = { merchantAuthPrivateKey:key('merchant_auth').privateKeyPem, platformAuthPublicKey:key('platform_auth').publicKeyPem };

describe('product protocol', () => {
  it.each(queries.valid)('query %s', (raw, expected) => expect(canonicalizeQuery(raw, profile)).toBe(expected));
  it.each(queries.invalid)('rejects query %s', raw => expect(() => canonicalizeQuery(raw, profile)).toThrow());
  it.each(['missing','present','wrong','empty','tamper','other','alpha','unsigned'])('response %s', async mode => {
    const ids: string[] = [];
    const fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const headers = new Headers(init!.headers);
      const id = headers.get('X-Request-Id')!; ids.push(id); expect(id).toBeTruthy();
      expect(headers.get('X-Idempotency-Key')).toBe('operation-1');
      expect(String(url)).toBe('https://example.test/test?q=a%20b&star=*&tilde=%7E');
      const canonical = [init!.method, '/test', 'q=a%20b&star=*&tilde=%7E', headers.get('X-Timestamp'), headers.get('X-Nonce'), '1', hash(Buffer.from(init!.body as Uint8Array).toString())].join('\n');
      expect(verifyCanonicalSignature(canonical, headers.get('X-Signature')!, key('merchant_auth').publicKeyPem)).toBe(true);
      const body = '{"success":true,"data":[]}';
      let lines = [mode === 'other' ? 'another-id' : id, '200', 'application/json', '1788836400000', hash(body)];
      if (mode === 'alpha') lines = ['SLAUNCHX-API-RESPONSE-V1', hash(canonical), '1', '/test', '', ...lines];
      const responseHeaders: Record<string,string> = {'Content-Type':'application/json','X-Response-Timestamp':'1788836400000','X-Response-Signature':signed(lines.join('\n'))};
      if (['present','wrong','empty'].includes(mode)) responseHeaders['X-Request-Id'] = mode === 'present' ? id : mode === 'wrong' ? 'wrong-id' : '';
      if (mode === 'unsigned') delete responseHeaders['X-Response-Signature'];
      return new Response(body + (mode === 'tamper' ? ' ' : ''), {status:200, headers:responseHeaders});
    }) as typeof globalThis.fetch;
    const client = new PlutusClient({baseUrl:'https://example.test', apiKey:'key', keys, protocolProfile:profile, fetch});
    const invoke = () => client.request({method:'POST', path:'/test', query:'q=a+b&tilde=~&star=%2A', body:{ok:true}, idempotencyKey:'operation-1'});
    if (['missing','present'].includes(mode)) {
      expect((await invoke()).signatureVerified).toBe(true);
      await invoke(); expect(ids[0]).not.toBe(ids[1]);
    } else await expect(invoke()).rejects.toThrow();
  });
  it('rejects ambiguous IDs before sending', async () => {
    const client = new PlutusClient({baseUrl:'https://example.test', apiKey:'key', keys, protocolProfile:profile});
    for (const headers of [{'x-request-id':'a','X-Request-Id':'b'}, {'X-Request-Id':'a\nb'}] as Record<string,string>[]) {
      await expect(client.request({method:'GET',path:'/test',headers})).rejects.toThrow();
    }
  });
  it('default protocol does not accept product signatures', () => {
    const request = new RequestSigner({apiKey:'key',merchantAuthPrivateKey:keys.merchantAuthPrivateKey}).sign({method:'GET',path:'/test'});
    expect(request.canonicalString.split('\n')).toHaveLength(8);
    const body = '{}';
    expect(() => new ResponseVerifier({platformAuthPublicKey:keys.platformAuthPublicKey}).verify({requestCanonicalSha256:request.requestCanonicalSha256,apiVersion:'1',externalPath:'/test',status:200,body:Buffer.from(body),sentRequestId:'id',headers:{'X-Request-Id':'id','Content-Type':'application/json','X-Response-Timestamp':'1788836400000','X-Response-Signature':signed(['id','200','application/json','1788836400000',hash(body)].join('\n'))}})).toThrow();
  });
});
