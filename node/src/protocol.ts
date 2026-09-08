import { randomBytes } from 'node:crypto';
import { PlutusConfigError, PlutusCanonicalizationError, PlutusRequestError } from './errors.js';

export enum ProtocolProfile {
  REQUEST_BOUND_V1 = 'request-bound-v1',
  PRODUCT_V1 = 'product-v1',
}

export function resolveProfile(value: ProtocolProfile = ProtocolProfile.REQUEST_BOUND_V1): ProtocolProfile {
  if (value !== ProtocolProfile.REQUEST_BOUND_V1 && value !== ProtocolProfile.PRODUCT_V1) {
    throw new PlutusConfigError('unknown protocolProfile');
  }
  return value;
}

export function productCanonicalQuery(raw: string | null | undefined): string {
  if (raw == null || /^[\u0009-\u000d\u001c-\u0020\u1680\u2000-\u2006\u2008-\u200a\u2028\u2029\u205f\u3000]*$/u.test(raw)) return '';
  try {
    const encode = (value: string): string => encodeURIComponent(value).replace(/[!'()~]/g, ch => '%' + ch.charCodeAt(0).toString(16).toUpperCase());
    const decode = (value: string): string => decodeURIComponent(value.replace(/\+/g, ' '));
    const pairs = raw.split('&').map(part => {
      const index = part.indexOf('=');
      return [decode(index < 0 ? part : part.slice(0, index)), decode(index < 0 ? '' : part.slice(index + 1))] as const;
    });
    // Java String ordering compares decoded UTF-16 code units, as JavaScript does.
    pairs.sort((a, b) => a[0] !== b[0] ? (a[0] < b[0] ? -1 : 1) : a[1] === b[1] ? 0 : a[1] < b[1] ? -1 : 1);
    return pairs.map(([key, value]) => encode(key) + '=' + encode(value)).join('&');
  } catch {
    throw new PlutusCanonicalizationError('invalid product query encoding');
  }
}

export function productRequestId(value?: string | null): string {
  if (value != null && /[\r\n]/.test(value)) throw new PlutusRequestError('X-Request-Id must not contain newlines');
  return value?.trim() || 'req_' + randomBytes(16).toString('hex');
}
