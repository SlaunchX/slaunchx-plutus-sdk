/**
 * `@slaunchx/plutus-sdk` — SlaunchX Plutus 商户 API SDK(协议 `SLAUNCHX-PLUTUS-API-V1`)。
 *
 * 覆盖四层密码学处理:请求签名、请求加密、响应验签、敏感响应解密,外加 Webhook 验签与解密。
 * 只实现传输层,不封装业务端点。
 */

export { ProtocolProfile } from './protocol.js';

export {
  EMPTY_BODY_SHA256,
  FORCED_EMPTY_BODY_METHODS,
  NONCE_PATTERN,
  RESPONSE_CANONICAL_PREFIX,
  bodyDigestHex,
  buildAad,
  buildRequestCanonicalString,
  buildResponseCanonicalString,
  buildWebhookCanonicalString,
  canonicalizeComponent,
  canonicalizeQuery,
  encodeQueryParams,
  isForcedEmptyBodyMethod,
  isValidNonce,
  percentDecodeStrict,
  percentEncode,
  requestCanonicalSha256,
  signedBodyDigest,
  webhookBodyDigestBase64,
  type AadComponents,
  type QueryParamValue,
  type RequestCanonicalInput,
  type ResponseCanonicalInput,
} from './canonical.js';

export {
  SDK_VERSION,
  resolveConfig,
  type PlutusConfig,
  type PlutusKeyMaterial,
  type ResolvedConfig,
} from './config.js';

export {
  AES_KEY_BYTES,
  ENVELOPE_ALGORITHM,
  EnvelopeCodec,
  IV_BYTES,
  MAX_PLAINTEXT_BYTES,
  TAG_BYTES,
  parseSensitiveResponseAad,
  type HybridEnvelope,
  type OpenOptions,
  type SealOptions,
  type WebhookEnvelope,
} from './envelope.js';

export {
  MAX_MODULUS_BITS,
  MIN_MODULUS_BITS,
  REQUIRED_PUBLIC_EXPONENT,
  constantTimeEquals,
  keyFingerprint,
  loadPrivateKey,
  loadPublicKey,
  type KeyInput,
  type PublicKeyOptions,
} from './keys.js';

export {
  DEFAULT_API_VERSION,
  RequestSigner,
  SIGNATURE_ALGORITHM,
  generateNonce,
  signCanonicalString,
  verifyCanonicalSignature,
  type QueryInput,
  type RequestSignerOptions,
  type SignableRequest,
  type SignedRequest,
} from './signer.js';

export {
  ResponseVerifier,
  readHeader,
  snapshotHeaders,
  type HeaderSource,
  type ResponseVerificationInput,
  type ResponseVerificationResult,
  type ResponseVerifierOptions,
} from './verifier.js';

export {
  ACCOUNT_PENDING_APPROVAL,
  SUCCESS_CODES,
  extractRateLimit,
  isSuccessCode,
  isSuccessResponse,
  toApiError,
  type ApiResponse,
  type PlutusResponse,
  type RateLimitInfo,
} from './response.js';

export { PlutusClient, serializeBody, type PlutusRequestOptions } from './client.js';

export { ENCRYPTED_ROUTE_TEMPLATES, isKnownEncryptedRoute } from './routes.js';

export {
  WEBHOOK_ROUTE_TEMPLATE,
  WebhookHandler,
  assertPayloadMatchesHeaders,
  assertWebhookEnvelope,
  extractWebhookHeaders,
  type WebhookDelivery,
  type WebhookHandlerOptions,
  type WebhookHeaders,
  type WebhookPayload,
} from './webhook.js';

export {
  PlutusApiError,
  PlutusAuthenticationError,
  PlutusCanonicalizationError,
  PlutusConfigError,
  PlutusConflictError,
  PlutusEnvelopeError,
  PlutusError,
  PlutusKeyError,
  PlutusNotFoundError,
  PlutusPermissionError,
  PlutusRateLimitError,
  PlutusRequestError,
  PlutusSecureChannelError,
  PlutusServerError,
  PlutusSignatureError,
  PlutusTransportError,
  PlutusValidationError,
  PlutusWebhookError,
  createApiError,
  errorFamily,
  type ErrorFamily,
  type PlutusApiErrorInit,
  type PublicErrorCode,
} from './errors.js';
