"""SlaunchX Plutus 商户 Python SDK。

实现协议 ``SLAUNCHX-PLUTUS-API-V1`` 的传输层:请求签名、响应验签、混合加密信封与
Webhook 接收。不建立业务端点模型,业务路径与载荷由调用方给出。

典型用法::

    from slaunchx_plutus_sdk import PlutusClient, PlutusConfig

    client = PlutusClient(PlutusConfig(
        base_url="https://consumer-api.example.com",
        api_key="apk_xxx",
        merchant_auth_private_key="/path/to/merchant_auth_private.pem",
        platform_auth_public_key="/path/to/platform_auth_public.pem",
    ))
    resp = client.get("/card-products/cards/page", query={"pageSize": 20})
"""

from __future__ import annotations

from .client import (
    ApiResponse,
    PlutusClient,
    UnknownEncryptedRouteWarning,
    generate_request_id,
    serialize_json,
)
from .config import (
    DEFAULT_API_VERSION,
    MAX_PLAINTEXT_BYTES,
    PlutusConfig,
    load_private_key,
    load_public_key,
    spki_fingerprint,
)
from .envelope import (
    ENVELOPE_ALGORITHM,
    build_aad,
    decrypt_envelope,
    decrypt_sensitive_response,
    encrypt_envelope,
    encrypt_request_payload,
    parse_aad,
)
from .errors import (
    ApiError,
    AuthenticationError,
    CanonicalQueryError,
    ConfigurationError,
    ConflictError,
    EndpointRetiredError,
    EnvelopeError,
    NonceReusedError,
    NotFoundError,
    PermissionDeniedError,
    PlutusError,
    PublicErrorCode,
    RateLimitedError,
    ResponseSignatureError,
    SecureChannelError,
    ServerError,
    SignatureError,
    TimestampExpiredError,
    TransportError,
    ValidationError,
    WebhookEnvelopeError,
    WebhookError,
    WebhookPayloadError,
    WebhookSignatureError,
)
from .result_codes import (
    ACCOUNT_PENDING_APPROVAL,
    SUCCESS_CODES,
    is_success_code,
)
from .routes import (
    ENCRYPTED_ROUTE_TEMPLATES,
    is_known_encrypted_route,
)
from .signer import (
    EMPTY_BODY_SHA256,
    FORCED_EMPTY_BODY_METHODS,
    SIGNATURE_ALGORITHM,
    RequestSigner,
    SignedRequest,
    body_sha256_hex,
    build_request_canonical_string,
    canonical_sha256,
    canonicalize_query,
    current_timestamp_ms,
    encode_query,
    generate_nonce,
    sign_canonical_string,
    validate_nonce,
)
from .verifier import (
    RESPONSE_CANONICAL_PREFIX,
    ResponseVerifier,
    build_response_canonical_string,
    response_body_sha256_hex,
    verify_signature,
)
from .webhook import (
    WEBHOOK_ROUTE_TEMPLATE,
    WebhookEvent,
    WebhookReceiver,
    build_webhook_canonical_string,
    webhook_body_digest_base64,
)

__version__ = "0.1.0"

#: 协议标识
PROTOCOL = "SLAUNCHX-PLUTUS-API-V1"

__all__ = [
    "__version__",
    "PROTOCOL",
    # client
    "PlutusClient",
    "ApiResponse",
    "serialize_json",
    "generate_request_id",
    "UnknownEncryptedRouteWarning",
    # result codes
    "SUCCESS_CODES",
    "ACCOUNT_PENDING_APPROVAL",
    "is_success_code",
    # routes
    "ENCRYPTED_ROUTE_TEMPLATES",
    "is_known_encrypted_route",
    # config
    "PlutusConfig",
    "DEFAULT_API_VERSION",
    "MAX_PLAINTEXT_BYTES",
    "load_private_key",
    "load_public_key",
    "spki_fingerprint",
    # signer
    "RequestSigner",
    "SignedRequest",
    "EMPTY_BODY_SHA256",
    "FORCED_EMPTY_BODY_METHODS",
    "SIGNATURE_ALGORITHM",
    "canonicalize_query",
    "encode_query",
    "body_sha256_hex",
    "build_request_canonical_string",
    "canonical_sha256",
    "sign_canonical_string",
    "generate_nonce",
    "validate_nonce",
    "current_timestamp_ms",
    # verifier
    "ResponseVerifier",
    "RESPONSE_CANONICAL_PREFIX",
    "build_response_canonical_string",
    "response_body_sha256_hex",
    "verify_signature",
    # envelope
    "ENVELOPE_ALGORITHM",
    "build_aad",
    "parse_aad",
    "encrypt_envelope",
    "decrypt_envelope",
    "encrypt_request_payload",
    "decrypt_sensitive_response",
    # webhook
    "WebhookReceiver",
    "WebhookEvent",
    "WEBHOOK_ROUTE_TEMPLATE",
    "webhook_body_digest_base64",
    "build_webhook_canonical_string",
    # errors
    "PlutusError",
    "ConfigurationError",
    "CanonicalQueryError",
    "SignatureError",
    "ResponseSignatureError",
    "EnvelopeError",
    "WebhookError",
    "WebhookSignatureError",
    "WebhookEnvelopeError",
    "WebhookPayloadError",
    "TransportError",
    "ApiError",
    "AuthenticationError",
    "TimestampExpiredError",
    "NonceReusedError",
    "PermissionDeniedError",
    "ValidationError",
    "NotFoundError",
    "ConflictError",
    "RateLimitedError",
    "SecureChannelError",
    "EndpointRetiredError",
    "ServerError",
    "PublicErrorCode",
]
