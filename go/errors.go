package plutus

import (
	"errors"
	"fmt"
)

// ErrorCode 是平台对外错误码, 形如 "域.名称"。业务判定应基于该码, 而非 GATEWAY_* 阶段码。
type ErrorCode string

// 与商户 API 认证/协议相关的错误码 (SPEC 第 13 节)。
const (
	CodeKeyMissing                ErrorCode = "API.KEY_MISSING"
	CodeKeyInvalid                ErrorCode = "API.KEY_INVALID"
	CodeKeyDisabled               ErrorCode = "API.KEY_DISABLED"
	CodeKeyLocked                 ErrorCode = "API.KEY_LOCKED"
	CodeTimestampRequired         ErrorCode = "API.TIMESTAMP_REQUIRED"
	CodeTimestampInvalid          ErrorCode = "API.TIMESTAMP_INVALID"
	CodeTimestampExpired          ErrorCode = "API.TIMESTAMP_EXPIRED"
	CodeVersionRequired           ErrorCode = "API.VERSION_REQUIRED"
	CodeVersionUnsupported        ErrorCode = "API.VERSION_UNSUPPORTED"
	CodeEndpointRetired           ErrorCode = "API.ENDPOINT_RETIRED"
	CodeNonceRequired             ErrorCode = "API.NONCE_REQUIRED"
	CodeNonceInvalid              ErrorCode = "API.NONCE_INVALID"
	CodeNonceReused               ErrorCode = "API.NONCE_REUSED"
	CodeSignatureRequired         ErrorCode = "API.SIGNATURE_REQUIRED"
	CodeSignatureAlgorithmInvalid ErrorCode = "API.SIGNATURE_ALGORITHM_INVALID"
	CodeSignatureInvalid          ErrorCode = "API.SIGNATURE_INVALID"
	CodeIPNotAllowed              ErrorCode = "API.IP_NOT_ALLOWED"
	CodeWorkspaceRequired         ErrorCode = "API.WORKSPACE_REQUIRED"
	CodeWorkspaceUnavailable      ErrorCode = "API.WORKSPACE_UNAVAILABLE"
	CodePermissionDenied          ErrorCode = "ACCESS.PERMISSION_DENIED"
	CodeSecureChannelInvalid      ErrorCode = "SECURE_CHANNEL.INVALID_PAYLOAD"
	CodeRateLimited               ErrorCode = "REQUEST.RATE_LIMITED"
	CodeConflict                  ErrorCode = "REQUEST.CONFLICT"
	CodeStaleVersion              ErrorCode = "REQUEST.STALE_VERSION"
	CodeInvalidParameter          ErrorCode = "VALIDATION.INVALID_PARAMETER"
	CodeNotFound                  ErrorCode = "RESOURCE.NOT_FOUND"
	CodeInternalError             ErrorCode = "SYSTEM.INTERNAL_ERROR"
)

// SDK 本地错误的哨兵值, 供 errors.Is 判定。
var (
	// ErrInvalidQuery 表示 query 串不满足 SPEC 4.2 的严格 percent 编码要求。
	ErrInvalidQuery = errors.New("plutus: invalid canonical query")
	// ErrInvalidNonce 表示 nonce 不满足 ^[A-Za-z0-9._~-]{16,128}$。
	ErrInvalidNonce = errors.New("plutus: invalid nonce")
	// ErrInvalidTimestamp 表示时间戳不是 Unix 毫秒十进制字符串。
	ErrInvalidTimestamp = errors.New("plutus: invalid timestamp")
	// ErrInvalidConfig 表示 Config 缺少必需字段或字段互相冲突。
	ErrInvalidConfig = errors.New("plutus: invalid config")
	// ErrInvalidKey 表示 PEM 密钥格式或参数不满足协议要求。
	ErrInvalidKey = errors.New("plutus: invalid rsa key")
	// ErrResponseSignatureMissing 表示响应缺少 X-Response-Signature 头。
	ErrResponseSignatureMissing = errors.New("plutus: response signature header missing")
	// ErrResponseSignatureInvalid 表示响应验签失败, 响应体必须丢弃。
	ErrResponseSignatureInvalid = errors.New("plutus: response signature verification failed")
	// ErrWebhookSignatureInvalid 表示 Webhook 验签失败, 不得继续解密。
	ErrWebhookSignatureInvalid = errors.New("plutus: webhook signature verification failed")
	// ErrEnvelopeInvalid 表示信封结构不合法 (字段缺失、算法不符、长度异常等)。
	ErrEnvelopeInvalid = errors.New("plutus: invalid encryption envelope")
	// ErrAADMismatch 表示本地重建的 AAD 与信封回显的 aad 不一致。
	ErrAADMismatch = errors.New("plutus: envelope aad mismatch")
	// ErrKeyFingerprintMismatch 表示信封 keyFingerprint 与本地公钥指纹不一致。
	ErrKeyFingerprintMismatch = errors.New("plutus: key fingerprint mismatch")
	// ErrDecryptFailed 表示 RSA 解包或 GCM 认证失败。
	ErrDecryptFailed = errors.New("plutus: envelope decryption failed")
	// ErrPlaintextTooLarge 表示解密后明文超过 MaxPlaintextBytes。
	ErrPlaintextTooLarge = errors.New("plutus: decrypted plaintext exceeds size limit")
	// ErrWebhookPayloadMismatch 表示 Webhook 明文与传输头交叉校验不一致。
	ErrWebhookPayloadMismatch = errors.New("plutus: webhook payload does not match transport headers")
	// ErrWebhookTimestampOutOfRange 表示 Webhook 时间戳超出本地配置的容差窗口。
	ErrWebhookTimestampOutOfRange = errors.New("plutus: webhook timestamp out of tolerance")
	// ErrUnknownEncryptedRoute 表示加密请求的 routeTemplate 不在已知加密端点表中(严格模式下阻断)。
	ErrUnknownEncryptedRoute = errors.New("plutus: unknown encrypted route template")
)

// QueryError 描述 query 规范化失败的具体原因, Unwrap 到 ErrInvalidQuery。
type QueryError struct {
	// Component 是触发失败的原始分量 (key 或 value)。
	Component string
	// Reason 是失败原因的英文短语, 与 SPEC 的拒绝理由对应。
	Reason string
}

func (e *QueryError) Error() string {
	return fmt.Sprintf("plutus: canonical query rejected: %s (component %q)", e.Reason, e.Component)
}

// Unwrap 返回 ErrInvalidQuery, 使 errors.Is(err, plutus.ErrInvalidQuery) 成立。
func (e *QueryError) Unwrap() error { return ErrInvalidQuery }

// APIError 是平台返回的非 2xx 响应对应的类型化错误。
//
// 判定错误族用 errors.Is 配合零值模板, 例如:
//
//	errors.Is(err, &plutus.APIError{Code: plutus.CodeNonceReused})
//	errors.Is(err, &plutus.APIError{HTTPStatus: 429})
//
// 取字段用 errors.As。
type APIError struct {
	// Code 是平台错误码; 响应体无法解析出错误码时为空。
	Code ErrorCode
	// Message 是平台返回的错误描述。
	Message string
	// HTTPStatus 是 HTTP 状态码。
	HTTPStatus int
	// RequestID 取自响应头 X-Request-Id。
	RequestID string
	// OperationID 取自响应头 X-Operation-Id。
	OperationID string
	// RetryAfter 取自响应头 Retry-After 原值 (429 时通常存在)。
	RetryAfter string
	// Response 是已解析的完整响应, 便于取原始 body。
	Response *APIResponse
}

// Error 返回错误码、HTTP 状态与平台描述, 不包含响应体与任何密钥材料。
func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("plutus: api error: http %d", e.HTTPStatus)
	}
	if e.Message == "" {
		return fmt.Sprintf("plutus: api error %s (http %d)", e.Code, e.HTTPStatus)
	}
	return fmt.Sprintf("plutus: api error %s (http %d): %s", e.Code, e.HTTPStatus, e.Message)
}

// Is 支持用只填 Code 或只填 HTTPStatus 的模板做匹配; 两者都填则须同时相等。
func (e *APIError) Is(target error) bool {
	t, ok := target.(*APIError)
	if !ok {
		return false
	}
	if t.Code == "" && t.HTTPStatus == 0 {
		return true
	}
	if t.Code != "" && t.Code != e.Code {
		return false
	}
	if t.HTTPStatus != 0 && t.HTTPStatus != e.HTTPStatus {
		return false
	}
	return true
}

// Retryable 给出 SPEC 第 13 节的重试建议。重试必须重新生成 timestamp 与 nonce 并重新签名;
// 写操作重试必须带 X-Idempotency-Key。
func (e *APIError) Retryable() bool {
	switch e.Code {
	case CodeTimestampExpired, CodeNonceReused, CodeRateLimited:
		return true
	}
	return e.HTTPStatus >= 500
}

// IsCode 判断 err 链上是否存在指定错误码的 APIError。
func IsCode(err error, code ErrorCode) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Code == code
}
