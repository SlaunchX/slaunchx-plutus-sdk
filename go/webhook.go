package plutus

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// MaxWebhookBodyBytes 是读取 Webhook 请求体的硬上限, 防止无界读取。
const MaxWebhookBodyBytes = 4 << 20

// WebhookBodyDigestBase64 计算 Webhook 签名规范串第 4 行的 body 摘要。
// 注意是 Base64, 与 API 链的小写 hex 摘要不是同一套编码。
func WebhookBodyDigestBase64(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// WebhookHeaders 是 Webhook 投递的传输头。
type WebhookHeaders struct {
	// DeliveryID 取自 X-SlaunchX-Delivery-Id, 是去重键。
	DeliveryID string
	// EventType 取自 X-SlaunchX-Event-Type。
	EventType string
	// Timestamp 取自 X-SlaunchX-Timestamp, Unix 毫秒。
	Timestamp string
	// KeyID 取自 X-SlaunchX-Key-Id, 是接收方 API Key 业务 ID, 不是指纹。
	KeyID string
	// Signature 取自 X-SlaunchX-Signature, Base64 RSA-SHA256 签名。
	Signature string
}

// WebhookHeadersFromHTTP 从 http.Header 提取 Webhook 传输头。
func WebhookHeadersFromHTTP(h http.Header) WebhookHeaders {
	return WebhookHeaders{
		DeliveryID: h.Get(HeaderWebhookDeliveryID),
		EventType:  h.Get(HeaderWebhookEventType),
		Timestamp:  h.Get(HeaderWebhookTimestamp),
		KeyID:      h.Get(HeaderWebhookKeyID),
		Signature:  h.Get(HeaderWebhookSignature),
	}
}

// CanonicalString 返回 Webhook 签名规范串 (4 行)。
func (h WebhookHeaders) CanonicalString(body []byte) string {
	return WebhookCanonicalString(h.DeliveryID, h.EventType, h.Timestamp, WebhookBodyDigestBase64(body))
}

// AAD 返回 Webhook 信封的 AAD 四元组: routeTemplate 固定为字面量 "webhook",
// keyId 为 API Key 业务 ID。
func (h WebhookHeaders) AAD() AAD {
	return AAD{
		RequestID:     h.DeliveryID,
		RouteTemplate: WebhookRouteTemplate,
		Timestamp:     h.Timestamp,
		KeyID:         h.KeyID,
	}
}

// WebhookPayload 是解密后的通知明文的顶层结构。
//
// Data 保持为原始 JSON, 由调用方按事件类型自行解码。金额是 {currency, amount} 且
// amount 为十进制字符串, 不得解析为浮点数, 见 Amount。
type WebhookPayload struct {
	EventID              string          `json:"eventId"`
	EventType            string          `json:"eventType"`
	PayloadSchemaVersion int             `json:"payloadSchemaVersion"`
	OccurredAt           string          `json:"occurredAt"`
	WorkspaceBizID       string          `json:"workspaceBizId"`
	DeliveryBizID        string          `json:"deliveryBizId"`
	Resource             WebhookResource `json:"resource"`
	Data                 json.RawMessage `json:"data"`
}

// WebhookResource 是通知指向的资源标识。
type WebhookResource struct {
	Type  string `json:"type"`
	BizID string `json:"bizId"`
}

// Amount 是协议中的金额表示。Amount 字段是主单位十进制字符串, 不是浮点数。
type Amount struct {
	Currency string `json:"currency"`
	Amount   string `json:"amount"`
}

// WebhookNotification 是一次通过验签与解密的 Webhook 投递。
type WebhookNotification struct {
	// Headers 是传输头。
	Headers WebhookHeaders
	// Body 是原始 HTTP body (即签名覆盖的信封 JSON 字节)。
	Body []byte
	// Envelope 是解析后的 Webhook 信封。
	Envelope *Envelope
	// Plaintext 是解密后的通知明文字节。
	Plaintext []byte
	// Payload 是解析后的通知载荷。
	Payload WebhookPayload
}

// DecodeData 把通知的 data 字段解码到 v。
func (n *WebhookNotification) DecodeData(v any) error {
	if len(n.Payload.Data) == 0 {
		return fmt.Errorf("plutus: webhook payload has no data field")
	}
	return json.Unmarshal(n.Payload.Data, v)
}

// ParseWebhookEnvelope 严格解析 Webhook 信封 JSON。
//
// Webhook 信封的 schema 为 additionalProperties:false, 因此出现未知字段 (含 encryptedPayload)
// 即视为非法; envelopeVersion 必须恰为 1。
func ParseWebhookEnvelope(body []byte) (*Envelope, error) {
	var raw struct {
		EnvelopeVersion *int   `json:"envelopeVersion"`
		Algorithm       string `json:"algorithm"`
		KeyFingerprint  string `json:"keyFingerprint"`
		EncryptedKey    string `json:"encryptedKey"`
		Ciphertext      string `json:"ciphertext"`
		AAD             string `json:"aad"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnvelopeInvalid, err)
	}
	if raw.EnvelopeVersion == nil || *raw.EnvelopeVersion != 1 {
		return nil, fmt.Errorf("%w: envelopeVersion must be 1", ErrEnvelopeInvalid)
	}
	env := &Envelope{
		EnvelopeVersion: raw.EnvelopeVersion,
		Algorithm:       raw.Algorithm,
		KeyFingerprint:  raw.KeyFingerprint,
		EncryptedKey:    raw.EncryptedKey,
		Ciphertext:      raw.Ciphertext,
		AAD:             raw.AAD,
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	return env, nil
}

// WebhookConfig 是 WebhookReceiver 的配置。密钥可用 PEM 或已解析对象提供, 两者取其一。
type WebhookConfig struct {
	// APIKey 是本商户的 API Key 业务 ID, 即 AAD 第 4 分量的期望值。
	// 非空时会与 X-SlaunchX-Key-Id 比对, 不一致直接拒绝。
	APIKey string
	// PlatformAuthPublicKeyPEM 是平台认证公钥, 用于验签。
	PlatformAuthPublicKeyPEM []byte
	// PlatformAuthPublicKey 是已解析的平台认证公钥。
	PlatformAuthPublicKey *rsa.PublicKey
	// MerchantEncPrivateKeyPEM 是商户加密私钥, 用于解密。
	MerchantEncPrivateKeyPEM []byte
	// MerchantEncPrivateKey 是已解析的商户加密私钥。
	MerchantEncPrivateKey *rsa.PrivateKey
	// TimestampTolerance 是本地时间戳容差; 0 表示不校验。
	// 协议未规定 Webhook 时间戳窗口 (SPEC 第 16 节), 默认关闭。
	TimestampTolerance time.Duration
	// Now 用于测试注入当前时间; 默认 time.Now。
	Now func() time.Time
}

// WebhookReceiver 完成 Webhook 的验签、解密与交叉校验。可并发使用。
type WebhookReceiver struct {
	apiKey      string
	verifyKey   *rsa.PublicKey
	decryptKey  *rsa.PrivateKey
	fingerprint string
	tolerance   time.Duration
	now         func() time.Time
}

// NewWebhookReceiver 构造 Webhook 接收器。
func NewWebhookReceiver(cfg WebhookConfig) (*WebhookReceiver, error) {
	verifyKey := cfg.PlatformAuthPublicKey
	if verifyKey == nil {
		if len(cfg.PlatformAuthPublicKeyPEM) == 0 {
			return nil, fmt.Errorf("%w: platform_auth public key is required", ErrInvalidConfig)
		}
		parsed, err := ParseRSAPublicKeyPEM(cfg.PlatformAuthPublicKeyPEM)
		if err != nil {
			return nil, err
		}
		verifyKey = parsed
	}
	decryptKey := cfg.MerchantEncPrivateKey
	if decryptKey == nil {
		if len(cfg.MerchantEncPrivateKeyPEM) == 0 {
			return nil, fmt.Errorf("%w: merchant_enc private key is required", ErrInvalidConfig)
		}
		parsed, err := ParseRSAPrivateKeyPEM(cfg.MerchantEncPrivateKeyPEM)
		if err != nil {
			return nil, err
		}
		decryptKey = parsed
	}
	fingerprint, err := KeyFingerprint(&decryptKey.PublicKey)
	if err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &WebhookReceiver{
		apiKey:      cfg.APIKey,
		verifyKey:   verifyKey,
		decryptKey:  decryptKey,
		fingerprint: fingerprint,
		tolerance:   cfg.TimestampTolerance,
		now:         now,
	}, nil
}

// Verify 只做验签: 重建 4 行规范串并用平台认证公钥验证 X-SlaunchX-Signature。
// 签名覆盖的是信封 JSON 的原始字节, 必须先验签再解密。
func (r *WebhookReceiver) Verify(headers WebhookHeaders, body []byte) error {
	if headers.Signature == "" {
		return fmt.Errorf("%w: signature header is missing", ErrWebhookSignatureInvalid)
	}
	canonical := headers.CanonicalString(body)
	if err := VerifyCanonicalString(r.verifyKey, canonical, headers.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrWebhookSignatureInvalid, err)
	}
	return nil
}

// Handle 完成一次投递的全部处理: 验签 → 解析信封 → 重建 AAD 解密 → 解析明文 → 交叉校验。
//
// 调用方仍需按 Payload.DeliveryBizID 做去重, 自动重试与人工重放共用同一个投递 ID。
func (r *WebhookReceiver) Handle(headers WebhookHeaders, body []byte) (*WebhookNotification, error) {
	if r.apiKey != "" && headers.KeyID != r.apiKey {
		return nil, fmt.Errorf("%w: %s is %q, expected %q", ErrWebhookPayloadMismatch, HeaderWebhookKeyID, headers.KeyID, r.apiKey)
	}
	if err := r.checkTimestamp(headers.Timestamp); err != nil {
		return nil, err
	}
	if err := r.Verify(headers, body); err != nil {
		return nil, err
	}
	env, err := ParseWebhookEnvelope(body)
	if err != nil {
		return nil, err
	}
	if err := env.VerifyFingerprint(r.fingerprint); err != nil {
		return nil, err
	}
	plaintext, err := Open(r.decryptKey, env, headers.AAD())
	if err != nil {
		return nil, err
	}
	var payload WebhookPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("plutus: decode webhook payload: %w", err)
	}
	if payload.DeliveryBizID != headers.DeliveryID {
		return nil, fmt.Errorf("%w: deliveryBizId %q != header %q", ErrWebhookPayloadMismatch, payload.DeliveryBizID, headers.DeliveryID)
	}
	if payload.EventType != headers.EventType {
		return nil, fmt.Errorf("%w: eventType %q != header %q", ErrWebhookPayloadMismatch, payload.EventType, headers.EventType)
	}
	if payload.PayloadSchemaVersion != 1 {
		return nil, fmt.Errorf("%w: payloadSchemaVersion must be 1, got %d", ErrWebhookPayloadMismatch, payload.PayloadSchemaVersion)
	}
	return &WebhookNotification{
		Headers:   headers,
		Body:      body,
		Envelope:  env,
		Plaintext: plaintext,
		Payload:   payload,
	}, nil
}

// HandleRequest 从 http.Request 读取原始 body 并处理。
//
// 必须在任何中间件解析 body 之前调用: 签名覆盖的是原始字节, 重新序列化会破坏摘要。
func (r *WebhookReceiver) HandleRequest(req *http.Request) (*WebhookNotification, error) {
	if req.Body == nil {
		return nil, fmt.Errorf("%w: request body is nil", ErrWebhookSignatureInvalid)
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, MaxWebhookBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("plutus: read webhook body: %w", err)
	}
	if len(body) > MaxWebhookBodyBytes {
		return nil, fmt.Errorf("plutus: webhook body exceeds %d bytes", MaxWebhookBodyBytes)
	}
	return r.Handle(WebhookHeadersFromHTTP(req.Header), body)
}

func (r *WebhookReceiver) checkTimestamp(timestamp string) error {
	if r.tolerance <= 0 {
		return nil
	}
	millis, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %s is not a decimal millisecond string", ErrInvalidTimestamp, HeaderWebhookTimestamp)
	}
	delta := r.now().Sub(time.UnixMilli(millis))
	if delta < 0 {
		delta = -delta
	}
	if delta > r.tolerance {
		return fmt.Errorf("%w: skew %s exceeds %s", ErrWebhookTimestampOutOfRange, delta, r.tolerance)
	}
	return nil
}
