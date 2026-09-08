package plutus

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultMaxResponseBytes 是读取响应体的默认上限。
const DefaultMaxResponseBytes = 8 << 20

// Config 是 Client 的配置。密钥均可用 PEM 字节或已解析对象提供。
type Config struct {
	ProtocolProfile ProtocolProfile
	// BaseURL 是商户 API 的基地址, 如 https://consumer-api.example.com。
	// 必须是对外 CONSUMER API 域名 (边缘/网关地址), 不能是源站地址, 也不能自行拼接
	// /prometheus、/api/v1/consumer 等内部前缀: 外部路径统一由 Request.Path 给出,
	// 链/版本/门户前缀由边缘负责改写。BaseURL 配错是签名校验失败的常见根因之一,
	// 详见 README「BaseURL 配置」与「签名排障」两节。
	BaseURL string
	// APIKey 是 API Key 业务 ID, 对应 X-Api-Key。
	APIKey string
	// APIVersion 对应 X-API-VERSION, 必须显式填写；当前 product 填 "1"。
	APIVersion string

	// MerchantAuthPrivateKeyPEM / MerchantAuthPrivateKey 是商户认证私钥, 用于请求签名。必填。
	MerchantAuthPrivateKeyPEM []byte
	MerchantAuthPrivateKey    *rsa.PrivateKey
	// PlatformAuthPublicKeyPEM / PlatformAuthPublicKey 是平台认证公钥, 用于响应验签与 Webhook 验签。
	// 未提供时必须显式设置 DisableResponseSignatureVerification。
	PlatformAuthPublicKeyPEM []byte
	PlatformAuthPublicKey    *rsa.PublicKey
	// PlatformEncPublicKeyPEM / PlatformEncPublicKey 是平台加密公钥, 用于加密请求。
	// 只在调用加密端点时必需。
	PlatformEncPublicKeyPEM []byte
	PlatformEncPublicKey    *rsa.PublicKey
	// MerchantEncPrivateKeyPEM / MerchantEncPrivateKey 是商户加密私钥,
	// 用于敏感响应解密与 Webhook 解密。
	MerchantEncPrivateKeyPEM []byte
	MerchantEncPrivateKey    *rsa.PrivateKey

	// HTTPClient 用于实际发送请求, 默认 &http.Client{Timeout: 30s}。
	HTTPClient *http.Client
	// UserAgent 是附加的 User-Agent 头, 可留空。
	UserAgent string
	// DisableResponseSignatureVerification 关闭响应验签。默认强制验签,
	// 关闭后 SDK 无法保证响应未被篡改, 仅用于联调。
	DisableResponseSignatureVerification bool
	// RequireSignatureOnErrorResponses 要求非 2xx 响应也必须带签名。
	//
	// 默认 false, 对应 SDK 的统一缺签名头策略 (SPEC「SDK 约定 (非平台契约)」一节):
	// HTTP 2xx 缺签名头一律报验签失败; 非 2xx 缺签名头默认放行, 按类型化 API 错误返回,
	// 且 APIResponse.SignatureVerified 为 false。置为 true 后非 2xx 缺签名头也报验签失败。
	//
	// 平台契约并未穷举哪些状态码不带签名头, 因此 SDK 不做状态码白名单, 只按 2xx / 非 2xx 区分。
	RequireSignatureOnErrorResponses bool
	// MaxResponseBytes 是响应体读取上限, 默认 DefaultMaxResponseBytes。
	MaxResponseBytes int64
	// NonceFunc 生成 X-Nonce, 默认 NewNonce。
	NonceFunc func() (string, error)
	// NowFunc 返回当前时间, 默认 time.Now。
	NowFunc func() time.Time
	// StrictEncryptedRouteValidation 控制加密请求的 routeTemplate 校验强度。
	//
	// 默认 false (非严格): req.Path 不在 EncryptedRouteTemplates 已知加密端点表中时,
	// 不阻断请求, 只向 stderr 输出一次警告, 避免平台新增加密端点后 SDK 校验滞后
	// 卡死商户请求。置为 true 后, 未知 routeTemplate 会使 Prepare 返回
	// 满足 errors.Is(err, ErrUnknownEncryptedRoute) 的 error。该校验只影响
	// Request.Encrypt 为 true 的请求。
	StrictEncryptedRouteValidation bool
}

// Client 是商户 API 的通用 HTTP 客户端, 完成签名、发送、验签与错误解析。可并发使用。
type Client struct {
	protocolProfile        ProtocolProfile
	baseURL                *url.URL
	apiKey                 string
	apiVersion             string
	signer                 *Signer
	verifier               *ResponseVerifier
	platformEncPub         *rsa.PublicKey
	platformEncFingerprint string
	merchantEncPriv        *rsa.PrivateKey
	httpClient             *http.Client
	userAgent              string
	verifyResponse         bool
	requireErrorSignature  bool
	maxResponseBytes       int64
	nonceFunc              func() (string, error)
	nowFunc                func() time.Time
	strictEncryptedRoute   bool
}

// New 校验配置并构造 Client。
func New(cfg Config) (*Client, error) {
	if err := cfg.ProtocolProfile.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("%w: base url is required", ErrInvalidConfig)
	}
	base, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("%w: base url: %v", ErrInvalidConfig, err)
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("%w: api key is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.APIVersion) == "" {
		return nil, fmt.Errorf("%w: api version is required", ErrInvalidConfig)
	}
	authKey := cfg.MerchantAuthPrivateKey
	if authKey == nil {
		if len(cfg.MerchantAuthPrivateKeyPEM) == 0 {
			return nil, fmt.Errorf("%w: merchant_auth private key is required", ErrInvalidConfig)
		}
		authKey, err = ParseRSAPrivateKeyPEM(cfg.MerchantAuthPrivateKeyPEM)
		if err != nil {
			return nil, err
		}
	}
	c := &Client{
		protocolProfile:       cfg.ProtocolProfile,
		baseURL:               base,
		apiKey:                cfg.APIKey,
		apiVersion:            cfg.APIVersion,
		signer:                NewSignerWithKey(cfg.APIKey, authKey),
		httpClient:            cfg.HTTPClient,
		userAgent:             cfg.UserAgent,
		verifyResponse:        !cfg.DisableResponseSignatureVerification,
		requireErrorSignature: cfg.RequireSignatureOnErrorResponses,
		maxResponseBytes:      cfg.MaxResponseBytes,
		nonceFunc:             cfg.NonceFunc,
		nowFunc:               cfg.NowFunc,
		strictEncryptedRoute:  cfg.StrictEncryptedRouteValidation,
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if c.maxResponseBytes <= 0 {
		c.maxResponseBytes = DefaultMaxResponseBytes
	}
	if c.nonceFunc == nil {
		c.nonceFunc = NewNonce
	}
	if c.nowFunc == nil {
		c.nowFunc = time.Now
	}

	authPub := cfg.PlatformAuthPublicKey
	if authPub == nil && len(cfg.PlatformAuthPublicKeyPEM) > 0 {
		authPub, err = ParseRSAPublicKeyPEM(cfg.PlatformAuthPublicKeyPEM)
		if err != nil {
			return nil, err
		}
	}
	if authPub != nil {
		c.verifier = NewResponseVerifierWithKey(authPub)
	} else if c.verifyResponse {
		return nil, fmt.Errorf("%w: platform_auth public key is required unless response signature verification is disabled", ErrInvalidConfig)
	}

	encPub := cfg.PlatformEncPublicKey
	if encPub == nil && len(cfg.PlatformEncPublicKeyPEM) > 0 {
		encPub, err = ParseRSAPublicKeyPEM(cfg.PlatformEncPublicKeyPEM)
		if err != nil {
			return nil, err
		}
	}
	if encPub != nil {
		c.platformEncPub = encPub
		if c.platformEncFingerprint, err = KeyFingerprint(encPub); err != nil {
			return nil, err
		}
	}

	encPriv := cfg.MerchantEncPrivateKey
	if encPriv == nil && len(cfg.MerchantEncPrivateKeyPEM) > 0 {
		encPriv, err = ParseRSAPrivateKeyPEM(cfg.MerchantEncPrivateKeyPEM)
		if err != nil {
			return nil, err
		}
	}
	c.merchantEncPriv = encPriv
	return c, nil
}

// Signer 返回底层签名器。
func (c *Client) Signer() *Signer { return c.signer }

// PlatformEncryptionKeyID 返回平台加密公钥指纹, 即 X-Platform-Encryption-Key-Id 的值。
func (c *Client) PlatformEncryptionKeyID() string { return c.platformEncFingerprint }

// Request 描述一次业务调用。SDK 不建模业务端点: Path 与 body 由调用方给出。
type Request struct {
	// Method 是 HTTP 方法, 大写。
	Method string
	// Path 是外部路径, 以 / 开头, 不含 /api、/v1、/consumer 等前缀。
	Path string
	// Query 是查询参数; 与 RawQuery 二选一。SDK 按 RFC 3986 编码后再规范化。
	Query url.Values
	// RawQuery 是原始 query 串 (不含 '?'); 必须已按 RFC 3986 编码, 否则返回 ErrInvalidQuery。
	RawQuery string
	// Body 是已序列化的原始请求体字节; 与 JSONBody 二选一。
	Body []byte
	// JSONBody 非 nil 时由 SDK 序列化一次, 摘要与发送使用同一份字节。
	JSONBody any
	// ContentType 默认 application/json; 仅在 body 非空时发送。
	ContentType string
	// IdempotencyKey 非空时发送 X-Idempotency-Key 并参与签名。
	IdempotencyKey string
	// RequestID 对应 X-Request-Id; 加密请求必填, 留空时由 SDK 生成。
	RequestID string
	// Encrypt 为 true 时把 body 封装为混合加密信封后再签名发送。
	Encrypt bool
	// Header 是附加的自定义头; 协议头会被 SDK 覆盖。
	Header http.Header
}

// PreparedRequest 是签名完成、尚未发送的请求, 便于诊断与定制发送逻辑。
type PreparedRequest struct {
	// HTTPRequest 是可直接发送的 http.Request。
	HTTPRequest *http.Request
	// Signed 是签名产物, 含规范串与绑定摘要。
	Signed *SignedRequest
	// Body 是实际发送的字节 (加密端点为信封 JSON)。
	Body []byte
	// Envelope 在加密请求时非 nil。
	Envelope *Envelope
	// Binding 是响应验签所需的本地绑定信息。
	Binding ResponseBinding
	// RequestID 是本次请求的 X-Request-Id (可能为空)。
	RequestID string
}

// Prepare 组装并签名一次请求, 但不发送。
func (c *Client) Prepare(ctx context.Context, req Request) (*PreparedRequest, error) {
	if strings.TrimSpace(req.Method) == "" {
		return nil, fmt.Errorf("%w: method is required", ErrInvalidConfig)
	}
	method := strings.ToUpper(req.Method)
	if !strings.HasPrefix(req.Path, "/") {
		return nil, fmt.Errorf("%w: path must be an external path starting with '/'", ErrInvalidConfig)
	}
	if req.Body != nil && req.JSONBody != nil {
		return nil, fmt.Errorf("%w: set either Body or JSONBody, not both", ErrInvalidConfig)
	}
	if len(req.Query) > 0 && req.RawQuery != "" {
		return nil, fmt.Errorf("%w: set either Query or RawQuery, not both", ErrInvalidConfig)
	}

	body := req.Body
	if req.JSONBody != nil {
		encoded, err := json.Marshal(req.JSONBody)
		if err != nil {
			return nil, fmt.Errorf("plutus: marshal request body: %w", err)
		}
		body = encoded
	}

	rawQuery := req.RawQuery
	if len(req.Query) > 0 {
		rawQuery = EncodeQuery(req.Query)
	}

	timestamp := strconv.FormatInt(c.nowFunc().UnixMilli(), 10)
	nonce, err := c.nonceFunc()
	if err != nil {
		return nil, err
	}

	requestID := req.RequestID
	if c.protocolProfile == ProductV1 {
		ids := []string{}
		for name, values := range req.Header {
			if strings.EqualFold(name, HeaderRequestID) {
				ids = append(ids, values...)
			}
		}
		if len(ids) > 1 || len(ids) > 0 && requestID != "" {
			return nil, fmt.Errorf("%w: duplicate X-Request-Id", ErrInvalidConfig)
		}
		if len(ids) == 1 {
			requestID = ids[0]
		}
		requestID, err = productRequestID(requestID)
		if err != nil {
			return nil, err
		}
	}
	var envelope *Envelope
	if req.Encrypt {
		if c.platformEncPub == nil {
			return nil, fmt.Errorf("%w: platform_enc public key is required for encrypted endpoints", ErrInvalidConfig)
		}
		if !IsKnownEncryptedRoute(req.Path) {
			if c.strictEncryptedRoute {
				return nil, fmt.Errorf("%w: routeTemplate %q is not a known encrypted endpoint", ErrUnknownEncryptedRoute, req.Path)
			}
			fmt.Fprintf(os.Stderr, "plutus: warning: routeTemplate %q is not in the known encrypted endpoint table; proceeding because StrictEncryptedRouteValidation is false\n", req.Path)
		}
		if requestID == "" {
			generated, err := NewNonce()
			if err != nil {
				return nil, err
			}
			requestID = "req_" + generated
		}
		envelope, err = SealRequest(c.platformEncPub, requestID, req.Path, timestamp, body)
		if err != nil {
			return nil, err
		}
		if body, err = envelope.JSON(); err != nil {
			return nil, fmt.Errorf("plutus: marshal envelope: %w", err)
		}
	}

	signed, err := c.signer.Sign(CanonicalRequest{
		ProtocolProfile: c.protocolProfile,
		RequestID:       requestID,
		Method:          method,
		ExternalPath:    req.Path,
		RawQuery:        rawQuery,
		Timestamp:       timestamp,
		Nonce:           nonce,
		APIVersion:      c.apiVersion,
		IdempotencyKey:  req.IdempotencyKey,
		Body:            body,
	})
	if err != nil {
		return nil, err
	}

	target := *c.baseURL
	target.Path = strings.TrimRight(c.baseURL.Path, "/") + req.Path
	// 本 SDK 总是发送规范化后的 query (排序 + RFC 3986 编码), 不可配置。
	// 平台对收到的原始 query 重新执行同一规范化算法, 因此原样与规范化两种形态等价。
	target.RawQuery = signed.CanonicalQuery

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		httpReq.ContentLength = int64(len(body))
	}
	for name, values := range req.Header {
		if c.protocolProfile == ProductV1 && strings.EqualFold(name, HeaderRequestID) {
			continue
		}
		for _, value := range values {
			httpReq.Header.Add(name, value)
		}
	}
	for name, value := range signed.Headers {
		if name == HeaderAPIVersion {
			// 保持线格式上的全大写形式, 绕过 Go 的头名规范化。
			httpReq.Header[HeaderAPIVersion] = []string{value}
			continue
		}
		httpReq.Header.Set(name, value)
	}
	if len(body) > 0 {
		contentType := req.ContentType
		if contentType == "" {
			contentType = "application/json"
		}
		httpReq.Header.Set("Content-Type", contentType)
	}
	if requestID != "" {
		httpReq.Header.Set(HeaderRequestID, requestID)
	}
	if req.Encrypt {
		httpReq.Header.Set(HeaderPlatformEncryptionKeyID, c.platformEncFingerprint)
	}
	if c.userAgent != "" {
		httpReq.Header.Set("User-Agent", c.userAgent)
	}

	return &PreparedRequest{
		HTTPRequest: httpReq,
		Signed:      signed,
		Body:        body,
		Envelope:    envelope,
		RequestID:   requestID,
		Binding: ResponseBinding{
			ProtocolProfile:        c.protocolProfile,
			SentRequestID:          requestID,
			RequestCanonicalSHA256: signed.CanonicalDigestHex,
			APIVersion:             c.apiVersion,
			ExternalPath:           req.Path,
		},
	}, nil
}

// Do 签名并发送一次请求, 校验响应签名并解析统一响应包络 (SPEC「统一响应包络」一节)。
//
// 成功判定见 APIResponse.IsSuccess: 以包络的 success 布尔字段为权威, 缺失时回退 HTTP 2xx。
// 判定为失败时返回 *APIError (同时返回已解析的 APIResponse 便于取原始 body),
// 因此 HTTP 200 且 success 为 false 也会返回 *APIError。
//
// 验签失败返回 ErrResponseSignatureInvalid 且不返回响应体。缺签名头的处理见
// Config.RequireSignatureOnErrorResponses。
func (c *Client) Do(ctx context.Context, req Request) (*APIResponse, error) {
	prepared, err := c.Prepare(ctx, req)
	if err != nil {
		return nil, err
	}
	httpResp, err := c.httpClient.Do(prepared.HTTPRequest)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("plutus: read response body: %w", err)
	}
	if int64(len(body)) > c.maxResponseBytes {
		return nil, fmt.Errorf("plutus: response body exceeds %d bytes", c.maxResponseBytes)
	}

	verified := false
	if c.verifyResponse {
		err := c.verifier.Verify(prepared.Binding, httpResp.StatusCode, httpResp.Header, body)
		switch {
		case err == nil:
			verified = true
		case errors.Is(err, ErrResponseSignatureMissing) &&
			!c.requireErrorSignature &&
			(httpResp.StatusCode < 200 || httpResp.StatusCode >= 300):
			// 非 2xx 且缺签名头: 默认放行, 按类型化 API 错误返回, SignatureVerified 保持 false。
			// 2xx 缺签名头一律走 default 分支报错。
		default:
			return nil, err
		}
	}

	resp := ParseAPIResponse(httpResp.StatusCode, httpResp.Header, body)
	resp.SignatureVerified = verified
	if apiErr := resp.AsError(); apiErr != nil {
		return resp, apiErr
	}
	return resp, nil
}

// DoJSON 发送请求并把统一响应包络的 data 字段解码到 out; out 为 nil 时只做发送与验签。
func (c *Client) DoJSON(ctx context.Context, req Request, out any) (*APIResponse, error) {
	resp, err := c.Do(ctx, req)
	if err != nil {
		return resp, err
	}
	if out != nil {
		if err := resp.DecodeData(out); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

// DecryptSensitiveEnvelope 用 merchant_enc 私钥解密敏感响应信封。
// requestID 通常取响应头 X-Request-Id; 无关联上下文时传空串。
func (c *Client) DecryptSensitiveEnvelope(env *Envelope, requestID string) ([]byte, error) {
	if c.merchantEncPriv == nil {
		return nil, fmt.Errorf("%w: merchant_enc private key is required to decrypt sensitive responses", ErrInvalidConfig)
	}
	return OpenSensitiveResponse(c.merchantEncPriv, env, requestID)
}

// WebhookReceiver 用 Client 已配置的 platform_auth 公钥与 merchant_enc 私钥构造 Webhook 接收器。
// tolerance 为时间戳容差, 传 0 表示不校验。
func (c *Client) WebhookReceiver(tolerance time.Duration) (*WebhookReceiver, error) {
	if c.verifier == nil {
		return nil, fmt.Errorf("%w: platform_auth public key is required for webhook verification", ErrInvalidConfig)
	}
	return NewWebhookReceiver(WebhookConfig{
		APIKey:                c.apiKey,
		PlatformAuthPublicKey: c.verifier.PublicKey(),
		MerchantEncPrivateKey: c.merchantEncPriv,
		TimestampTolerance:    tolerance,
		Now:                   c.nowFunc,
	})
}

// EncodeQuery 把参数按 RFC 3986 编码为 query 串 (unreserved 字符不编码, 空格为 %20)。
// 输出已按 (key, value) 字节序排序, 与规范化结果一致。
//
// 不要用 url.Values.Encode: 它把空格编成 '+', 会被规范化算法拒绝。
func EncodeQuery(values url.Values) string {
	pairs := make([][2]string, 0, len(values))
	for key, list := range values {
		for _, value := range list {
			pairs = append(pairs, [2]string{percentEncode([]byte(key)), percentEncode([]byte(value))})
		}
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	var b strings.Builder
	for i, pair := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(pair[0])
		b.WriteByte('=')
		b.WriteString(pair[1])
	}
	return b.String()
}
