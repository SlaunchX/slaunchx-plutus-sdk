package plutus

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// NonceMinLength 与 NonceMaxLength 是 X-Nonce 的长度约束。
const (
	NonceMinLength = 16
	NonceMaxLength = 128
)

// NewNonce 生成 32 字符十六进制随机 nonce, 满足 ^[A-Za-z0-9._~-]{16,128}$。
func NewNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("plutus: generate nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// ValidateNonce 校验 nonce 是否满足 ^[A-Za-z0-9._~-]{16,128}$。
// Base64 输出含 '+' '/' '=' , 不合法; 带连字符的 UUID 合法。
func ValidateNonce(nonce string) error {
	if len(nonce) < NonceMinLength || len(nonce) > NonceMaxLength {
		return fmt.Errorf("%w: length must be %d..%d, got %d", ErrInvalidNonce, NonceMinLength, NonceMaxLength, len(nonce))
	}
	for i := 0; i < len(nonce); i++ {
		if !isUnreserved(nonce[i]) {
			return fmt.Errorf("%w: character %q is not allowed", ErrInvalidNonce, nonce[i])
		}
	}
	return nil
}

// ValidateTimestamp 校验时间戳是否为非空的十进制数字串, 且为毫秒量级 (至少 13 位)。
func ValidateTimestamp(timestamp string) error {
	if timestamp == "" {
		return fmt.Errorf("%w: timestamp is required", ErrInvalidTimestamp)
	}
	for i := 0; i < len(timestamp); i++ {
		if timestamp[i] < '0' || timestamp[i] > '9' {
			return fmt.Errorf("%w: must be a decimal Unix millisecond string", ErrInvalidTimestamp)
		}
	}
	if len(timestamp) < 13 {
		return fmt.Errorf("%w: must be milliseconds, not seconds", ErrInvalidTimestamp)
	}
	return nil
}

// Signer 用 merchant_auth 私钥对请求规范串签名。可并发使用。
type Signer struct {
	apiKey     string
	privateKey *rsa.PrivateKey
}

// NewSigner 用 API Key 业务 ID 与 merchant_auth 私钥 PEM 构造签名器。
func NewSigner(apiKey string, merchantAuthPrivateKeyPEM []byte) (*Signer, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("%w: api key is required", ErrInvalidConfig)
	}
	key, err := ParseRSAPrivateKeyPEM(merchantAuthPrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	return NewSignerWithKey(apiKey, key), nil
}

// NewSignerWithKey 用已解析的私钥构造签名器。
func NewSignerWithKey(apiKey string, key *rsa.PrivateKey) *Signer {
	return &Signer{apiKey: apiKey, privateKey: key}
}

// APIKey 返回签名器绑定的 API Key 业务 ID。
func (s *Signer) APIKey() string { return s.apiKey }

// PublicKey 返回 merchant_auth 公钥, 便于计算指纹或自检。
func (s *Signer) PublicKey() *rsa.PublicKey { return &s.privateKey.PublicKey }

// SignedRequest 是一次签名的产物。
type SignedRequest struct {
	// CanonicalString 是 8 行请求规范串。
	CanonicalString string
	// CanonicalDigestHex 是规范串自身的 SHA-256 小写 hex, 用于响应验签绑定 (规范串第 2 行)。
	CanonicalDigestHex string
	// BodyDigestHex 是规范串第 8 行的 body 摘要。
	BodyDigestHex string
	// CanonicalQuery 是规范化后的 query 串; 可直接作为实际发送的 query。
	CanonicalQuery string
	// Signature 是 Base64 编码的 X-Signature 值。
	Signature string
	// Headers 是本次请求应携带的协议头 (不含 Content-Type 与加密端点专属头)。
	Headers map[string]string
}

// Sign 计算请求规范串并签名。调用方必须保证 req.Body 与实际发送的字节完全一致。
func (s *Signer) Sign(req CanonicalRequest) (*SignedRequest, error) {
	if err := ValidateTimestamp(req.Timestamp); err != nil {
		return nil, err
	}
	if err := ValidateNonce(req.Nonce); err != nil {
		return nil, err
	}
	canonical, err := req.CanonicalString()
	if err != nil {
		return nil, err
	}
	signature, err := SignCanonicalString(s.privateKey, canonical)
	if err != nil {
		return nil, err
	}
	canonicalQuery, err := CanonicalizeQuery(req.RawQuery)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		HeaderAPIKey:             s.apiKey,
		HeaderAPIVersion:         req.APIVersion,
		HeaderTimestamp:          req.Timestamp,
		HeaderNonce:              req.Nonce,
		HeaderSignature:          signature,
		HeaderSignatureAlgorithm: SignatureAlgorithm,
	}
	if req.IdempotencyKey != "" {
		headers[HeaderIdempotencyKey] = req.IdempotencyKey
	}
	return &SignedRequest{
		CanonicalString:    canonical,
		CanonicalDigestHex: SHA256Hex([]byte(canonical)),
		BodyDigestHex:      BodyDigestHex(req.Method, req.Body),
		CanonicalQuery:     canonicalQuery,
		Signature:          signature,
		Headers:            headers,
	}, nil
}

// SignCanonicalString 用 RSASSA-PKCS1-v1_5 + SHA-256 对规范串签名, 返回标准 Base64。
func SignCanonicalString(key *rsa.PrivateKey, canonical string) (string, error) {
	digest := sha256.Sum256([]byte(canonical))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("plutus: sign canonical string: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyCanonicalString 用 RSASSA-PKCS1-v1_5 + SHA-256 验证 Base64 签名。
func VerifyCanonicalString(pub *rsa.PublicKey, canonical, signatureBase64 string) error {
	sig, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("plutus: decode signature: %w", err)
	}
	digest := sha256.Sum256([]byte(canonical))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}
