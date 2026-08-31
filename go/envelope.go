package plutus

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// 混合信封的固定参数 (SPEC 7.1)。
const (
	// AESKeySize 是一次性 AES 密钥长度 (字节)。
	AESKeySize = 32
	// GCMNonceSize 是 GCM IV 长度 (字节), 前置在密文之前。
	GCMNonceSize = 12
	// GCMTagSize 是 GCM 认证标签长度 (字节), 附在密文之后。
	GCMTagSize = 16
	// MaxPlaintextBytes 是解密后明文的大小上限 (1 MiB)。
	MaxPlaintextBytes = 1 << 20
	// WebhookRouteTemplate 是 Webhook 信封 AAD 第二分量的字面量。
	WebhookRouteTemplate = "webhook"
)

// AAD 是混合信封的附加认证数据四元组。
//
// 三条链的取值不同 (SPEC 第 11 节):
//
//	加密请求:   requestId=X-Request-Id, routeTemplate=端点外部路径, timestamp=X-Timestamp, keyId=平台加密公钥指纹
//	敏感响应:   requestId=请求关联 ID (可为空), routeTemplate="",   timestamp=平台毫秒时间戳, keyId=商户加密公钥指纹
//	Webhook:    requestId=投递 ID,      routeTemplate="webhook",    timestamp=投递毫秒时间戳, keyId=API Key 业务 ID
type AAD struct {
	RequestID     string
	RouteTemplate string
	Timestamp     string
	KeyID         string
}

// String 返回 "requestId|routeTemplate|timestamp|keyId"; 任一分量为空时保留分隔符。
func (a AAD) String() string {
	return strings.Join([]string{a.RequestID, a.RouteTemplate, a.Timestamp, a.KeyID}, "|")
}

// Bytes 返回 AAD 的 UTF-8 字节。
func (a AAD) Bytes() []byte { return []byte(a.String()) }

// Base64 返回 AAD 字节的标准 Base64 编码, 对应信封的 aad 字段。
func (a AAD) Base64() string { return base64.StdEncoding.EncodeToString(a.Bytes()) }

// ParseAAD 把 "requestId|routeTemplate|timestamp|keyId" 解析回四元组。
func ParseAAD(s string) (AAD, error) {
	parts := strings.Split(s, "|")
	if len(parts) != 4 {
		return AAD{}, fmt.Errorf("%w: aad must have 4 components, got %d", ErrEnvelopeInvalid, len(parts))
	}
	return AAD{RequestID: parts[0], RouteTemplate: parts[1], Timestamp: parts[2], KeyID: parts[3]}, nil
}

// Envelope 是混合加密信封。
//
// API 链 (加密请求 / 敏感响应) 不含 EnvelopeVersion 而含 EncryptedPayload (值恒等于 Ciphertext);
// Webhook 信封含 EnvelopeVersion=1 且不含 EncryptedPayload。解密一律读 Ciphertext。
type Envelope struct {
	// EnvelopeVersion 仅出现在 Webhook 信封, 恒为 1。
	EnvelopeVersion *int `json:"envelopeVersion,omitempty"`
	// Algorithm 恒为 RSA-OAEP-AES-256-GCM。
	Algorithm string `json:"algorithm"`
	// KeyFingerprint 是接收方公钥指纹, 形如 SHA256:<小写 hex>。
	KeyFingerprint string `json:"keyFingerprint"`
	// EncryptedKey 是 RSA-OAEP-SHA256 包装的一次性 AES 密钥 (Base64)。
	EncryptedKey string `json:"encryptedKey"`
	// Ciphertext 是 Base64(IV || 密文 || 标签)。
	Ciphertext string `json:"ciphertext"`
	// AAD 是 AAD 字节的 Base64 回显; 只用于比对, 绝不可直接当作权威值解密。
	AAD string `json:"aad"`
	// EncryptedPayload 是 API 链的历史兼容字段, 值等于 Ciphertext。
	EncryptedPayload string `json:"encryptedPayload,omitempty"`
}

// ParseEnvelopeJSON 解析 API 链信封 JSON (允许 encryptedPayload 字段)。
func ParseEnvelopeJSON(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnvelopeInvalid, err)
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	return &env, nil
}

// JSON 返回信封的紧凑 JSON 字节, 可直接作为 HTTP body 发送。
func (e *Envelope) JSON() ([]byte, error) {
	return json.Marshal(e)
}

// Validate 校验信封的必填字段与算法标识。
func (e *Envelope) Validate() error {
	if e.Algorithm != EnvelopeAlgorithm {
		return fmt.Errorf("%w: algorithm must be %q, got %q", ErrEnvelopeInvalid, EnvelopeAlgorithm, e.Algorithm)
	}
	if e.EncryptedKey == "" {
		return fmt.Errorf("%w: encryptedKey is missing", ErrEnvelopeInvalid)
	}
	if e.Ciphertext == "" {
		return fmt.Errorf("%w: ciphertext is missing", ErrEnvelopeInvalid)
	}
	if e.AAD == "" {
		return fmt.Errorf("%w: aad is missing", ErrEnvelopeInvalid)
	}
	return nil
}

// DecodedAAD 解析信封回显的 aad 字段。返回值只可用于取得本地无法获知的分量
// (敏感响应的 timestamp), 其余分量必须用本地值重建后比对。
func (e *Envelope) DecodedAAD() (AAD, error) {
	raw, err := base64.StdEncoding.DecodeString(e.AAD)
	if err != nil {
		return AAD{}, fmt.Errorf("%w: aad is not valid base64: %v", ErrEnvelopeInvalid, err)
	}
	return ParseAAD(string(raw))
}

// VerifyFingerprint 比对信封 keyFingerprint 与本地期望的接收方公钥指纹。
func (e *Envelope) VerifyFingerprint(expected string) error {
	if expected == "" || e.KeyFingerprint == expected {
		return nil
	}
	return fmt.Errorf("%w: envelope keyFingerprint %q, expected %q", ErrKeyFingerprintMismatch, e.KeyFingerprint, expected)
}

// Seal 用接收方公钥生成混合信封 (RSA-OAEP-SHA256 + AES-256-GCM)。
// keyFingerprint 为接收方公钥指纹; 传空串时由 pub 计算。
func Seal(pub *rsa.PublicKey, keyFingerprint string, aad AAD, plaintext []byte) (*Envelope, error) {
	if pub == nil {
		return nil, fmt.Errorf("%w: recipient public key is required", ErrInvalidConfig)
	}
	if len(plaintext) > MaxPlaintextBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrPlaintextTooLarge, len(plaintext))
	}
	if keyFingerprint == "" {
		fp, err := KeyFingerprint(pub)
		if err != nil {
			return nil, err
		}
		keyFingerprint = fp
	}
	key := make([]byte, AESKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("plutus: generate aes key: %w", err)
	}
	iv := make([]byte, GCMNonceSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("plutus: generate iv: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("plutus: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithTagSize(block, GCMTagSize)
	if err != nil {
		return nil, fmt.Errorf("plutus: aes-gcm: %w", err)
	}
	aadBytes := aad.Bytes()
	blob := gcm.Seal(append([]byte(nil), iv...), iv, plaintext, aadBytes)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, nil)
	if err != nil {
		return nil, fmt.Errorf("plutus: rsa-oaep wrap: %w", err)
	}
	ciphertext := base64.StdEncoding.EncodeToString(blob)
	return &Envelope{
		Algorithm:        EnvelopeAlgorithm,
		KeyFingerprint:   keyFingerprint,
		EncryptedKey:     base64.StdEncoding.EncodeToString(encryptedKey),
		Ciphertext:       ciphertext,
		AAD:              base64.StdEncoding.EncodeToString(aadBytes),
		EncryptedPayload: ciphertext,
	}, nil
}

// Open 用接收方私钥解开信封。
//
// 流程: 校验结构 → 用本地重建的 aad 与信封回显值做常量时间比对 → RSA-OAEP 解出 AES 密钥
// → 用重建的 AAD 做 GCM 解密 → 校验明文大小上限。
func Open(priv *rsa.PrivateKey, env *Envelope, aad AAD) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("%w: decryption private key is required", ErrInvalidConfig)
	}
	if env == nil {
		return nil, fmt.Errorf("%w: envelope is nil", ErrEnvelopeInvalid)
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	echoed, err := base64.StdEncoding.DecodeString(env.AAD)
	if err != nil {
		return nil, fmt.Errorf("%w: aad is not valid base64: %v", ErrEnvelopeInvalid, err)
	}
	aadBytes := aad.Bytes()
	if subtle.ConstantTimeCompare(echoed, aadBytes) != 1 {
		return nil, ErrAADMismatch
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(env.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: encryptedKey is not valid base64: %v", ErrEnvelopeInvalid, err)
	}
	blob, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: ciphertext is not valid base64: %v", ErrEnvelopeInvalid, err)
	}
	if len(blob) < GCMNonceSize+GCMTagSize {
		return nil, fmt.Errorf("%w: ciphertext is shorter than iv+tag", ErrEnvelopeInvalid)
	}
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: rsa-oaep unwrap failed", ErrDecryptFailed)
	}
	if len(key) != AESKeySize {
		return nil, fmt.Errorf("%w: unwrapped aes key must be %d bytes, got %d", ErrEnvelopeInvalid, AESKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("plutus: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithTagSize(block, GCMTagSize)
	if err != nil {
		return nil, fmt.Errorf("plutus: aes-gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, blob[:GCMNonceSize], blob[GCMNonceSize:], aadBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: gcm authentication failed", ErrDecryptFailed)
	}
	if len(plaintext) > MaxPlaintextBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrPlaintextTooLarge, len(plaintext))
	}
	return plaintext, nil
}

// SealRequest 为加密端点生成请求信封。
//
// routeTemplate 是该端点的外部路径, timestamp 必须与签名使用的 X-Timestamp 同值,
// requestID 必须与 X-Request-Id 同值且非空。返回信封的 JSON 字节即为实际 HTTP body。
func SealRequest(platformEncPub *rsa.PublicKey, requestID, routeTemplate, timestamp string, plaintext []byte) (*Envelope, error) {
	if requestID == "" {
		return nil, fmt.Errorf("%w: request id is required for encrypted requests", ErrInvalidConfig)
	}
	if routeTemplate == "" {
		return nil, fmt.Errorf("%w: route template is required for encrypted requests", ErrInvalidConfig)
	}
	if err := ValidateTimestamp(timestamp); err != nil {
		return nil, err
	}
	fingerprint, err := KeyFingerprint(platformEncPub)
	if err != nil {
		return nil, err
	}
	aad := AAD{RequestID: requestID, RouteTemplate: routeTemplate, Timestamp: timestamp, KeyID: fingerprint}
	return Seal(platformEncPub, fingerprint, aad, plaintext)
}

// OpenSensitiveResponse 解密敏感响应信封。
//
// AAD 的 routeTemplate 固定为空串, keyId 为商户 merchant_enc 公钥指纹,
// timestamp 本地无从获知, 因此从信封回显的 aad 中解析出来后重建整条 AAD 并做常量时间比对。
// requestID 为本次请求的关联 ID, 无关联上下文时传空串。
func OpenSensitiveResponse(merchantEncPriv *rsa.PrivateKey, env *Envelope, requestID string) ([]byte, error) {
	if merchantEncPriv == nil {
		return nil, fmt.Errorf("%w: merchant_enc private key is required", ErrInvalidConfig)
	}
	if env == nil {
		return nil, fmt.Errorf("%w: envelope is nil", ErrEnvelopeInvalid)
	}
	fingerprint, err := KeyFingerprint(&merchantEncPriv.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := env.VerifyFingerprint(fingerprint); err != nil {
		return nil, err
	}
	echoed, err := env.DecodedAAD()
	if err != nil {
		return nil, err
	}
	aad := AAD{RequestID: requestID, RouteTemplate: "", Timestamp: echoed.Timestamp, KeyID: fingerprint}
	return Open(merchantEncPriv, env, aad)
}
