package plutus

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// RSA 密钥的协议约束。
const (
	// MinRSAModulusBits 是允许的最小 RSA 模数位长。
	MinRSAModulusBits = 2048
	// MaxRSAModulusBits 是允许的最大 RSA 模数位长。
	MaxRSAModulusBits = 4096
	// RequiredPublicExponent 是协议强制的 RSA 公开指数。
	RequiredPublicExponent = 65537
)

// ParseRSAPublicKeyPEM 解析 SPKI (BEGIN PUBLIC KEY) 格式的 RSA 公钥, 并校验协议约束:
// 模数 2048–4096 位、公开指数恰为 65537、DER 为规范编码。PKCS#1 (BEGIN RSA PUBLIC KEY) 被拒绝。
func ParseRSAPublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrInvalidKey)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%w: expected SPKI PEM block %q, got %q", ErrInvalidKey, "PUBLIC KEY", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an RSA public key", ErrInvalidKey)
	}
	reencoded, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if !bytes.Equal(reencoded, block.Bytes) {
		return nil, fmt.Errorf("%w: non-canonical SPKI DER encoding", ErrInvalidKey)
	}
	if err := ValidateRSAPublicKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// ParseRSAPrivateKeyPEM 解析 PKCS#8 (BEGIN PRIVATE KEY) 格式的 RSA 私钥;
// 为兼容旧工具链也接受 PKCS#1 (BEGIN RSA PRIVATE KEY)。
func ParseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrInvalidKey)
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: not an RSA private key", ErrInvalidKey)
		}
		key = rsaKey
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		key = parsed
	default:
		return nil, fmt.Errorf("%w: unsupported private key PEM block %q", ErrInvalidKey, block.Type)
	}
	if err := ValidateRSAPublicKey(&key.PublicKey); err != nil {
		return nil, err
	}
	return key, nil
}

// LoadRSAPrivateKeyFile 从文件读取并解析 RSA 私钥。
func LoadRSAPrivateKeyFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRSAPrivateKeyPEM(data)
}

// LoadRSAPublicKeyFile 从文件读取并解析 RSA 公钥。
func LoadRSAPublicKeyFile(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRSAPublicKeyPEM(data)
}

// ValidateRSAPublicKey 校验模数位长与公开指数是否满足协议约束。
func ValidateRSAPublicKey(pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil {
		return fmt.Errorf("%w: nil public key", ErrInvalidKey)
	}
	bits := pub.N.BitLen()
	if bits < MinRSAModulusBits || bits > MaxRSAModulusBits {
		return fmt.Errorf("%w: modulus must be %d..%d bits, got %d", ErrInvalidKey, MinRSAModulusBits, MaxRSAModulusBits, bits)
	}
	if pub.E != RequiredPublicExponent {
		return fmt.Errorf("%w: public exponent must be %d, got %d", ErrInvalidKey, RequiredPublicExponent, pub.E)
	}
	return nil
}

// KeyFingerprint 返回公钥指纹, 格式为 "SHA256:" + SHA-256(SPKI DER) 的小写十六进制。
// 用于 X-Platform-Encryption-Key-Id、X-Platform-Signing-Key-Id 与信封 keyFingerprint。
func KeyFingerprint(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + hex.EncodeToString(sum[:]), nil
}
