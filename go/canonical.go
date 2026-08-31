package plutus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// EmptyBodySHA256Hex 是空 body 的 SHA-256 小写十六进制摘要。
const EmptyBodySHA256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// ResponseCanonicalPrefix 是响应规范串的固定首行。
const ResponseCanonicalPrefix = "SLAUNCHX-API-RESPONSE-V1"

// isUnreserved 判定字节是否为 RFC 3986 unreserved 字符 (A-Z a-z 0-9 - . _ ~)。
func isUnreserved(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '-' || b == '.' || b == '_' || b == '~':
		return true
	}
	return false
}

func hexDigit(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	}
	return -1
}

// percentDecodeStrict 严格解码: 只接受 unreserved 字面量与合法 %XX, 结果必须是合法 UTF-8。
func percentDecodeStrict(component string) ([]byte, error) {
	out := make([]byte, 0, len(component))
	for i := 0; i < len(component); {
		c := component[i]
		if c == '%' {
			if i+2 >= len(component) {
				return nil, &QueryError{Component: component, Reason: "incomplete percent encoding"}
			}
			hi, lo := hexDigit(component[i+1]), hexDigit(component[i+2])
			if hi < 0 || lo < 0 {
				return nil, &QueryError{Component: component, Reason: "invalid percent encoding"}
			}
			out = append(out, byte(hi*16+lo))
			i += 3
			continue
		}
		if c > 0x7F || !isUnreserved(c) {
			return nil, &QueryError{Component: component, Reason: "reserved or non-ASCII character must be percent-encoded"}
		}
		out = append(out, c)
		i++
	}
	if !utf8.Valid(out) {
		return nil, &QueryError{Component: component, Reason: "percent-decoded bytes are not valid UTF-8"}
	}
	return out, nil
}

// percentEncode 按 RFC 3986 重新编码, 非 unreserved 字节输出大写两位十六进制。
func percentEncode(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))
	const upperHex = "0123456789ABCDEF"
	for _, c := range raw {
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&0x0F])
	}
	return b.String()
}

// CanonicalizeComponent 对单个 query 分量执行「严格解码 → RFC 3986 重编码」。
func CanonicalizeComponent(component string) (string, error) {
	raw, err := percentDecodeStrict(component)
	if err != nil {
		return "", err
	}
	return percentEncode(raw), nil
}

// CanonicalizeQuery 按 SPEC 4.2 规范化 query 串, 用于请求规范串第 3 行。
//
// 算法为「严格解码 → RFC 3986 重编码 → 按 (key, value) 字节序排序 → 用 & 重组」。
// 空串或全空白返回空串。裸保留字符 (含 '+')、非法或截断的 %XX、非 ASCII 字符、
// 解码后非法 UTF-8 一律返回错误 (errors.Is(err, ErrInvalidQuery) 成立), 不做任何回退。
func CanonicalizeQuery(rawQuery string) (string, error) {
	if strings.TrimSpace(rawQuery) == "" {
		return "", nil
	}
	segments := strings.Split(rawQuery, "&")
	pairs := make([][2]string, 0, len(segments))
	for _, segment := range segments {
		var rawKey, rawValue string
		if i := strings.IndexByte(segment, '='); i >= 0 {
			rawKey, rawValue = segment[:i], segment[i+1:]
		} else {
			rawKey, rawValue = segment, ""
		}
		key, err := CanonicalizeComponent(rawKey)
		if err != nil {
			return "", err
		}
		value, err := CanonicalizeComponent(rawValue)
		if err != nil {
			return "", err
		}
		pairs = append(pairs, [2]string{key, value})
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
	return b.String(), nil
}

// SHA256Hex 返回字节序列的 SHA-256 小写十六进制摘要。
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ForcesEmptyBodyDigest 判定该方法是否强制使用空 body 摘要 (GET / HEAD / DELETE)。
func ForcesEmptyBodyDigest(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "DELETE":
		return true
	}
	return false
}

// BodyDigestHex 计算请求规范串第 8 行的 body 摘要。
//
// GET / HEAD / DELETE 无条件使用空 body 摘要, 即使实际携带了 body;
// 其余方法对给定的原始字节计算摘要, 不做任何规整。
func BodyDigestHex(method string, body []byte) string {
	if ForcesEmptyBodyDigest(method) || len(body) == 0 {
		return EmptyBodySHA256Hex
	}
	return SHA256Hex(body)
}

// CanonicalRequest 是构造请求规范串所需的全部输入。
type CanonicalRequest struct {
	// Method 是 HTTP 方法, 大写。
	Method string
	// ExternalPath 是外部路径, 以 / 开头, 不含 query, 不含链/版本/门户前缀。
	ExternalPath string
	// RawQuery 是原始 query 串 (不含 '?'), 由 SDK 规范化后进入规范串第 3 行。
	RawQuery string
	// Timestamp 是 X-Timestamp 原值, Unix 毫秒十进制字符串。
	Timestamp string
	// Nonce 是 X-Nonce 原值。
	Nonce string
	// APIVersion 是 X-API-VERSION 原值, 不可为空。
	APIVersion string
	// IdempotencyKey 是 X-Idempotency-Key 原值; 不发送该头时留空。
	IdempotencyKey string
	// Body 是实际发送的原始字节 (加密端点为信封 JSON 字节)。
	Body []byte
}

// CanonicalString 返回 8 行请求规范串, 以 LF 连接, 无尾换行。
func (r CanonicalRequest) CanonicalString() (string, error) {
	if strings.TrimSpace(r.Method) == "" {
		return "", fmt.Errorf("%w: method is required", ErrInvalidConfig)
	}
	if !strings.HasPrefix(r.ExternalPath, "/") {
		return "", fmt.Errorf("%w: external path must start with '/'", ErrInvalidConfig)
	}
	if strings.TrimSpace(r.APIVersion) == "" {
		return "", fmt.Errorf("%w: api version is required", ErrInvalidConfig)
	}
	canonicalQuery, err := CanonicalizeQuery(r.RawQuery)
	if err != nil {
		return "", err
	}
	lines := []string{
		r.Method,
		r.ExternalPath,
		canonicalQuery,
		r.Timestamp,
		r.Nonce,
		r.APIVersion,
		r.IdempotencyKey,
		BodyDigestHex(r.Method, r.Body),
	}
	return strings.Join(lines, "\n"), nil
}

// CanonicalResponse 是构造响应规范串所需的全部输入。
type CanonicalResponse struct {
	// RequestCanonicalSHA256 是本次请求规范串的 SHA-256 小写 hex, 必须本地计算,
	// 绝不能从响应头读取。
	RequestCanonicalSHA256 string
	// APIVersion 是本次请求的 X-API-VERSION。
	APIVersion string
	// ExternalPath 是本次请求的外部路径。
	ExternalPath string
	// OperationID 取自响应头 X-Operation-Id; 无则空串。
	OperationID string
	// RequestID 取自响应头 X-Request-Id; 无则空串。
	RequestID string
	// HTTPStatus 是响应状态码。
	HTTPStatus int
	// ContentType 是响应头 Content-Type 原值, 含 charset 参数, 不做归一化。
	ContentType string
	// ResponseTimestamp 是响应头 X-Response-Timestamp 原值。
	ResponseTimestamp string
	// Body 是原始响应体字节。
	Body []byte
}

// CanonicalString 返回 10 行响应规范串, 以 LF 连接, 无尾换行。
func (r CanonicalResponse) CanonicalString() string {
	lines := []string{
		ResponseCanonicalPrefix,
		r.RequestCanonicalSHA256,
		r.APIVersion,
		r.ExternalPath,
		r.OperationID,
		r.RequestID,
		strconv.Itoa(r.HTTPStatus),
		r.ContentType,
		r.ResponseTimestamp,
		SHA256Hex(r.Body),
	}
	return strings.Join(lines, "\n")
}

// WebhookCanonicalString 返回 Webhook 签名规范串 (4 行, LF 连接, 无尾换行)。
// bodyDigestBase64 是原始 body 的 SHA-256 的 Base64 编码, 不是 hex。
func WebhookCanonicalString(deliveryID, eventType, timestamp, bodyDigestBase64 string) string {
	return strings.Join([]string{deliveryID, eventType, timestamp, bodyDigestBase64}, "\n")
}
