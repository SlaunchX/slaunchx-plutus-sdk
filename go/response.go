package plutus

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ResponseVerifier 用 platform_auth 公钥校验响应签名。可并发使用。
type ResponseVerifier struct {
	publicKey *rsa.PublicKey
}

// NewResponseVerifier 用 platform_auth 公钥 PEM 构造验签器。
func NewResponseVerifier(platformAuthPublicKeyPEM []byte) (*ResponseVerifier, error) {
	pub, err := ParseRSAPublicKeyPEM(platformAuthPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return &ResponseVerifier{publicKey: pub}, nil
}

// NewResponseVerifierWithKey 用已解析的公钥构造验签器。
func NewResponseVerifierWithKey(pub *rsa.PublicKey) *ResponseVerifier {
	return &ResponseVerifier{publicKey: pub}
}

// PublicKey 返回验签使用的 platform_auth 公钥。
func (v *ResponseVerifier) PublicKey() *rsa.PublicKey { return v.publicKey }

// ResponseBinding 是响应验签的本地绑定信息, 全部来自 SDK 自己发出的请求。
type ResponseBinding struct {
	ProtocolProfile ProtocolProfile
	SentRequestID   string
	// RequestCanonicalSHA256 是请求规范串的 SHA-256 小写 hex, 必须本地计算。
	RequestCanonicalSHA256 string
	// APIVersion 是本次请求的 X-API-VERSION。
	APIVersion string
	// ExternalPath 是本次请求的外部路径。
	ExternalPath string
}

// Verify 校验响应签名。header/body 必须是原始响应头与原始响应体字节。
//
// 缺少 X-Response-Signature 时返回 ErrResponseSignatureMissing;
// 验签失败时返回 ErrResponseSignatureInvalid, 调用方必须丢弃响应体。
func (v *ResponseVerifier) Verify(binding ResponseBinding, status int, header http.Header, body []byte) error {
	if err := binding.ProtocolProfile.validate(); err != nil {
		return err
	}
	signature := header.Get(HeaderResponseSignature)
	if signature == "" {
		return ErrResponseSignatureMissing
	}
	if alg := header.Get(HeaderResponseSignatureAlgorithm); alg != "" && !strings.EqualFold(alg, SignatureAlgorithm) {
		return fmt.Errorf("%w: unexpected algorithm %q", ErrResponseSignatureInvalid, alg)
	}
	requestID := header.Get(HeaderRequestID)
	present := false
	for name := range header {
		if strings.EqualFold(name, HeaderRequestID) {
			present = true
		}
	}
	if !present && binding.ProtocolProfile == ProductV1 {
		if strings.TrimSpace(binding.SentRequestID) == "" {
			return fmt.Errorf("%w: product response missing request ID and no sent ID retained", ErrResponseSignatureInvalid)
		}
		requestID = binding.SentRequestID
	}
	canonical := CanonicalResponse{
		ProtocolProfile:        binding.ProtocolProfile,
		RequestCanonicalSHA256: binding.RequestCanonicalSHA256,
		APIVersion:             binding.APIVersion,
		ExternalPath:           binding.ExternalPath,
		OperationID:            header.Get(HeaderOperationID),
		RequestID:              requestID,
		HTTPStatus:             status,
		ContentType:            header.Get("Content-Type"),
		ResponseTimestamp:      header.Get(HeaderResponseTimestamp),
		Body:                   body,
	}.CanonicalString()
	if err := VerifyCanonicalString(v.publicKey, canonical, signature); err != nil {
		return fmt.Errorf("%w: %v", ErrResponseSignatureInvalid, err)
	}
	return nil
}

// APIResponse 是平台统一响应包络的解析结果。
//
// 包络形如:
//
//	{"version":"2.0.0","timestamp":1755600000123,"success":true,
//	 "code":"2000","message":"Success","data":{}}
//
// SDK 不建模业务端点: Data 保持为原始 JSON, 由调用方用 DecodeData 解出自己的类型。
type APIResponse struct {
	// HTTPStatus 是 HTTP 状态码。
	HTTPStatus int
	// Header 是响应头。
	Header http.Header
	// Body 是原始响应体字节 (验签所用的同一份字节)。
	Body []byte
	// RequestID 取自响应头 X-Request-Id。
	RequestID string
	// OperationID 取自响应头 X-Operation-Id。
	OperationID string
	// SignatureVerified 表示本次响应是否通过了验签。
	SignatureVerified bool
	// Version 是包络的 version 字段 (如 "2.0.0"); 缺失或非字符串时为空串。
	Version string
	// Timestamp 是包络的 timestamp 字段 (Unix 毫秒); 缺失或非整数时为 0。
	Timestamp int64
	// SuccessFlag 是包络的 success 字段, 成功与否的唯一权威。
	// 该字段在响应体中缺失、为 null 或不是布尔类型时为 nil, 此时成功判定回退到 HTTP 状态码。
	SuccessFlag *bool
	// Code 是包络的 code 字段的字符串形式。
	//
	// 成功时是成功族结果码 ("2000" "2001" "2002" "2004" "2006", 以及待审批的 "2101");
	// 失败时网关层是 "域.名称" (如 "API.SIGNATURE_INVALID"), 业务层是 4xxx/5xxx 的
	// 数字字符串 (如 "4022" "5001")。响应体不是 JSON 对象或无 code 字段时为空串。
	//
	// code 不是成功判定依据, 判定见 IsSuccess。
	Code string
	// Message 是包络的 message 字段。
	Message string
	// Data 是包络的 data 字段原始 JSON。
	Data json.RawMessage
}

// unifiedBody 是统一响应包络中与协议相关的字段。
//
// code 一律按字符串对待 (数字形式的业务错误码会被字符串化); success 只在其值为
// JSON 布尔字面量时才被视为权威。松散类型的字段用 json.RawMessage 承接,
// 避免单个字段类型不符导致整体解析失败。
type unifiedBody struct {
	Version   json.RawMessage `json:"version"`
	Timestamp json.RawMessage `json:"timestamp"`
	Success   json.RawMessage `json:"success"`
	Code      json.RawMessage `json:"code"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data"`
}

// ParseAPIResponse 解析统一响应包络。响应体不是 JSON 对象时不报错, 只保留原始字节。
func ParseAPIResponse(status int, header http.Header, body []byte) *APIResponse {
	resp := &APIResponse{
		HTTPStatus:  status,
		Header:      header,
		Body:        body,
		RequestID:   header.Get(HeaderRequestID),
		OperationID: header.Get(HeaderOperationID),
	}
	var parsed unifiedBody
	if len(body) > 0 && json.Unmarshal(body, &parsed) == nil {
		resp.Message = parsed.Message
		resp.Data = parsed.Data
		resp.Version = rawString(parsed.Version)
		if len(parsed.Timestamp) > 0 {
			var ts int64
			if json.Unmarshal(parsed.Timestamp, &ts) == nil {
				resp.Timestamp = ts
			}
		}
		// 只有布尔字面量才是权威的 success; null / 字符串 / 数字一律忽略。
		switch string(parsed.Success) {
		case "true":
			flag := true
			resp.SuccessFlag = &flag
		case "false":
			flag := false
			resp.SuccessFlag = &flag
		}
		if len(parsed.Code) > 0 {
			raw := string(parsed.Code)
			if strings.HasPrefix(raw, `"`) {
				var code string
				if json.Unmarshal(parsed.Code, &code) == nil {
					resp.Code = code
				}
			} else if raw != "null" {
				// 数字形式的 code 直接字符串化: 业务错误码本就是数字字符串。
				resp.Code = raw
			}
		}
	}
	return resp
}

// rawString 在 raw 是 JSON 字符串字面量时返回其值, 否则返回空串。
func rawString(raw json.RawMessage) string {
	if len(raw) == 0 || !strings.HasPrefix(string(raw), `"`) {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// IsSuccess 判定本次调用是否成功。
//
// 算法 (五语言逐字对齐):
//
//	响应体是 JSON 对象, 且键 "success" 存在且其值是布尔类型时, 返回该布尔值;
//	否则回退到 200 <= HTTPStatus < 300。
//
// 只有布尔类型的 success 才算权威: 缺失、为 null、为字符串或数字一律走 HTTP 状态码回退。
// 不使用 code 判定成功 —— 成功码集合见 IsSuccessCode, 仅作文档与便利用途。
func (r *APIResponse) IsSuccess() bool {
	if r.SuccessFlag != nil {
		return *r.SuccessFlag
	}
	return r.HTTPStatus >= 200 && r.HTTPStatus < 300
}

// DecodeData 把 data 字段解码到 v。data 缺失时返回错误。
func (r *APIResponse) DecodeData(v any) error {
	if len(r.Data) == 0 {
		return fmt.Errorf("plutus: response has no data field")
	}
	return json.Unmarshal(r.Data, v)
}

// DecodeBody 把整个响应体解码到 v。
func (r *APIResponse) DecodeBody(v any) error {
	return json.Unmarshal(r.Body, v)
}

// AsError 在 IsSuccess 为 false 时返回 *APIError, 否则返回 nil。
//
// HTTP 200 且包络 success 为 false 同样是失败, 也会返回 *APIError;
// 错误码原样取包络的 code (数字形式的业务错误码保留为 "4022" 这类字符串, 不会被丢弃)。
func (r *APIResponse) AsError() error {
	if r.IsSuccess() {
		return nil
	}
	return &APIError{
		Code:        ErrorCode(r.Code),
		Message:     r.Message,
		HTTPStatus:  r.HTTPStatus,
		RequestID:   r.RequestID,
		OperationID: r.OperationID,
		RetryAfter:  r.Header.Get(HeaderRetryAfter),
		Response:    r,
	}
}
