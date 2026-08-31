// Package plutus 是 SlaunchX Plutus 商户 API 的 Go SDK, 实现协议 SLAUNCHX-PLUTUS-API-V1。
//
// 覆盖范围仅为传输层密码学与 HTTP 组装:
//
//   - 请求签名: RSA-SHA256 (PKCS#1 v1.5) 对 8 行规范串签名, 含严格的 query 规范化;
//   - 通用 HTTP 客户端: 组装全部协议头, body 只序列化一次, 摘要与发送使用同一份字节;
//   - 响应验签: 校验 SLAUNCHX-API-RESPONSE-V1 的 10 行规范串, 并把统一响应包络与
//     平台错误码解析为类型化错误;
//   - 混合加密信封: RSA-OAEP-SHA256 + AES-256-GCM, 用于加密请求与敏感响应解密;
//   - Webhook: 先验签 (bodyDigest 为 Base64) 后解密。
//
// 统一响应包络 (SPEC「统一响应包络」一节) 形如
// {"version","timestamp","success","code","message","data"}。成功与否以布尔字段
// success 为唯一权威, 缺失或非布尔时回退 HTTP 2xx; code 不参与判定, 成功族结果码
// 见 SuccessCodes / IsSuccessCode。判定逻辑在 APIResponse.IsSuccess。
//
// 响应缺 X-Response-Signature 时的策略属于 SDK 约定而非平台契约
// (SPEC「SDK 约定 (非平台契约)」一节): HTTP 2xx 缺签名头报验签失败,
// 非 2xx 缺签名头默认放行且 SignatureVerified 为 false, 可用
// Config.RequireSignatureOnErrorResponses 收紧。平台契约未穷举哪些状态码不带签名头,
// 因此 SDK 不做状态码白名单。
//
// 本包不建模任何业务端点的请求/响应模型: 调用方自行提供外部路径与已序列化的 body,
// 自行解析 data 字段。
//
// 依赖只有 Go 标准库。协议依据为仓库根的 SPEC.md 与 shared/test-vectors.json。
package plutus

// Protocol 是本 SDK 实现的协议标识。
const Protocol = "SLAUNCHX-PLUTUS-API-V1"

// DefaultAPIVersion 是当前唯一受支持的契约主版本, 对应 X-API-VERSION 头。
const DefaultAPIVersion = "1"

// SignatureAlgorithm 是 X-Signature-Algorithm / X-Response-Signature-Algorithm 的字面量值。
const SignatureAlgorithm = "RSA-SHA256"

// EnvelopeAlgorithm 是混合加密信封的算法标识。
const EnvelopeAlgorithm = "RSA-OAEP-AES-256-GCM"

// 协议头名。线格式上 X-API-VERSION 为全大写, 其余为 X-Xxx-Yyy 形式。
const (
	HeaderAPIKey                  = "X-Api-Key"
	HeaderAPIVersion              = "X-API-VERSION"
	HeaderTimestamp               = "X-Timestamp"
	HeaderNonce                   = "X-Nonce"
	HeaderSignature               = "X-Signature"
	HeaderSignatureAlgorithm      = "X-Signature-Algorithm"
	HeaderIdempotencyKey          = "X-Idempotency-Key"
	HeaderRequestID               = "X-Request-Id"
	HeaderPlatformEncryptionKeyID = "X-Platform-Encryption-Key-Id"

	HeaderResponseTimestamp          = "X-Response-Timestamp"
	HeaderResponseSignature          = "X-Response-Signature"
	HeaderResponseSignatureAlgorithm = "X-Response-Signature-Algorithm"
	HeaderPlatformSigningKeyID       = "X-Platform-Signing-Key-Id"
	HeaderOperationID                = "X-Operation-Id"
	HeaderRetryAfter                 = "Retry-After"

	HeaderWebhookDeliveryID = "X-SlaunchX-Delivery-Id"
	HeaderWebhookEventType  = "X-SlaunchX-Event-Type"
	HeaderWebhookTimestamp  = "X-SlaunchX-Timestamp"
	HeaderWebhookKeyID      = "X-SlaunchX-Key-Id"
	HeaderWebhookSignature  = "X-SlaunchX-Signature"
)
