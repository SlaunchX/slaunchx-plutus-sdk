# SlaunchX Plutus 商户 Go SDK

## product 接入

接入 product 时显式选择以下配置；默认仍使用 Alpha 规则，不会在验签失败后自动切换。

```go
// 在 plutus.Config 中增加：
ProtocolProfile: plutus.ProductV1,
```

product 请求按 7 行签名、响应按 5 行验签。URL 参数按 product 的排序和编码规则处理。SDK 自动发送并保存请求编号；响应缺少 `X-Request-Id` 时，用本次发送的编号验签。响应已有编号时使用返回值，验签失败仍报错。

这些改动仅在本地验证，尚未发布；下文未特别说明的协议细节和原有黄金向量使用默认 Alpha 规则。

协议 `SLAUNCHX-PLUTUS-API-V1` 的 Go 实现,覆盖请求签名、加密请求、响应验签、敏感响应解密、
Webhook 验签与解密。仅依赖 Go 标准库,零第三方依赖。

实现依据是协议 `SLAUNCHX-PLUTUS-API-V1` 与 [`shared/test-vectors.json`](../shared/test-vectors.json);
测试直接加载该向量文件,逐条比对全部分组。

- module: `github.com/slaunchx/slaunchx-plutus-sdk/go`
- 包名: `plutus`
- 最低 Go 版本: 1.21

## 安装

发布后:

```bash
go get github.com/slaunchx/slaunchx-plutus-sdk/go@latest
```

```go
import plutus "github.com/slaunchx/slaunchx-plutus-sdk/go"
```

发布前(仓库尚未发布到公开 module 代理时)用本地 `replace` 引用:

```bash
# 在你的项目 go.mod 所在目录执行
go mod edit -replace github.com/slaunchx/slaunchx-plutus-sdk/go=/path/to/slaunchx-plutus-sdk/go
go mod tidy
```

`go.mod` 中的效果:

```go.mod
require github.com/slaunchx/slaunchx-plutus-sdk/go v0.0.0

replace github.com/slaunchx/slaunchx-plutus-sdk/go => /path/to/slaunchx-plutus-sdk/go
```

私有仓库直接引用则配置 `GOPRIVATE`:

```bash
go env -w GOPRIVATE=github.com/slaunchx/*
```

## 密钥

四把 RSA 密钥对职责严格分离,不得混用:

| 密钥 | 商户持有 | 用途 |
| --- | --- | --- |
| `merchant_auth` | 私钥 | 对请求规范串签名 |
| `platform_auth` | 公钥 | 校验响应签名与 Webhook 签名 |
| `merchant_enc` | 私钥 | 解密敏感响应与 Webhook 通知 |
| `platform_enc` | 公钥 | 加密请求体 |

私钥为 PKCS#8 PEM(`BEGIN PRIVATE KEY`),公钥为 SPKI PEM(`BEGIN PUBLIC KEY`),
模数 2048–4096 位、公开指数恰为 65537。`plutus.KeyFingerprint` 计算
`SHA256:<SPKI DER 的小写 hex>` 形式的指纹。

## 快速开始

### 1. 构造客户端

```go
client, err := plutus.New(plutus.Config{
    APIVersion: "1",
    BaseURL:                   "https://consumer-api.slaunchx.example",
    APIKey:                    "apk_xxx",
    MerchantAuthPrivateKeyPEM: merchantAuthPrivPEM,
    PlatformAuthPublicKeyPEM:  platformAuthPubPEM,
    PlatformEncPublicKeyPEM:   platformEncPubPEM,  // 调用加密端点时必需
    MerchantEncPrivateKeyPEM:  merchantEncPrivPEM, // 解密敏感响应 / Webhook 时必需
})
if err != nil {
    return err
}
```

`BaseURL` 只写到 host,**不要**拼 `/api/v1/consumer`:外部路径由 `Request.Path` 给出,
版本走 `X-API-VERSION` 头。

`BaseURL` 必须是**对外 CONSUMER API 域名**(边缘/网关地址),不能是源站地址,也不能自行拼
`/prometheus`、`/api/v1/consumer` 等内部前缀——这两类前缀由边缘(Cloudflare/nginx)负责改写,
SDK 对外部路径签名,源站地址或拼错的前缀会导致签名规范串第 2 行(外部路径)与平台重建的
不一致,签名校验必然失败:

```go
// 正确: BaseURL 只到 host, Request.Path 是外部路径, SDK 对 "/card-products/..." 签名。
client, err := plutus.New(plutus.Config{
    APIVersion: "1",
    BaseURL: "https://consumer-api.slaunchx.example",
    // ...
})
resp, err := client.Do(ctx, plutus.Request{
    Method: http.MethodPost,
    Path:   "/card-products/10010106/shared/cards/create",
    // ...
})
```

```go
// 错误: BaseURL 指向源站并拼了内部前缀, 签名必然失败。
client, err := plutus.New(plutus.Config{
    APIVersion: "1",
    BaseURL: "https://origin.internal.example/prometheus/api/v1/consumer",
    // ...
})
```

### 2. 普通签名调用

```go
var page struct {
    Records []struct {
        CardBizID string `json:"cardBizId"`
        Status    string `json:"status"`
    } `json:"records"`
}

resp, err := client.DoJSON(ctx, plutus.Request{
    Method: http.MethodGet,
    Path:   "/card-products/cards/page",
    Query:  url.Values{"status": {"IN_USE"}, "pageSize": {"20"}},
}, &page)
if err != nil {
    var apiErr *plutus.APIError
    if errors.As(err, &apiErr) && apiErr.Retryable() {
        // 429 按 Retry-After 退避; TIMESTAMP_EXPIRED / NONCE_REUSED 重新签名重试
    }
    return err
}
_ = resp.RequestID
```

`err == nil` 即表示成功:`Do` / `DoJSON` 内部已按统一响应包络判定成功与否,失败时返回
`*plutus.APIError`。不要自己去比较 `resp.Code`,判定规则见下节。

写操作带幂等键与已序列化的 body:

```go
resp, err := client.Do(ctx, plutus.Request{
    Method:         http.MethodPost,
    Path:           "/card-products/cards/freeze",
    JSONBody:       map[string]string{"reasonCategory": "USER_REQUESTED"},
    IdempotencyKey: "idem-20260830-0001",
})
```

`JSONBody` 由 SDK 序列化一次,摘要与发送使用同一份字节。若你自己序列化,请传 `Body []byte`
并保证之后不再改动这段字节。

重试必须重新调用 `Do`(重新生成时间戳与 nonce 并重新签名),业务幂等靠 `X-Idempotency-Key`,
不要复用整套签名头。

### 3. 加密端点

对 `plutus.EncryptedRouteTemplates` 列出的加密端点设置 `Encrypt: true`,SDK 自动完成:混合信封封装
(RSA-OAEP-SHA256 + AES-256-GCM)、AAD 绑定 `X-Request-Id | 外部路径 | X-Timestamp | 平台加密公钥指纹`、
`X-Platform-Encryption-Key-Id` 头,并对信封 JSON 字节签名。

```go
resp, err := client.Do(ctx, plutus.Request{
    Method:         http.MethodPost,
    Path:           "/card-products/10010106/shared/cards/create",
    JSONBody:       map[string]any{"platformCardProductBizId": "pcp_xxx", "quantity": 2},
    Encrypt:        true,
    RequestID:      "req_20260830_0001", // 留空则由 SDK 生成
    IdempotencyKey: "idem-20260830-0002",
})
```

已知加密端点表见 `plutus.EncryptedRouteTemplates`,
`plutus.IsKnownEncryptedRoute(path)` 判定给定路径是否在表中。`Client.Prepare` 对加密请求会
校验 `Request.Path`:默认(`Config.StrictEncryptedRouteValidation` 为零值 `false`)未知路径
不阻断请求,只向 stderr 打印一次警告,避免平台新增加密端点而 SDK 表未及时更新时卡死商户请求;
置为 `true` 后未知路径会使 `Prepare` 返回满足 `errors.Is(err, plutus.ErrUnknownEncryptedRoute)`
的 error。

### 4. 敏感响应解密

敏感字段以混合信封形式出现在响应体中(具体位置由业务端点定义)。取出信封后:

```go
var data struct {
    Secure plutus.Envelope `json:"secure"`
}
if err := resp.DecodeData(&data); err != nil {
    return err
}
plaintext, err := client.DecryptSensitiveEnvelope(&data.Secure, resp.RequestID)
```

该方法内部重建 AAD(`routeTemplate` 固定为空串,`keyId` 为商户加密公钥指纹,
`timestamp` 从信封回显的 `aad` 解析)并做常量时间比对,再用 `merchant_enc` 私钥解密。

### 5. 接收 Webhook

```go
receiver, err := plutus.NewWebhookReceiver(plutus.WebhookConfig{
    APIKey:                   "apk_xxx", // 与 X-SlaunchX-Key-Id 比对
    PlatformAuthPublicKeyPEM: platformAuthPubPEM,
    MerchantEncPrivateKeyPEM: merchantEncPrivPEM,
})

http.HandleFunc("/webhooks/slaunchx", func(w http.ResponseWriter, r *http.Request) {
    // 必须读原始 body: 签名覆盖的是信封 JSON 的原始字节。
    // 不要让任何中间件先做 json 解码再重新序列化。
    notification, err := receiver.HandleRequest(r)
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    if seenBefore(notification.Payload.DeliveryBizID) { // 按投递 ID 去重
        w.WriteHeader(http.StatusNoContent)
        return
    }
    switch notification.Payload.EventType {
    case "card.issuance":
        var data struct {
            CardBizID string `json:"cardBizId"`
            Status    string `json:"status"`
        }
        if err := notification.DecodeData(&data); err != nil {
            w.WriteHeader(http.StatusBadRequest)
            return
        }
    }
    w.WriteHeader(http.StatusNoContent)
})
```

`HandleRequest` 的顺序是:比对 `X-SlaunchX-Key-Id` → 可选时间戳容差 → 验签 → 严格解析信封
(必须有 `envelopeVersion: 1`,不得有 `encryptedPayload`)→ 重建 AAD 解密 → 交叉校验明文的
`deliveryBizId` / `eventType` / `payloadSchemaVersion`。

已有 `Client` 时可直接派生:`receiver, err := client.WebhookReceiver(0)`,参数是时间戳容差,
传 `0` 表示不校验。

金额字段是 `{currency, amount}` 且 `amount` 为十进制字符串,用 `plutus.Amount` 接,
不要解析成 `float64`。

## 统一响应包络与成功判定

平台的全部响应共用一个包络结构:

```json
{
  "version": "2.0.0",
  "timestamp": 1755600000123,
  "success": true,
  "code": "2000",
  "message": "Success",
  "data": {}
}
```

`plutus.APIResponse` 逐字段映射:`Version`、`Timestamp`(Unix 毫秒)、
`SuccessFlag *bool`、`Code`、`Message`、`Data`。

**成功判定算法**(`APIResponse.IsSuccess`,五语言 SDK 逐字一致):

```
响应体是 JSON 对象, 且键 "success" 存在且值是布尔类型 → 返回该布尔值
否则                                                 → 返回 200 <= httpStatus < 300
```

- `success` 是布尔字段,是成功与否的唯一权威。只有**布尔类型**才算权威:缺失、`null`、
  字符串 `"true"`、数字 `1` 一律走 HTTP 状态码回退,此时 `SuccessFlag` 为 `nil`。
- **不用 `code` 判定成功。** HTTP 200 且 `success` 为 `false` 是失败,`Do` / `DoJSON` 会返回
  `*plutus.APIError`;非 2xx 但 `success` 为 `true` 是成功。
- `code` 是字符串。成功族为 `"2000" "2001" "2002" "2004" "2006"`,另有 `"2101"`
  (账号待审批:登录成功但不签发 JWT,`success` 仍为 `true`)。失败时网关层是 `域.名称`
  (如 `API.SIGNATURE_INVALID`),业务层是 4xxx/5xxx 的数字字符串(如 `"4022"` `"5001"`)。
  数字形式的业务错误码会原样保留在 `APIError.Code`,不会被丢弃。

成功码集合以 `plutus.SuccessCodes` 与 `plutus.IsSuccessCode(code)` 暴露,**仅作文档与便利用途**,
不是成功判定依据:

```go
plutus.CodeAccountPendingApproval // "2101"
plutus.IsSuccessCode("2101")      // true

// 判定一次调用是否成功,只看 err 或 IsSuccess:
resp, err := client.Do(ctx, req)
if err != nil {
    var apiErr *plutus.APIError
    if errors.As(err, &apiErr) {
        _ = apiErr.Code // 如 "4022" 或 "API.SIGNATURE_INVALID"
    }
    return err
}
_ = resp.IsSuccess() // 此处必为 true
```

## 响应缺签名头的默认策略

响应验签默认开启(关闭开关是 `Config.DisableResponseSignatureVerification`)。在验签开启的前提下:

| 情形 | 行为 |
| --- | --- |
| 响应带 `X-Response-Signature` | 强制验签;失败返回 `ErrResponseSignatureInvalid` 并丢弃响应体 |
| HTTP 2xx 且缺签名头 | 返回 `ErrResponseSignatureMissing` |
| 非 2xx 且缺签名头 | 放行;`APIResponse.SignatureVerified` 为 `false`,按 `*APIError` 返回 |
| 非 2xx 且缺签名头 + `RequireSignatureOnErrorResponses: true` | 返回 `ErrResponseSignatureMissing` |

严格开关是 `Config.RequireSignatureOnErrorResponses`,默认 `false`。

SDK 不做状态码白名单(没有「401/403 一律放行」这类配置),只按 2xx / 非 2xx 区分。
平台契约并未穷举哪些状态码不带签名头,因此该策略属于 SDK 自身约定而非平台强制契约。

被放行的响应必须在业务侧自行判断可信度:

```go
resp, err := client.Do(ctx, req)
var apiErr *plutus.APIError
if errors.As(err, &apiErr) && !apiErr.Response.SignatureVerified {
    // 该错误响应未经验签, 只能用于日志与提示, 不得据此改写本地状态
}
```

## 实际发送的 query 形态

本 SDK **总是发送规范化后的 query**:排序 + RFC 3986 编码(unreserved 字符不编码,
空格为 `%20`)。**该行为不可配置**,没有「按原样发送」的开关。

`Request.Query` 与 `Request.RawQuery` 都只决定输入:两者都会先经过同一套规范化算法,
`client.go` 把规范化结果直接写入实际请求的 `RawQuery`。因此:

```go
Query: url.Values{"status": {"IN_USE"}, "keyword": {"hello world"}, "pageSize": {"20"}}
// 线上实际发出: ?keyword=hello%20world&pageSize=20&status=IN_USE
```

传入 `RawQuery: "status=IN_USE&pageSize=20"` 时,线上发出的仍是排序后的
`pageSize=20&status=IN_USE`。平台对收到的原始 query 重新执行同一规范化算法,两种形态等价,
但若你的服务端日志按原始顺序做匹配,需要知道顺序会变。

`RawQuery` 必须已按 RFC 3986 正确编码,否则 `Prepare` 返回 `ErrInvalidQuery`。

## Webhook 时间戳容差

`WebhookConfig.TimestampTolerance` 是 `time.Duration`,**默认零值即关闭**:零值时完全不校验
`X-SlaunchX-Timestamp`。协议未规定 Webhook 时间戳窗口,是否启用与窗口大小由接入方自行决定。

```go
receiver, err := plutus.NewWebhookReceiver(plutus.WebhookConfig{
    APIKey:                   "apk_xxx",
    PlatformAuthPublicKeyPEM: platformAuthPubPEM,
    MerchantEncPrivateKeyPEM: merchantEncPrivPEM,
    TimestampTolerance:       5 * time.Minute, // 省略即关闭
})
```

从 `Client` 派生时容差由参数给出:`client.WebhookReceiver(0)` 关闭,
`client.WebhookReceiver(5 * time.Minute)` 启用。超出窗口返回 `ErrWebhookTimestampOutOfRange`。

## 配置项

> 协议头由 SDK 自动补齐,调用方只需配置下表字段;各字段是否进入签名串由下表说明标注。
> 平台**不读取** `X-Workspace-Id`,SDK 也不发送该头。

`plutus.Config`:

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `BaseURL` | `string` | 必填 | 商户 API 基地址,必须是对外 CONSUMER API 域名,不含链/版本/门户前缀,不能是源站地址或自行拼接的 `/prometheus`、`/api/v1/consumer` 前缀 |
| `APIKey` | `string` | 必填 | API Key 业务 ID,即 `X-Api-Key` |
| `APIVersion` | `string` | 无（必填） | `X-API-VERSION`,参与签名 |
| `MerchantAuthPrivateKeyPEM` / `MerchantAuthPrivateKey` | `[]byte` / `*rsa.PrivateKey` | 必填 | 请求签名私钥 |
| `PlatformAuthPublicKeyPEM` / `PlatformAuthPublicKey` | `[]byte` / `*rsa.PublicKey` | 验签开启时必填 | 响应与 Webhook 验签公钥 |
| `PlatformEncPublicKeyPEM` / `PlatformEncPublicKey` | `[]byte` / `*rsa.PublicKey` | 加密端点必填 | 请求加密公钥 |
| `MerchantEncPrivateKeyPEM` / `MerchantEncPrivateKey` | `[]byte` / `*rsa.PrivateKey` | 解密时必填 | 敏感响应 / Webhook 解密私钥 |
| `HTTPClient` | `*http.Client` | `&http.Client{Timeout: 30s}` | 实际发送请求的客户端 |
| `UserAgent` | `string` | 空 | 附加 `User-Agent` |
| `DisableResponseSignatureVerification` | `bool` | `false` | 默认强制验签;置为 `true` 仅用于联调 |
| `RequireSignatureOnErrorResponses` | `bool` | `false` | 严格开关:默认非 2xx 缺签名头放行,置为 `true` 后非 2xx 缺签名头也报验签失败。2xx 缺签名头一律报错,不受本开关影响 |
| `MaxResponseBytes` | `int64` | 8 MiB | 响应体读取上限 |
| `NonceFunc` | `func() (string, error)` | `plutus.NewNonce` | 生成 `X-Nonce`,须满足 `^[A-Za-z0-9._~-]{16,128}$` |
| `NowFunc` | `func() time.Time` | `time.Now` | 生成 `X-Timestamp`(Unix 毫秒) |
| `StrictEncryptedRouteValidation` | `bool` | `false` | 加密请求的 `Request.Path` 不在 `plutus.EncryptedRouteTemplates` 已知表中时:`false` 只打印 stderr 警告不阻断;`true` 时 `Prepare` 返回满足 `errors.Is(err, plutus.ErrUnknownEncryptedRoute)` 的 error |

`plutus.WebhookConfig`:

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `APIKey` | `string` | 空 | 非空时与 `X-SlaunchX-Key-Id` 比对;该值同时是 AAD 第 4 分量 |
| `PlatformAuthPublicKeyPEM` / `PlatformAuthPublicKey` | `[]byte` / `*rsa.PublicKey` | 必填 | Webhook 验签公钥 |
| `MerchantEncPrivateKeyPEM` / `MerchantEncPrivateKey` | `[]byte` / `*rsa.PrivateKey` | 必填 | Webhook 解密私钥 |
| `TimestampTolerance` | `time.Duration` | `0`,即零值关闭 | 零值时完全不校验时间戳;协议未规定 Webhook 时间戳窗口,按需自行设置 |
| `Now` | `func() time.Time` | `time.Now` | 时间源,便于测试 |

`plutus.Request`:

| 字段 | 说明 |
| --- | --- |
| `Method` / `Path` | HTTP 方法与外部路径(以 `/` 开头) |
| `Query` / `RawQuery` | 二选一;`Query` 由 SDK 按 RFC 3986 编码,`RawQuery` 须已正确编码。两者都会被规范化后再发送,见「实际发送的 query 形态」 |
| `Body` / `JSONBody` | 二选一;`JSONBody` 由 SDK 序列化一次 |
| `ContentType` | 默认 `application/json`,仅在 body 非空时发送 |
| `IdempotencyKey` | 非空则发送 `X-Idempotency-Key` 并参与签名 |
| `RequestID` | `X-Request-Id`,加密端点必需(留空由 SDK 生成) |
| `Encrypt` | 是否封装为混合加密信封 |
| `Header` | 附加自定义头,协议头会被 SDK 覆盖 |

## 错误处理

- 本地协议错误用哨兵值判定:`ErrInvalidQuery`、`ErrInvalidNonce`、`ErrInvalidTimestamp`、
  `ErrResponseSignatureMissing`、`ErrResponseSignatureInvalid`、`ErrWebhookSignatureInvalid`、
  `ErrEnvelopeInvalid`、`ErrAADMismatch`、`ErrKeyFingerprintMismatch`、`ErrDecryptFailed` 等。
- 平台错误是 `*APIError`,在 `IsSuccess()` 为 `false` 时产生(含 HTTP 200 且 `success:false`),
  支持模板匹配:

```go
errors.Is(err, &plutus.APIError{Code: plutus.CodeNonceReused})
errors.Is(err, &plutus.APIError{HTTPStatus: 429})
plutus.IsCode(err, plutus.CodeRateLimited)

var apiErr *plutus.APIError
if errors.As(err, &apiErr) {
    _ = apiErr.RetryAfter
    _ = apiErr.Retryable()
    _ = apiErr.Code     // 网关码 "API.KEY_DISABLED" 或业务码 "4022"
    _ = apiErr.Response // 已解析的响应, 可取原始 body 与 SignatureVerified
}
```

- 业务层错误码是数字字符串,同样用 `IsCode` / 模板匹配:
  `plutus.IsCode(err, plutus.ErrorCode("4022"))`。
- 响应验签失败时 `Do` 不返回响应体:未验证的数据不得交给业务代码。

## 签名排障

服务端验签失败时不会返回诊断信息(只有 `API.SIGNATURE_INVALID` 一类错误码),排障只能靠客户端
自检规范串。SDK 提供两种「只签名不发送」的方式,均不依赖网络:

**方式一:`Client.Prepare`**(推荐,复用已配置的 Client,自动带上加密/幂等等分支逻辑):

```go
prepared, err := client.Prepare(ctx, plutus.Request{
    Method:         http.MethodPost,
    Path:           "/card-products/10010106/shared/cards/create",
    JSONBody:       map[string]any{"platformCardProductBizId": "pcp_xxx", "quantity": 2},
    Encrypt:        true,
    RequestID:      "req_debug_0001",
    IdempotencyKey: "idem-debug-0001",
})
if err != nil {
    return err
}
signed := prepared.Signed // *plutus.SignedRequest
fmt.Println(signed.CanonicalString)    // 8 行规范串, LF 连接
fmt.Println(signed.CanonicalDigestHex) // 规范串自身的 SHA-256 hex (响应验签绑定用)
fmt.Println(signed.Signature)          // 最终 Base64 签名, 即 X-Signature 头的值
// prepared.HTTPRequest 尚未发送, 可先比对协议头 / body 字节, 确认无误后再调用 c.httpClient.Do 或改用 client.Do
```

**方式二:直接调用 `Signer.Sign`**(不依赖 Client,只需要 `merchant_auth` 私钥):

```go
signer := client.Signer() // 或 plutus.NewSigner(apiKey, merchantAuthPrivateKeyPEM)
signed, err := signer.Sign(plutus.CanonicalRequest{
    Method:         http.MethodPost,
    ExternalPath:   "/card-products/10010106/shared/cards/create",
    RawQuery:       "", // 已规范化的 query (严格解码 → RFC 3986 重编码 → 按字节序排序), 无 query 传空串
    Timestamp:      strconv.FormatInt(time.Now().UnixMilli(), 10),
    Nonce:          "0123456789abcdef0123456789abcdef",
    APIVersion:     "1",
    IdempotencyKey: "idem-debug-0001",
    Body:           bodyBytes, // 必须与实际要发送的字节完全一致
})
if err != nil {
    return err
}
fmt.Println(signed.CanonicalString)
fmt.Println(signed.CanonicalDigestHex)
fmt.Println(signed.Signature)
```

**逐行核对 checklist**(`CanonicalRequest.CanonicalString()` 按下列顺序拼出 8 行,LF 连接,
无尾换行,顺序取自 `go/canonical.go`):

| 行号 | 内容 | 常见问题 |
| --- | --- | --- |
| 1 | `Method`,大写 | — |
| 2 | `ExternalPath` | 必须是外部路径,以 `/` 开头;**不得**含 `/api/v1/consumer`、`/prometheus` 等内部前缀(见「`BaseURL` 配置」) |
| 3 | 规范化后的 query | 必须按「严格解码 → RFC 3986 重编码 → 按 (key, value) 字节序排序 → 用 `&` 重组」处理;自检用 `plutus.CanonicalizeQuery`,不要用 `url.Values.Encode()`(会把空格编成 `+`) |
| 4 | `Timestamp` | 必须是 Unix **毫秒**十进制字符串(至少 13 位),不是秒;`ValidateTimestamp` 会拒绝非法值 |
| 5 | `Nonce` | 必须满足 `^[A-Za-z0-9._~-]{16,128}$`;Base64(含 `+` `/` `=`)不合法 |
| 6 | `APIVersion` | 非空,且与实际发送的 `X-API-VERSION` 头一致 |
| 7 | `IdempotencyKey` | 无幂等键时该行是**空字符串**,不能省略整行(8 行结构固定,少一行会整体错位) |
| 8 | body 摘要(hex) | 必须对**实际要发送的字节**求 SHA-256,而不是序列化前的对象;`GET`/`HEAD`/`DELETE` 无条件用空 body 摘要(`plutus.EmptyBodySHA256Hex`),即使这三个方法携带了 body 也不例外(`plutus.ForcesEmptyBodyDigest` 可自检) |

自检时若第 2 行(外部路径)与预期不符,先检查 `BaseURL` 是否误配成源站地址或自行拼了内部前缀
(见上文「BaseURL 配置」的正确/错误示例);若第 3 行与预期不符,优先怀疑用了
`url.Values.Encode()` 或 query 未按上表规则规范化;若第 8 行与预期不符,优先怀疑 body 被序列化了
两次(摘要与发送用了不同字节),或对 `GET`/`HEAD`/`DELETE` 错用了实际 body 摘要。

## 常见错误

1. body 序列化两次(摘要与发送用了不同字节)。用 `JSONBody`,或自己序列化一次后传 `Body`。
2. query 用 `url.Values.Encode()`:它把空格编成 `+`,会被规范化算法拒绝。用 `Request.Query`
   或 `plutus.EncodeQuery`。
3. `GET` / `HEAD` / `DELETE` 带 body 时仍用实际 body 摘要 —— 这三个方法一律用空 body 摘要。
4. `X-Timestamp` 用了秒。必须是毫秒;认证窗口以 ±60 秒为准,生产环境必须启用 NTP。
5. nonce 用 Base64(含 `+` `/` `=`)。用 hex 或带连字符的 UUID。
6. Webhook 先解密后验签,或对解密后的明文验签。必须先验签,且摘要用 Base64 而非 hex。
7. 直接用信封回显的 `aad` 解密。必须本地重建并常量时间比对。
8. 用 `code == 0` 或 `code == "0"` 判成功。平台的 `code` 是字符串,成功族是 `"2000"` 一类;
   成功判定看 `success` 布尔字段(即 `err == nil` / `IsSuccess()`),不要看 `code`。
9. 只看 HTTP 状态码判成功。HTTP 200 也可能是 `success:false` 的业务失败。

## 测试

```bash
cd go
go vet ./...
go test ./...
```

测试加载 `../shared/test-vectors.json`,覆盖 `canonicalQuery`(21,含 6 条拒绝用例)、
`bodyHash`(7)、`requestSignature`(7,规范串逐行比对 + 重签名逐字节比对)、
`responseSignature`(3,只做验签与解析断言)、`encryptedEnvelope`(3,解密比对明文 +
篡改 AAD/密文的负向用例)、`webhook`(2,验签 + 解密比对明文)。

不依赖向量文件的部分:`envelope_success_test.go` 用本地 fixture 覆盖统一响应包络的成功判定,
`client_test.go` 用 `httptest` 覆盖端到端流程,包括「签名字节 == 发送字节」不变量
(`TestClientSignedBytesEqualSentBytes`,普通与加密两种 body)、HTTP 200 + `success:false`
的业务失败,以及缺签名头的三种情形。

向量中的 RSA 私钥仅用于测试,绝不可用于任何真实环境。

`X-API-VERSION` 必须由调用方通过版本配置显式填写，没有默认值；当前 product 填 `1`。遗漏、空串或纯空白会在本地报错。
