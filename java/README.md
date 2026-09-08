# SlaunchX Plutus 商户 Java SDK

## product 接入

接入 product 时显式选择以下配置；默认仍使用 Alpha 规则，不会在验签失败后自动切换。

```java
import com.slaunchx.plutus.sdk.ProtocolProfile;
// 在 PlutusConfig.builder() 中增加：
.protocolProfile(ProtocolProfile.PRODUCT_V1)
```

product 请求按 7 行签名、响应按 5 行验签。URL 参数按 product 的排序和编码规则处理。SDK 自动发送并保存请求编号；响应缺少 `X-Request-Id` 时，用本次发送的编号验签。响应已有编号时使用返回值，验签失败仍报错。

这些改动仅在本地验证，尚未发布；下文未特别说明的协议细节和原有黄金向量使用默认 Alpha 规则。

SlaunchX Plutus 平台 CONSUMER 门户 / API 链的官方 Java SDK,只覆盖**传输层**:请求签名、
请求加密、响应验签、敏感响应解密、Webhook 验签与解密。SDK 不建立业务端点模型,业务字段由
调用方按端点自行映射。

实现依据是协议 `SLAUNCHX-PLUTUS-API-V1` 与 [`shared/test-vectors.json`](../shared/test-vectors.json);
向量为最高权威。全部向量组均已在单元测试中逐条比对。

| 项 | 值 |
| --- | --- |
| groupId / artifactId | `com.slaunchx` / `plutus-sdk` |
| 当前版本 | `1.0.0-SNAPSHOT` |
| 目标 Java 版本 | 17(编译目标);已在 JDK 21 上验证 |
| 运行时依赖 | 仅 `com.fasterxml.jackson.core:jackson-databind` |
| HTTP 客户端 | JDK 内置 `java.net.http.HttpClient`,不引入第三方 |
| 测试框架 | JUnit 5 |

---

## 1. 安装

### 1.1 源码引入(当前推荐)

仓库尚未发布到公共制品库,先从源码构建并安装到本地 Maven 仓库:

```bash
git clone <gitea-or-github-host>/slaunchx/slaunchx-plutus-sdk.git
cd slaunchx-plutus-sdk/java
mvn clean install -DskipTests=false
```

再在业务工程中声明依赖:

```xml
<dependency>
  <groupId>com.slaunchx</groupId>
  <artifactId>plutus-sdk</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
```

多模块工程也可直接把 `java/` 作为子模块聚合构建。

### 1.2 Maven Central(待发布)

正式版本发布后可直接声明依赖,当前为占位:

```xml
<!-- 尚未发布, 版本号待定 -->
<dependency>
  <groupId>com.slaunchx</groupId>
  <artifactId>plutus-sdk</artifactId>
  <version>TBD</version>
</dependency>
```

---

## 2. 快速开始

### 2.1 构造配置

四把密钥职责严格分离,不得混用。私钥为 PKCS#8 PEM(`BEGIN PRIVATE KEY`),公钥为 SPKI PEM
(`BEGIN PUBLIC KEY`,不接受 PKCS#1)。

```java
import com.slaunchx.plutus.sdk.*;

PlutusConfig config = PlutusConfig.builder()
    .apiVersion("1")
        .baseUrl("https://<consumer-api-host>")
        .apiKey("apk_xxxxxxxx")
        .merchantAuthPrivateKeyPem(readPem("merchant_auth_private.pem"))   // 对请求签名
        .platformAuthPublicKeyPem(readPem("platform_auth_public.pem"))     // 验响应 / Webhook 签名
        .merchantEncPrivateKeyPem(readPem("merchant_enc_private.pem"))     // 解敏感响应 / Webhook
        .platformEncPublicKeyPem(readPem("platform_enc_public.pem"))       // 加密请求体
        .build();

PlutusClient client = new PlutusClient(config);
```

私钥只从受控的密钥管理设施加载,不要写进代码仓库、日志或环境变量明文。

### 2.2 签名调用(明文端点)

时间戳、nonce、签名头由 SDK 自动生成;body 只序列化一次,摘要与发送使用同一份字节。

```java
import com.slaunchx.plutus.sdk.model.ApiResponse;

// GET,带 query。参数值会按 RFC 3986 编码(空格 → %20,加号 → %2B)
ApiResponse page = client.call(PlutusRequest.get("/card-products/cards/page")
        .queryParam("status", "IN_USE")
        .queryParam("pageSize", "20")
        .build());
String cardBizId = page.data().get("records").get(0).get("cardBizId").asText();

// POST,带幂等键。写操作重试必须复用同一个幂等键,但必须重新签名
ApiResponse freeze = client.call(PlutusRequest.post("/card-products/cards/freeze")
        .jsonBody(Map.of("cardBizId", cardBizId, "reasonCategory", "USER_REQUESTED"))
        .idempotencyKey("idem-20260830-0001")
        .build());
```

`call(...)` 在平台判定失败时抛出 `PlutusApiException`;若需自行处理错误码,改用
`request(...)` 拿到 `PlutusResponse` 再调用 `apiResponse()`:

```java
ApiResponse parsed = client.request(req).apiResponse();
if (parsed.successful()) {
    handle(parsed.data());
} else {
    log.warn("平台返回失败: code={}, message={}", parsed.rawCode(), parsed.message());
}
```

成功判定的规则见 [4. 统一响应包络与成功判定](#4-统一响应包络与成功判定)。

路径必须是**外部路径**:以 `/` 开头,不含 `/api`、`/v1`、`/consumer` 前缀;版本走
`X-API-VERSION` 头。

query 的发送形态见 [4.3](#43-query-的实际发送形态)。

### 2.3 加密端点

对 `EncryptedRoutes.all()` 列出的加密端点,置 `encrypted(true)`。SDK 会用平台加密公钥封装混合信封,
把信封 JSON 作为实际 body 发送,并对信封字节签名,同时补齐 `X-Request-Id` 与
`X-Platform-Encryption-Key-Id`。

```java
PlutusResponse response = client.request(
        PlutusRequest.post("/card-products/10010106/shared/cards/create")
                .jsonBody(Map.of("platformCardProductBizId", "pcp_xxx", "quantity", 2))
                .requestId("req_20260830_0001")   // 可省略, 省略时 SDK 生成
                .idempotencyKey("idem-20260830-0002")
                .encrypted(true)
                .build());

ApiResponse created = response.requireSuccess();
```

若端点返回敏感字段(混合信封),用同一个 `requestId` 解密:

```java
JsonNode envelope = response.json().get("data").get("cardSecret");
String plaintext = client.decryptSensitivePayload(envelope, "req_20260830_0001");
```

敏感响应的 AAD 由 SDK 重建:`routeTemplate` 固定为空串,`keyId` 为商户加密
公钥指纹,`timestamp` 从信封回显的 `aad` 解析;重建后与回显值做常量时间比对,再用**重建的**
AAD 解密。信封 `keyFingerprint` 与本地商户加密公钥指纹不符时直接拒绝。

**已知加密端点常量表。** `com.slaunchx.plutus.sdk.crypto.EncryptedRoutes` 收录
6 条强制加密端点(`EncryptedRoutes.all()`、`EncryptedRoutes.isKnown(path)`)。
`PlutusClient` 在加密分支会用它核对实际的 routeTemplate:命中已知表则正常发送;未命中时,
默认(非严格)模式只打一条 WARNING 级日志、**不阻断请求**——平台新增加密端点是可预期的演进,
直接拒绝会让尚未升级 SDK 常量表的商户请求集体失败。需要提前发现路径拼写错误或端点变更的
商户,可用 `PlutusConfig.builder().strictEncryptedRouteValidation(true)` 开启严格模式,
未登记路由改为直接抛 `PlutusException`,已登记路由不受影响。

### 2.4 Webhook 接收

**必须先验签、后解密**,且签名覆盖的是**加密信封 JSON 的原始字节**。务必把框架收到的原始
字节交给 SDK:任何重新序列化、重新格式化或追加换行都会让摘要不匹配。

```java
import com.slaunchx.plutus.sdk.webhook.*;

WebhookHandler handler = WebhookHandler.builder()
        .platformAuthPublicKeyPem(readPem("platform_auth_public.pem"))
        .merchantEncPrivateKeyPem(readPem("merchant_enc_private.pem"))
        .expectedApiKeyBizId("apk_xxxxxxxx")   // 必填: 校验本地接收方 API Key
        .build();

// Servlet 示例:request.getInputStream().readAllBytes() 拿原始字节
@PostMapping(value = "/webhooks/slaunchx", consumes = MediaType.ALL_VALUE)
public ResponseEntity<Void> receive(@RequestHeader Map<String, String> headers,
                                    @RequestBody byte[] rawBody) {
    WebhookNotification event;
    try {
        event = handler.handle(headers, rawBody);   // 验签 + 形状校验 + 解密 + 交叉校验
    } catch (PlutusWebhookException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }

    // 按 deliveryBizId 去重:自动重试与人工重放共用同一个投递 ID
    if (!deliveryStore.markProcessed(event.deliveryBizId())) {
        return ResponseEntity.ok().build();
    }

    switch (event.eventType()) {
        case "card.issuance" -> onIssuance(event.data());
        case "card.status"   -> onStatusChange(event.data());
        default -> log.info("未处理的事件类型 {}", event.eventType());
    }
    return ResponseEntity.ok().build();
}
```

载荷中的金额是 `{currency, amount}` 结构,`amount` 为十进制字符串(如 `"25.80"`),
用 `BigDecimal` 解析,**不要用 float / double**。

`WebhookHandler` 也可由 `WebhookHandler.fromConfig(config)` 从既有 `PlutusConfig` 构造。

### 2.5 低层 API

需要自行控制 HTTP 栈时,可直接使用协议原语:

```java
// 请求签名
RequestSigner signer = new RequestSigner(merchantAuthPrivateKey);
SignedRequest signed = signer.sign(new SigningInput(
        "POST", "/card-products/cards/freeze", null,
        Long.toString(System.currentTimeMillis()), nonce, "1", idempotencyKey, bodyBytes));
// signed.canonicalString() / signed.signatureBase64() / signed.requestCanonicalSha256()

// 响应验签(第 2 行的绑定摘要必须本地计算, 绝不能从响应头读取)
new ResponseVerifier(platformAuthPublicKey).requireValid(
        new ResponseSignatureContext(signed.requestCanonicalSha256(), "1", path,
                operationId, requestId, status, contentTypeRaw, responseTimestamp,
                Digests.sha256Hex(responseBodyBytes)),
        responseSignature);

// 信封封装 / 拆封
Envelope envelope = new EnvelopeCodec().seal(plaintext, recipientPublicKey, fingerprint, aad);
byte[] decrypted = new EnvelopeCodec().open(envelope, privateKey, rebuiltAad);

// query 规范化与摘要
String canonicalQuery = CanonicalQuery.canonicalize("b=2&a=1");   // "a=1&b=2"
String bodyHash = Digests.bodySha256Hex("GET", bodyBytes);        // GET/HEAD/DELETE 强制空体摘要
```

### 2.6 签名排障

生产上「签名失败但服务端不给诊断信息」是常见的排障场景(服务端出于安全考虑,验签失败时不
回显失败原因)。商户侧可以完全不发请求,只用 `RequestSigner` 在本地拿到 8 行规范串、其
SHA-256、最终的 Base64 签名,再逐行跟自己的理解核对——这是 SDK 已公开的「只签名不发送」
原语,字段名以下方示例为准。

```java
import com.slaunchx.plutus.sdk.crypto.Digests;
import com.slaunchx.plutus.sdk.signing.RequestSigner;
import com.slaunchx.plutus.sdk.signing.SignedRequest;
import com.slaunchx.plutus.sdk.signing.SigningInput;

import java.nio.charset.StandardCharsets;
import java.util.List;

byte[] bodyBytes = "{\"platformCardProductBizId\":\"pcp_xxx\"}".getBytes(StandardCharsets.UTF_8);
// GET/HEAD/DELETE 一律用空 body 摘要, 即使携带了 body
String bodyHash = Digests.bodySha256Hex("POST", bodyBytes);

SigningInput input = new SigningInput(
        "POST",                                            // method, 大写
        "/card-products/10010106/shared/cards/create",     // externalPath: 外部路径, 不含 /api/v1/consumer, 不含 /prometheus
        null,                                               // rawQuery: 无 query 传 null
        Long.toString(System.currentTimeMillis()),          // timestamp: 必须与 X-Timestamp 头同一个值, 毫秒级 Unix 时间戳
        nonce,                                              // nonce: 必须与 X-Nonce 头同一个值
        "1",                                                // apiVersion: 必须与 X-API-VERSION 头同一个值
        null,                                               // idempotencyKey: 不发送该头则传 null
        bodyBytes);                                         // body: 实际要发送的那份字节, 不是重新序列化的另一份

RequestSigner signer = new RequestSigner(merchantAuthPrivateKey);
SignedRequest signed = signer.sign(input);

// 逐行核对: RequestSigner.canonicalStringLines 是静态方法, 不需要私钥, 单独拿 8 行比对最方便
List<String> lines = RequestSigner.canonicalStringLines(input, bodyHash);
lines.forEach(System.out::println);

System.out.println("8 行规范串(LF 连接, 结尾无换行): " + signed.canonicalString());
System.out.println("规范串自身的 SHA-256(响应验签第 2 行要用): " + signed.requestCanonicalSha256());
System.out.println("X-Signature 的值: " + signed.signatureBase64());
```

逐行核对 checklist(按 `RequestSigner.canonicalStringLines` 的真实顺序,从上到下依次是):

1. **`method`**——HTTP 方法是否大写,与实际发出的方法一致。
2. **`externalPath`**——是否为外部路径:不含 `/api/v1/consumer`、不含 `/prometheus`。
   签名 PATH 只是 `SigningInput.externalPath()` 这一段,边缘/源站改写发生在这一层之外,
   SDK 与商户都不应把改写后的路径当作签名输入(见 [`baseUrl` 配置示例](#31-plutusconfigbuilder))。
3. **`canonicalQuery`**——是否已按「严格解码 → RFC 3986 重编码 → 按字节序排序」规范化。
   不要假设自己拼的原始 query 串已经排序、编码好;直接调用
   `CanonicalQuery.canonicalize(rawQuery)` 得到这一行的真实取值再比对。
4. **`timestamp`**——是否为毫秒级 Unix 时间戳(13 位十进制字符串,即
   `Long.toString(System.currentTimeMillis())` 的形式),且与 `X-Timestamp` 头发送的是
   同一个字符串。
5. **`nonce`**——是否与 `X-Nonce` 头发送的是同一个字符串,满足 `^[A-Za-z0-9._~-]{16,128}$`。
6. **`apiVersion`**——是否与 `X-API-VERSION` 头发送的是同一个字符串。
7. **`idempotencyKey`**——无幂等键时这一行是否为**空串**,而不是把 8 行拼成 7 行整行省略;
   `SigningInput` 的 `idempotencyKey` 为 `null` 时,`RequestSigner` 会把这一行填成空串。
8. **`bodySha256Hex`**——是否对**实际要发送的那份字节**求 SHA-256,而不是摘要一份、序列化
   另一份(不同 JSON 库或字段顺序会产出不同字节,摘要就会不同)。`GET` / `HEAD` / `DELETE`
   是否强制走空体摘要——即使这次调用给这些方法带了 body,也应使用
   `Digests.bodySha256Hex(method, body)` 而不是自行判断分支。

8 行以 LF(`\n`)连接,结尾无换行;`X-Signature-Algorithm` 是固定字面量 `RSA-SHA256`,
**不参与**规范串(详见 [6. 实现约定与易错点](#6-实现约定与易错点))。

---

## 3. 配置项

> 协议头由 SDK 自动补齐,调用方只需配置下列项;各字段是否进入签名串由下表说明标注。
> 平台**不读取** `X-Workspace-Id`,SDK 也不发送该头。

### 3.1 `PlutusConfig.builder()`

| 配置项 | 类型 | 默认值 | 必填 | 说明 |
| --- | --- | --- | --- | --- |
| `baseUrl` | `String` | 无 | 使用 `PlutusClient` 时必填 | 商户 API 基地址,**必须是对外 CONSUMER API 域名**,不能是源站地址,也不能自行拼接 `/prometheus`、`/api/v1/consumer` 前缀;不含路径,末尾斜杠自动去除。详见下方示例 |
| `apiKey` | `String` | 无 | 是 | API Key 业务 ID,写入 `X-Api-Key` |
| `apiVersion` | `String` | 无（必填） | 是 | 写入 `X-API-VERSION` 并参与签名;当前只服务 `1` |
| `merchantAuthPrivateKeyPem` | `String` | 无 | 是 | `merchant_auth` PKCS#8 私钥,用于请求签名 |
| `platformAuthPublicKeyPem` | `String` | 无 | 启用响应验签时必填 | `platform_auth` SPKI 公钥,用于响应与 Webhook 验签 |
| `merchantEncPrivateKeyPem` | `String` | 无 | 需要解密时必填 | `merchant_enc` PKCS#8 私钥,用于敏感响应与 Webhook 解密 |
| `merchantEncPublicKeyPem` | `String` | 从私钥推导 | 否 | 仅用于计算自身指纹;通常无需显式提供 |
| `platformEncPublicKeyPem` | `String` | 无 | 调用加密端点时必填 | `platform_enc` SPKI 公钥,用于加密请求体 |
| `verifyResponseSignature` | `boolean` | `true` | 否 | 关闭即放弃响应完整性保护,仅用于排障 |
| `requireSignatureOnErrorResponses` | `boolean` | `false` | 否 | 打开后非 2xx 响应缺签名头也抛验签异常;详见 [4.2](#42-响应缺签名头的处理策略) |
| `strictEncryptedRouteValidation` | `boolean` | `false` | 否 | 打开后加密端点 routeTemplate 未命中 `EncryptedRoutes` 已知表时抛 `PlutusException`;默认仅告警不阻断,详见 [2.3](#23-加密端点) |
| `nonceGenerator` | `NonceGenerator` | 32 字符十六进制 | 否 | 必须满足 `^[A-Za-z0-9._~-]{16,128}$` |
| `httpClient` | `HttpClient` | 连接超时 10 秒 | 否 | 自定义代理、TLS、连接池等 |
| `requestTimeout` | `Duration` | 30 秒 | 否 | 单次请求超时 |
| `objectMapper` | `ObjectMapper` | 新实例 | 否 | 自定义 JSON 序列化行为 |

公钥在解析时强校验:必须是 SPKI PEM、模数 2048–4096 位、公开指数恰为 65537、
DER 编码规范;不满足即抛 `PlutusConfigurationException`。

**`baseUrl` 配置示例。** 签名 PATH 是外部路径(如 `/card-products/10010106/shared/cards/create`);
边缘(Cloudflare/nginx)负责把外部路径改写为源站内部路径(如 `/api/v1/consumer/...`),源站还
另有 `/prometheus` context-path。这两层改写都发生在 `baseUrl` 之外,`baseUrl` 只能是商户对外
可访问的 CONSUMER API 域名:

```java
// 正确: baseUrl 是对外 CONSUMER API 域名, path 传外部路径, SDK 对外部路径签名
PlutusConfig.builder()
    .apiVersion("1")
        .baseUrl("https://<consumer-api-host>")
        .build();
client.call(PlutusRequest.post("/card-products/10010106/shared/cards/create")...);
// 实际请求: POST https://<consumer-api-host>/card-products/10010106/shared/cards/create

// 错误: baseUrl 配成源站地址并自行拼接边缘/源站前缀, 签名必然失败
PlutusConfig.builder()
    .apiVersion("1")
        .baseUrl("https://origin-host/prometheus/api/v1/consumer")
        .build();
```

生产环境曾出现的失败模式正是把 `baseUrl` 配成源站地址或自行拼 `/prometheus/api/v1/consumer`
前缀;`RequestSigner` 只对外部路径签名,`baseUrl` 配错不会在签名阶段报错,只会在平台侧验签
失败——排障方法见 [2.6 签名排障](#26-签名排障)。

### 3.2 `PlutusRequest.builder()`

| 配置项 | 说明 |
| --- | --- |
| `method(String)` | HTTP 方法,大写。`GET` / `HEAD` / `DELETE` 强制使用空 body 摘要 |
| `path(String)` | 外部路径,以 `/` 开头,不含 query 与链/版本/门户前缀 |
| `query(String)` | 直接给定原始 query 串,必须已按 RFC 3986 编码 |
| `queryParam(String, String)` | 追加参数,SDK 负责 percent 编码;与 `query(...)` 互斥 |
| `body(byte[])` / `body(String)` | 已序列化的 body,SDK 原样摘要并发送 |
| `jsonBody(Object)` | 交由 SDK 序列化一次;与 `body(...)` 互斥 |
| `contentType(String)` | 覆盖默认的 `application/json` |
| `idempotencyKey(String)` | 发送即参与签名;不设置则规范串第 7 行为空 |
| `requestId(String)` | 加密端点必填,省略时由 SDK 生成 |
| `encrypted(boolean)` | 标记为加密端点调用 |
| `header(String, String)` | 附加自定义头 |

### 3.3 `WebhookHandler.builder()`

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `platformAuthPublicKeyPem` | 无(必填) | 验签公钥 |
| `merchantEncPrivateKeyPem` | 无(必填) | 解密私钥 |
| `merchantEncPublicKeyPem` | 从私钥推导 | 用于校验信封 `keyFingerprint` |
| `expectedApiKeyBizId` | 必填 | 验签后校验 `X-SlaunchX-Key-Id`，AAD 使用本地值 |
| `timestampTolerance` | **关闭** | 协议契约未规定商户侧时间窗;需要时自行设定,SDK 不硬编码 ±60 秒 |
| `objectMapper` | 新实例 | 自定义 JSON 解析 |

---

## 4. 统一响应包络与成功判定

### 4.1 包络结构与判定算法

平台所有 API 响应共用一个包络结构:

```json
{
  "version": "2.0.0",
  "timestamp": 1755600000123,
  "success": true,
  "code": "2000",
  "message": "Success",
  "data": { }
}
```

`success` 是**布尔**字段,是成功与否的唯一权威。`ApiResponse.successful()` 的算法:

```
如果响应体是 JSON 对象, 且键 "success" 存在且其值是布尔类型:
    返回 该布尔值
否则:
    返回 200 <= httpStatus < 300
```

只有**布尔类型**的 `success` 才算权威;缺失、为 `null`、为字符串或数字一律回退到 HTTP 2xx。
SDK **不再**用 `code == 0` 判定成功。

`code` 是**字符串**。成功族为 `"2000"` `"2001"` `"2002"` `"2004"` `"2006"`,另有特殊成功码
`"2101"`(账号待审批:登录成功但不签发 JWT,`success` 仍为 `true`)。失败时,网关层错误码是
`域.名称` 形式(如 `API.SIGNATURE_INVALID`),业务层错误码是 4xxx / 5xxx 的数字字符串
(如 `"4022"` `"5001"`)。

`ApiResponse` 的访问器:

| 方法 | 说明 |
| --- | --- |
| `successful()` | 上述判定算法的结果 |
| `successFlag()` | `Optional<Boolean>`,仅当 `success` 为 JSON 布尔类型时有值 |
| `rawCode()` | 顶层 `code` 的原始字符串;数字业务码(如 `"4022"`)原样返回,不置空 |
| `message()` | 顶层 `message` |
| `version()` | 顶层 `version`;缺失为 `null` |
| `timestamp()` / `timestampMillis()` | 顶层 `timestamp`(Unix 毫秒),分别为 `OptionalLong` 与 `Long` |
| `errorCode()` | `Optional<PublicErrorCode>`;该枚举只登记 `域.名称` 形式的对外错误码,数字业务码返回空,原始值取 `rawCode()` |
| `data()` / `data(mapper, type)` | 业务载荷 |
| `raw()` | 原始 JSON 树 |

`code` / `message` 的主路径是包络的权威字段;历史上的宽松写法(`errorCode`、`error.code`、
`msg`、`error.message`)保留为**次级回退**,仅在权威字段缺失时生效。

`ResultCodes` 提供成功码常量与便利判定:

```java
import com.slaunchx.plutus.sdk.model.ResultCodes;

ResultCodes.SUCCESS_CODES;                  // {"2000","2001","2002","2004","2006","2101"}
ResultCodes.ACCOUNT_PENDING_APPROVAL;       // "2101"
ResultCodes.isSuccessCode(parsed.rawCode());
```

**这组常量仅作文档与便利用途,不是成功判定依据**;判定始终以 `success` 布尔字段为准。
需要区分「登录成功但账号待审批」时,判成功后再比对 `rawCode()` 是否为
`ResultCodes.ACCOUNT_PENDING_APPROVAL`。

### 4.2 响应缺签名头的处理策略

在 `verifyResponseSignature` 为 `true`(默认)的前提下:

| 情形 | 行为 |
| --- | --- |
| 响应带 `X-Response-Signature` | 强制验签;失败抛 `PlutusSignatureException` 并丢弃响应体 |
| HTTP 2xx 且缺签名头 | 抛 `PlutusSignatureException` |
| 非 2xx 且缺签名头 | 放行,`PlutusResponse.signatureVerified()` 为 `false`,按类型化 API 错误处理 |
| 非 2xx 且缺签名头,且 `requireSignatureOnErrorResponses(true)` | 抛 `PlutusSignatureException` |

严格开关是 `PlutusConfig.Builder.requireSignatureOnErrorResponses(boolean)`,**默认 `false`**。

SDK 不按状态码白名单(如 401 / 403)放行:平台契约未穷举哪些状态码不带响应签名,
故统一采用「2xx 必须有签名,非 2xx 默认放行」。这是 **SDK 约定,不是平台契约**。

被放行的响应,调用方必须自行检查 `signatureVerified()`:

```java
PlutusResponse response = client.request(req);
if (!response.signatureVerified()) {
    log.warn("响应未经验签, 仅可用于读取错误码: status={}", response.statusCode());
}
```

### 4.3 query 的实际发送形态

`PlutusClient` 发送到线上的是**规范化后的 query**,不是调用方给定的原样 query。
`PlutusClient.buildUri(...)` 使用 `SignedRequest.canonicalQuery()` 拼装 URI,
即参数按名称、再按值的字节序排序并统一 percent 编码后的结果。

**该行为不可配置**,SDK 未提供开关。举例:调用方写
`queryParam("status","IN_USE").queryParam("pageSize","20")`,线上实际发送的是
`?pageSize=20&status=IN_USE`。

规范化算法与签名规范串第 3 行使用的是同一个;平台对收到的原始 query 重新执行同一算法,
两者等价。若需要原样保留参数顺序,当前版本无法满足。

### 4.4 Webhook 时间戳容差

`WebhookHandler.Builder.timestampTolerance(Duration)` **可配置,默认关闭**(内部值为 `null`,
即不校验时间戳)。`WebhookHandler.fromConfig(config)` 构造的处理器同样默认关闭。

协议契约未规定商户侧应接受多大的 `X-SlaunchX-Timestamp` 偏差,规定的防重放手段是 AAD 绑定
与按 `deliveryBizId` 去重,因此 SDK 不硬编码 ±60 秒。需要时显式设定:

```java
WebhookHandler handler = WebhookHandler.builder()
        .platformAuthPublicKeyPem(readPem("platform_auth_public.pem"))
        .merchantEncPrivateKeyPem(readPem("merchant_enc_private.pem"))
        .expectedApiKeyBizId("apk_xxxxxxxx")
        .timestampTolerance(Duration.ofMinutes(5))   // 可选, 不设即不校验
        .build();
```

---

## 5. 错误与重试

| 异常 | 触发场景 |
| --- | --- |
| `PlutusException` | 请求描述自身不合法,如外部路径不以 `/` 开头、`body` 与 `jsonBody` 同时给定,以及 `strictEncryptedRouteValidation(true)` 时加密端点 routeTemplate 未命中 `EncryptedRoutes` 已知表 |
| `PlutusConfigurationException` | 配置缺失、PEM 不合规、公钥不满足 SPKI / 位长 / 指数约束 |
| `PlutusCanonicalizationException` | query 含裸保留字符、裸非 ASCII、非法 percent 转义或非法 UTF-8 |
| `PlutusSignatureException` | 签名生成失败,或响应验签失败(响应体已丢弃) |
| `PlutusCryptoException` | AAD 不匹配、算法标识不符、GCM 认证失败、明文超过 1 MiB |
| `PlutusWebhookException` | Webhook 头缺失、验签失败、信封形状不合规、解密失败、明文交叉校验不通过 |
| `PlutusApiException` | 成功判定为失败(见 [4.1](#41-包络结构与判定算法));`errorCode()` 给出 `PublicErrorCode`,数字业务码取 `response().rawCode()` |
| `PlutusTransportException` | 连接、超时、中断等传输层失败 |

重试规则:`PublicErrorCode.retryable()` 标注建议重试的错误族
(`API.TIMESTAMP_EXPIRED`、`API.NONCE_REUSED`、`REQUEST.RATE_LIMITED`、`SYSTEM.INTERNAL_ERROR`)。
**重试必须重新生成时间戳与 nonce 并重新签名**——`PlutusClient` 每次调用都会重新生成,
直接再调用一次即可;业务幂等靠 `X-Idempotency-Key`,不靠复用签名。

响应验签的行为见 [4.2](#42-响应缺签名头的处理策略)。

---

## 6. 实现约定与易错点

- **body 只序列化一次。** `jsonBody(...)` 由 SDK 序列化后同时用于摘要与发送;若自行序列化,
  请用 `body(byte[])` 传入同一个数组。
- **`PlutusClient` 发送的是规范化后的 query,不是原样 query**,且不可配置。平台会对收到的
  query 重新执行同一算法,结果等价。详见 [4.3](#43-query-的实际发送形态)。
- **成功判定只看 `success` 布尔字段**,缺失时才回退 HTTP 2xx;`code` 不参与判定。
- **`+` 不是空格。** 空格写 `%20`,字面加号写 `%2B`;原始 `+` 会被本地拒绝而不是回退处理。
- **`GET` / `HEAD` / `DELETE` 一律用空 body 摘要**,即使携带了 body。
- **`X-Signature-Algorithm` 不参与签名**,只是固定字面量 `RSA-SHA256`。
- **响应 `Content-Type` 取原值**,不做归一化;`application/json` 与
  `application/json;charset=UTF-8` 会产生不同的签名。
- **响应规范串第 2 行本地计算**,由 `SignedRequest.requestCanonicalSha256()` 提供。
- **三处 AAD 不可混用**:加密请求的 `routeTemplate` 是外部路径,敏感响应是空串,
  Webhook 是字面量 `webhook`;Webhook 的 `keyId` 是 API Key 业务 ID 而非指纹。
- **Webhook body 摘要是 Base64**,API 链是小写 hex;SDK 分别由
  `Digests.sha256Base64` 与 `Digests.sha256Hex` 提供,不要复用同一个函数。
- **信封回显的 `aad` 只用于比对**,GCM 解密始终使用本地重建的 AAD。

---

## 7. 测试

```bash
cd java
mvn test
```

测试直接加载 `../shared/test-vectors.json`,覆盖全部向量组:

| 向量组 | 条数 | 断言 |
| --- | --- | --- |
| `canonicalQuery` | 21 | 逐条比对,6 条拒绝用例必须抛 `PlutusCanonicalizationException` |
| `bodyHash` | 7 | 逐条比对,含 GET / DELETE 强制空体 |
| `requestSignature` | 7 | 规范串逐行比对、绑定摘要复算、签名逐字节相等、公钥验签 |
| `responseSignature` | 3 | 规范串逐行比对、验签、绑定摘要由请求向量本地复算(向量 body 不用于成功判定) |
| `encryptedEnvelope` | 3 | AAD 重建比对、解密比对明文,外加加密方向 round-trip 自测 |
| `webhook` | 2 | 规范串与 Base64 摘要比对、验签、信封形状、AAD 重建、解密比对明文 |

另含负向用例(篡改规范串任意一行、篡改 AAD 任一分量、篡改密文与 body、归一化
`Content-Type`、伪造响应签名)与一组基于 JDK 内置 HTTP 服务器的端到端联通性测试。

统一响应包络的成功判定由 `UnifiedEnvelopeTest` 用本地 fixture 覆盖(标准成功、创建成功、
待审批成功、HTTP 200 的业务失败、网关失败、无 `success` 字段的 2xx / 5xx 回退)。
缺签名头的四种情形与「签名字节 == 发送字节」不变量由 `PlutusClientEndToEndTest` 覆盖
(`signedBytesEqualSentBytes` / `signedBytesEqualSentBytesForEncryptedRequest`)。

跨语言一致性可用仓库自带的独立校验器复核:

```bash
pip install cryptography
python3 ../shared/tools/verify_vectors.py --verbose
```

---

## 8. 安全提示

- 私钥不写入日志、异常消息与仓库;SDK 的异常消息不含密钥材料与解密后的明文。
- `shared/test-vectors.json` 中的 4 对 RSA 私钥仅供跨语言一致性校验,**绝不可用于任何真实环境**。
- 响应验签失败即安全事故:丢弃响应体,不要把未验证的数据交给业务代码。
- Webhook 必须按 `deliveryBizId` 去重,并交叉校验明文的 `deliveryBizId` / `eventType` 与
  `payloadSchemaVersion`(SDK 已内建该校验)。

`X-API-VERSION` 必须由调用方通过版本配置显式填写，没有默认值；当前 product 填 `1`。遗漏、空串或纯空白会在本地报错。


## Webhook 接收方校验修复版本

修复源码版本：`f16cdbf`；语言包尚未发布，安装源码需包含此提交。PHP 对应修复为 `58a2893`。

`WebhookHandler.builder().expectedApiKeyBizId(...)` 现在必填，不允许遗漏、空串或纯空白。必须配置本地登记的 API Key 业务 ID，不能从当前投递头动态赋值，也不是公钥指纹。

处理器先验证签名，再将 `X-SlaunchX-Key-Id` 与本地 API Key 比较；不一致即拒绝。AAD 第四段使用已核对的本地 API Key，两个 API Key 即使共用同一对加密密钥也不能互收投递。product 的 Webhook 签名规范串、信封和 AAD 四段协议没有改变。

旧版本的接收方配置可选，调用方必须显式设置上述配置才能启用比较；无法升级时应确保验签后、解密前比较接收方，不得只凭解密成功认定投递属于本地 API Key。

`WebhookHandler.fromConfig(config)` 继续从 `PlutusConfig.apiKey()` 取得本地 API Key，无需再单独配置。
