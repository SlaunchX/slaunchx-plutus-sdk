# SlaunchX Plutus 商户 PHP SDK

协议 `SLAUNCHX-PLUTUS-API-V1` 的 PHP 实现,覆盖商户对外 API 的**传输层**:请求签名、
通用 HTTP 客户端、响应验签、混合加密信封与 Webhook 接收。本 SDK **不建立业务端点模型**,
端点路径与请求体由调用方给出。

实现依据为协议 `SLAUNCHX-PLUTUS-API-V1` 与 `shared/test-vectors.json`(由服务端参考实现
生成,`shared/tools/verify_vectors.py` 可独立复算验证)。

## 环境要求

| 项 | 要求 |
| --- | --- |
| PHP | >= 8.1 |
| 扩展 | `ext-openssl`、`ext-curl`、`ext-json` |
| 第三方依赖 | **无**(仅开发期依赖 `phpunit/phpunit`) |

RSA-OAEP-SHA256 由 SDK 在 `OPENSSL_NO_PADDING` 之上自行完成 EME-OAEP 编解码
(`SlaunchX\Plutus\Support\Oaep`),因此不需要 phpseclib。原因见文末「实现说明」。

## 安装

SDK 位于仓库的 `php/` 子目录。将交付的完整 SDK 放到客户项目同级目录，用 path 仓库安装：

```json
{
    "repositories": [{"type": "path", "url": "../slaunchx-plutus-sdk/php"}],
    "require": {"slaunchx/plutus-sdk": "@dev"}
}
```

```sh
composer update slaunchx/plutus-sdk
```

保留 `composer.lock`，同时固定 SDK 源码提交并保留该路径。当前未发布 Packagist 稳定包；仅锁定 Composer 文件不能固定另一个本地目录的内容。

## 选择服务端协议

| 配置 | 请求签名 | 响应验签 | 适用范围 |
| --- | --- | --- | --- |
| `ProtocolProfile::PRODUCT_V1` | 7 行，不含幂等键行 | 5 行 | 当前 product 部署协议 |
| `ProtocolProfile::REQUEST_BOUND_V1`（默认） | 8 行，含幂等键行 | 10 行，绑定本次请求 | 原有请求绑定协议 |

本次 PHP 适配使用 `PRODUCT_V1`。必须按目标环境明确选择；SDK 不在验签失败后自动切换协议。
`PRODUCT_V1` 仍发送 `X-API-VERSION: 1`，对应后端启用 API 版本校验的配置，不适用于关闭版本校验的旧 6 行模式。

`PRODUCT_V1` 会为未指定 requestId 的请求自动生成 `X-Request-Id`。响应缺少这个头时，SDK 使用本次实际发送并保留的 requestId 重建响应规范串，仍完整验证 RSA 签名；响应已带该头时使用响应值，验签失败不会再尝试其他 ID。调用方显式指定 ID 时应保证每次独立请求使用唯一值。若代理改写了请求 ID 且响应未回传实际值，仍会验签失败。`REQUEST_BOUND_V1` 行为保持原样。

兼容只作用于验签输入，`ApiResponse::requestId()` 仍反映实际响应，因此缺少响应头时可能为 null。

product 请求签名依次为：方法、外部路径、规范化 Query、时间戳、Nonce、API 版本、Body SHA-256。
幂等键作为请求头发送，由服务端处理，但不进入这套请求签名。
product 响应签名依次为：请求 ID、HTTP 状态码、Content-Type、响应时间戳、Body SHA-256。
这套旧协议本身不含请求摘要绑定；SDK 严格校验服务端提供的 5 行签名，不声明具备 10 行协议的绑定能力。

可运行的完整初始化和 GET/POST 只读示例见 [`examples/product-readonly.php`](examples/product-readonly.php)。
后文静态方法和黄金向量默认仍描述 `REQUEST_BOUND_V1`；手工排障 product 时需向静态方法传入对应 profile。

## 快速开始

### 1. 构造配置

```php
use SlaunchX\Plutus\PlutusClient;
use SlaunchX\Plutus\PlutusConfig;
use SlaunchX\Plutus\ProtocolProfile;

$config = new PlutusConfig(
    protocolProfile: ProtocolProfile::PRODUCT_V1,
    baseUrl: 'https://consumer-api.example.com',
    apiKey: 'apk_xxxxxxxxxxxx',
    merchantAuthPrivateKeyPem: file_get_contents('/secure/merchant_auth_private.pem'),
    platformAuthPublicKeyPem: file_get_contents('/secure/platform_auth_public.pem'),
    // 普通只读查询只需以上两份鉴权密钥；加密接口再配置加密密钥。
);

$client = new PlutusClient($config);
```

`baseUrl` 必须是**对外 CONSUMER API 域名**,不能填源站地址,也不能自行拼接
`/prometheus`、`/api/v1/consumer` 等内部前缀——这些改写由边缘 (Cloudflare/nginx) 完成,
SDK 只对外部路径签名。baseUrl 配错是生产环境验签失败最常见的单点
根因:

```php
// 正确: baseUrl 是对外 CONSUMER API 域名, path 传外部路径
baseUrl: 'https://consumer-api.example.com'
$client->requestEncrypted('POST', '/card-products/10010106/shared/cards/create', $payload);
// 实际请求 https://consumer-api.example.com/card-products/10010106/shared/cards/create
// 边缘改写为源站内部路径 /api/v1/consumer/card-products/10010106/shared/cards/create,
// 但签名 PATH 只用外部路径 /card-products/10010106/shared/cards/create。

// 错误: baseUrl 填了源站地址并自行拼接内部前缀, 签名 PATH 与边缘改写后的实际请求路径不一致, 验签必然失败
baseUrl: 'https://origin-host.internal/prometheus/api/v1/consumer'
```

四把密钥职责严格分离,不得混用:

| 配置项 | 密钥 | 用途 |
| --- | --- | --- |
| `merchantAuthPrivateKeyPem` | `merchant_auth` 私钥 | 对请求规范串签名(必填) |
| `platformAuthPublicKeyPem` | `platform_auth` 公钥 | 校验响应签名与 Webhook 签名 |
| `merchantEncPrivateKeyPem` | `merchant_enc` 私钥 | 解密敏感响应与 Webhook 载荷 |
| `platformEncPublicKeyPem` | `platform_enc` 公钥 | 加密请求体 |

### 2. 明文签名调用

路径必须是**外部路径**:不含 `/api`、不含 `/v1`、不含门户段;版本走 `X-API-VERSION` 头。

```php
// GET,query 由 SDK 规范化后参与签名
$response = $client->get('/card-products/cards/page', [
    'query' => ['page' => 0, 'size' => 20, 'status' => 30060203],
]);

$rows = $response->dataPath('items', []);

// POST,body 由 SDK 一次性序列化,摘要与实际发送使用同一字节串
$response = $client->post('/card-products/groups/list', [
    'json' => ['isActive' => true],
]);
```

若业务侧已经自行序列化了 body,改用 `body` 选项传入**已序列化的字符串**,
不要让 SDK 二次序列化:

```php
$payload = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$client->post('/card-products/cards/remark/update', ['body' => $payload]);
```

`GET` / `HEAD` / `DELETE` 一律使用空 body 摘要,即使请求携带了 body。

### 3. 加密端点调用

协议标注为加密的端点(见下文 `EncryptedRoutes::ROUTES`)用 `requestEncrypted()`。SDK 负责生成信封、
组装 `X-Request-Id` 与 `X-Platform-Encryption-Key-Id`,并对**信封字节**签名:

```php
$response = $client->requestEncrypted(
    'POST',
    '/card-products/10010106/shared/cards/create',
    [
        'platformCardProductBizId' => 'pcp_example_001',
        'quantity' => 2,
    ],
    ['idempotencyKey' => 'idem-20260830-0002'],
);
```

已知的加密端点收录在 `SlaunchX\Plutus\EncryptedRoutes::ROUTES`,
`EncryptedRoutes::isKnown()` 可查询某外部路径是否在表中。`requestEncrypted()` 对不在表中的
外部路径:默认(`PlutusConfig::$strictEncryptedRouteValidation = false`)只用 `error_log`
记录一条提示、不阻断请求——平台新增加密端点时若常量表更新滞后,严格校验会让 SDK
本身卡死商户请求;需要强校验的商户可显式打开该开关,未知路由会抛出
`Exception\ConfigurationException`。

### 4. 敏感响应解密

部分端点在响应体中返回信封而非明文字段:

```php
$response = $client->get('/card-products/cards/sensitive', [
    'requestId' => $requestId,
]);

$plaintext = $client->decryptSensitiveResponse($response);
$card = json_decode($plaintext, true);
```

AAD 的 `routeTemplate` 位固定为空串;平台生成的时间戳从信封回显的 `aad` 解析,
SDK 用它连同本地已知的 `requestId` 与 `merchant_enc` 指纹重建 AAD 并逐字节比对,
比对通过后才用**重建的** AAD 解密。

### 5. 接收 Webhook

```php
use SlaunchX\Plutus\WebhookHandler;
use SlaunchX\Plutus\Exception\WebhookException;

$handler = new WebhookHandler($config);

$rawBody = file_get_contents('php://input');   // 必须取原始字节, 不可先 json_decode 再重编码
$headers = getallheaders();

try {
    $event = $handler->handle($headers, $rawBody);
} catch (WebhookException $exception) {
    http_response_code(400);
    return;
}

// 按 deliveryBizId 去重: 自动重试与人工重放共用同一个 deliveryBizId
if ($store->alreadyProcessed($event->deliveryBizId)) {
    http_response_code(200);
    return;
}

match ($event->eventType) {
    'card.issuance' => $service->onIssuance($event->data()),
    'card.status'   => $service->onStatusChange($event->data()),
    default         => null,
};

http_response_code(200);
```

`handle()` 依次完成:验签(body 摘要用 **Base64**)→ 校验信封形状(有 `envelopeVersion`,
无 `encryptedPayload`)→ 重建 AAD(第 2 位固定字面量 `webhook`,第 4 位是 **API Key 业务 ID**
而非指纹)→ 解密 → 与传输头交叉校验。**去重由调用方负责**。

载荷中的金额形如 `{"currency":"USD","amount":"25.80"}`,`amount` 是十进制字符串,
不得解析为浮点数。

## 签名排障

平台验签失败时**不返回诊断信息**,商户只能靠客户端自检。`RequestSigner` 已经公开了
「只签名不发送」的原语,自检时不需要真的发起 HTTP 请求。

### 拿到所选协议的规范串、其 SHA-256 与最终签名

最简单的方式是用 `PlutusClient::signer()` 拿到的 `RequestSigner` 实例调用 `sign()`,
返回的 `SignedRequest` 即包含规范串、逐行拆分、规范串自身摘要与 Base64 签名,
且**不会发出任何 HTTP 请求**:

```php
use SlaunchX\Plutus\PlutusClient;
use SlaunchX\Plutus\PlutusConfig;

$config = new PlutusConfig(/* ... */);
$client = new PlutusClient($config);

$signed = $client->signer()->sign(
    'POST',
    '/card-products/10010106/shared/cards/create',
    body: json_encode(
        ['platformCardProductBizId' => 'pcp_example_001', 'quantity' => 2],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    ),
);

foreach ($signed->canonicalStringLines() as $i => $line) {
    printf("第 %d 行: %s\n", $i + 1, $line);
}
echo "规范串 SHA-256: {$signed->requestCanonicalSha256}\n";
echo "Base64 签名: {$signed->signature}\n";
echo "X-Timestamp: {$signed->timestamp}, X-Nonce: {$signed->nonce}\n";
```

不想构造完整 `PlutusConfig` / `PlutusClient` 时,也可以直接用 `RequestSigner` 的静态方法
逐步手工拼接(适合只想核对某一行怎么算出来的场景):

```php
use SlaunchX\Plutus\RequestSigner;
use SlaunchX\Plutus\Support\Keys;

$canonicalQuery = RequestSigner::canonicalizeQuery('status=30060203&size=20'); // -> size=20&status=30060203
$bodyHash = RequestSigner::bodyDigestHex('GET', null); // GET 强制空 body 摘要

$canonicalString = RequestSigner::buildCanonicalString(
    'GET',
    '/card-products/cards/page',
    $canonicalQuery,
    '1755600000123',              // Unix 毫秒
    'nonce-abcdefgh12345678',     // 满足 ^[A-Za-z0-9._~-]{16,128}$
    '1',                          // apiVersion
    null,                         // 无幂等键: 该行是空串, 不是整行省略
    $bodyHash,
);

$digest = RequestSigner::canonicalStringDigest($canonicalString);

$privateKey = Keys::loadPrivateKey(file_get_contents('/secure/merchant_auth_private.pem'));
$signature = RequestSigner::signCanonicalString($canonicalString, $privateKey);
```

### 逐行核对 checklist

`REQUEST_BOUND_V1` 规范串按 `RequestSigner::buildCanonicalString()` 的顺序为 8 行(LF 连接,无尾换行):

| 行号 | 内容 | 常见错误 |
| --- | --- | --- |
| 1 | HTTP 方法(大写) | 混用大小写(SDK 内部已强制大写,自建规范串时别漏) |
| 2 | 外部路径 | **误填内部路径**:不得含 `/api/v1/consumer` 前缀,也不得含 `/prometheus`;必须是商户实际请求的外部路径,逐字节一致 |
| 3 | 规范化 query | 未按「RFC 3986 全量百分号编码、按 `key` 再 `value` 字节序排序」处理;无 query 时是空串,不是省略该行 |
| 4 | 时间戳 | 不是 Unix **毫秒**(常见错误是秒级 10 位而非 13 位);与 `X-Timestamp` 头不一致 |
| 5 | nonce | 与 `X-Nonce` 头不一致;不满足 `^[A-Za-z0-9._~-]{16,128}$` |
| 6 | apiVersion | 与 `X-API-VERSION` 头不一致(当前恒为 `"1"`) |
| 7 | 幂等键 | **无幂等键时该行必须是空串,而不是整行省略**;发了 `X-Idempotency-Key` 却不参与签名 |
| 8 | body 摘要 | 对**实际要发送的字节**求 SHA-256 而不是对业务对象重新序列化一次(重新序列化可能改变字段顺序/转义,产生不同字节);`GET` / `HEAD` / `DELETE` **无论是否带 body 都强制用空 body 摘要**(`RequestSigner::EMPTY_BODY_SHA256`),不能对其 body 实际求哈希 |

自检步骤建议:

1. 用上面的代码在本地对同一笔请求签名,逐行 diff `canonicalStringLines()` 与自己实现
   (或其他语言 SDK)算出的 8 行,定位第一处不一致的行号。
2. 确认 `baseUrl` 语义正确(见「配置项」`baseUrl` 一行与「快速开始」示例)——第 2 行
   外部路径必须和签名时用的路径完全一致,与 `baseUrl` 拼接后才是实际发出的 URL。
3. body 摘要对不上时,优先检查是否发生了「二次序列化」:SDK 的 `json` 选项只序列化
   一次,若调用方在别处又手工 `json_encode` 了一份不同字节的 body 传给 `body` 选项,
   摘要会对不上实际发送的字节。

## 统一响应包络与成功判定

平台响应统一使用如下包络:

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

- `success` 是**布尔**字段,是成功与否的唯一权威。
- `code` 是**字符串**。成功族为 `2000` `2001` `2002` `2004` `2006`,以及 `2101`
  (账号待审批:登录成功但不签发 JWT,`success` 仍为 `true`)。
  失败时网关层是 `域.名称`(如 `API.SIGNATURE_INVALID`),业务层是 4xxx/5xxx 的
  数字字符串(如 `4022`)。
- `message` 是错误或提示消息。

`ApiResponse::isSuccess()` 的判定算法:

1. 响应体是 JSON 对象、`success` 键存在且其值是 **JSON 布尔类型** → 返回该布尔值;
2. 否则 → 返回 `200 <= HTTP 状态码 < 300`。

`success` 缺失、为 `null`、为字符串或数字一律走第 2 步的 HTTP 回退。SDK **不使用**
`code == 0` 之类的判定。因此 HTTP 200 且 `success:false` 会被判为失败并抛出类型化异常。

```php
$response = $client->get('/card-products/cards/page', [
    'query' => ['size' => 20],
]);

$response->isSuccess();     // bool, 按上述算法
$response->successFlag();   // ?bool, 仅 JSON 布尔时非 null; 用于区分"权威判定"与"HTTP 回退"
$response->code();          // ?string, 权威 code, 成功响应也能读到 "2000" / "2101"
$response->errorCode();     // ?string, 成功时为 null; 失败时为 code 的字符串形式
$response->errorMessage();  // ?string, 取 message
$response->version();       // ?string, 如 "2.0.0"
$response->timestampMs();   // ?int, 包络时间戳 (Unix 毫秒)
$response->data();          // mixed, data 段
```

成功码常量仅供文档与便利用途,**不参与**成功判定:

```php
use SlaunchX\Plutus\Model\ResultCodes;

ResultCodes::SUCCESS_CODES;                 // ['2000','2001','2002','2004','2006','2101']
ResultCodes::ACCOUNT_PENDING_APPROVAL;      // '2101', 账号待审批, 属于成功码
ResultCodes::isSuccessCode($response->code() ?? '');

// 判定成功仍然只看 isSuccess():
if ($response->code() === ResultCodes::ACCOUNT_PENDING_APPROVAL) {
    // 登录成功但账号待审批, 此次不会签发 JWT
}
```

数字业务错误码不会因为"看起来是数字"而被丢弃:`code` 为 `"4022"` 时
`errorCode()` 返回 `"4022"`,异常侧从 `ApiException::rawErrorCode()` 取得同一值。

## 响应验签与缺签名头策略

响应验签由 `verifyResponseSignature` 控制,默认开启。开启时:

| 情形 | 行为 |
| --- | --- |
| 响应带 `X-Response-Signature` | 强制验签;失败抛 `ResponseSignatureException` 并丢弃响应体 |
| HTTP 2xx 且缺签名头 | 抛 `ResponseSignatureException` |
| 非 2xx 且缺签名头 | 放行;`ApiResponse::$signatureVerified === false`;按类型化 API 错误返回或抛出 |
| 非 2xx 且缺签名头,且 `requireSignatureOnErrorResponses = true` | 抛 `ResponseSignatureException` |

严格开关是 `PlutusConfig::$requireSignatureOnErrorResponses`,**默认 `false`**。
SDK 不按状态码白名单(401/403 等)放行:平台契约只说明认证失败等场景的响应可能不带
签名头,并未穷举无签名的状态码集合,因此改用"2xx 必须有签名、非 2xx 默认放行"的
统一策略——这是 SDK 自身约定,不是平台强制契约。

被放行的响应务必检查 `signatureVerified`:

```php
$response = $client->get('/card-products/cards/page');
if (!$response->signatureVerified) {
    // 响应未经验签, 不得据此做资金或授权决策
}
```

## Query 发送形态

SDK 默认发送规范化后的 Query（`sendCanonicalQuery=true`），URL Query 与参与签名的内容一致。

- `REQUEST_BOUND_V1`：严格 RFC 3986 编码，按编码后的 key/value 排序。
- `PRODUCT_V1`：按 Java form 规则解码（裸 `+` 为一个空格），按解码后的 UTF-16 key/value 排序，再编码；`~` 编为 `%7E`、`*` 保留、空格编为 `%20`。

推荐传数组，例如 `['page' => 0, 'size' => 20, 'status' => 30060203]`。数组中真正的 `+` 会先编码为 `%2B`，不会变成空格。
`PRODUCT_V1` 对非法 percent 转义和非法 UTF-8 提前报错，不复刻旧后端对错误输入的宽松处理。
`sendCanonicalQuery=false` 时发送原始串，但签名依然按所选 profile 规范化。普通业务参数建议保留默认设置。

## 配置项

> 协议头由 SDK 自动补齐,调用方只需配置下表参数;各字段是否进入签名串由下表说明标注。
> 平台**不读取** `X-Workspace-Id`,SDK 也不发送该头。

| 参数 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `baseUrl` | `string` | — | 商户 API 基址,须以 `http://` 或 `https://` 开头,**必须是对外 CONSUMER API 域名**,不能是源站地址,不能自行拼接 `/prometheus`、`/api/v1/consumer` 前缀(见「快速开始」一节的正确/错误示例) |
| `apiKey` | `string` | — | `X-Api-Key` 的值(API Key 业务 ID) |
| `merchantAuthPrivateKeyPem` | `string` | — | 商户认证私钥(PKCS#8 PEM) |
| `platformAuthPublicKeyPem` | `?string` | `null` | 平台认证公钥(SPKI PEM);开启响应验签时必填 |
| `merchantEncPrivateKeyPem` | `?string` | `null` | 商户加密私钥;敏感响应与 Webhook 解密所需 |
| `platformEncPublicKeyPem` | `?string` | `null` | 平台加密公钥;请求加密所需 |
| `platformEncKeyId` | `?string` | `null` | 平台加密公钥指纹;为空时从 PEM 推导 |
| `platformAuthKeyId` | `?string` | `null` | 平台认证公钥指纹;非空时与 `X-Platform-Signing-Key-Id` 比对 |
| `apiVersion` | `string` | `'1'` | `X-API-VERSION` 的值,参与签名 |
| `verifyResponseSignature` | `bool` | `true` | 是否校验响应签名 |
| `requireSignatureOnErrorResponses` | `bool` | `false` | 非 2xx 缺签名头时是否也强制验签;2xx 缺签名头一律报错,不受本开关影响 |
| `throwOnErrorStatus` | `bool` | `true` | 响应判定为失败时抛出类型化异常,而非返回响应对象 |
| `sendCanonicalQuery` | `bool` | `true` | 发送规范化后的 query 而非原始串(两者在平台侧等价) |
| `connectTimeoutMs` | `int` | `5000` | 连接超时(毫秒) |
| `protocolProfile` | `ProtocolProfile` | `REQUEST_BOUND_V1` | 目标 product 使用 `PRODUCT_V1`，明确选择，不自动降级 |
| `timeoutMs` | `int` | `30000` | 整体超时(毫秒) |
| `userAgent` | `string` | `slaunchx-plutus-php-sdk/1.0` | `User-Agent` 请求头 |
| `webhookTimestampToleranceMs` | `int` | `0` | Webhook 时间戳容差(毫秒);`0` 表示不校验 |
| `nonceGenerator` | `?Closure` | `null` | 自定义 nonce 生成器 `fn(): string` |
| `clock` | `?Closure` | `null` | 自定义时钟 `fn(): string`,返回 Unix 毫秒十进制串 |
| `curlOptions` | `array` | `[]` | 追加的 cURL 选项,覆盖 SDK 默认值 |
| `strictEncryptedRouteValidation` | `bool` | `false` | 加密请求的外部路径不在 `EncryptedRoutes::ROUTES` 已知表中时是否直接拒绝;默认仅 `error_log` 提示不阻断(见「加密端点调用」一节) |

Webhook 时间戳容差由 `webhookTimestampToleranceMs` 配置,**默认 `0`,即关闭校验**:
协议未规定商户侧应接受多大的时间戳偏差,防重放依赖 AAD 常量
时间比对与 `deliveryBizId` 去重。需要收紧时按自身时钟精度显式设置,例如 `60000`
表示只接受 ±60 秒内的 Webhook。

## 错误处理

响应判定为失败(`ApiResponse::isSuccess()` 为 `false`)且 `throwOnErrorStatus` 开启时,
抛出 `ApiException` 的子类。触发条件是业务判定,不是 HTTP 状态码:HTTP 200 且包络
`success:false` 同样抛出。

| 异常 | 触发条件 |
| --- | --- |
| `AuthenticationException` | `API.KEY_*` / `API.TIMESTAMP_*` / `API.NONCE_*` / `API.SIGNATURE_*`,或 401 |
| `PermissionException` | `ACCESS.PERMISSION_DENIED` / `API.IP_NOT_ALLOWED` / `API.WORKSPACE_UNAVAILABLE`,或 403 |
| `ValidationException` | `VALIDATION.INVALID_PARAMETER` / `API.VERSION_*`,或其余 4xx |
| `NotFoundException` | `RESOURCE.NOT_FOUND`,或 404 |
| `ConflictException` | `REQUEST.CONFLICT` / `REQUEST.STALE_VERSION`,或 409 |
| `RateLimitException` | `REQUEST.RATE_LIMITED`,或 429;提供 `retryAfterSeconds()` |
| `SecureChannelException` | `SECURE_CHANNEL.INVALID_PAYLOAD` |
| `ServerException` | `SYSTEM.INTERNAL_ERROR`,或 5xx |

选型先看错误码,未收录的码(含 4xxx/5xxx 数字业务码)按 HTTP 状态码回退;HTTP 2xx
且业务判定失败时没有更精确的状态线索,回退为基类 `ApiException`。原始码始终可从
`ApiException::rawErrorCode()` 取得,`ApiException::errorCode()` 只在码已收录进
`PublicErrorCode` 时非 null。

```php
use SlaunchX\Plutus\Exception\ApiException;

try {
    $client->post('/card-products/cards/freeze', ['json' => $payload]);
} catch (ApiException $exception) {
    $exception->statusCode();    // int, HTTP 状态码
    $exception->rawErrorCode();  // ?string, 如 'API.SIGNATURE_INVALID' 或 '4022'
    $exception->errorCode();     // ?PublicErrorCode, 未收录时为 null
    $exception->requestId();     // ?string, 平台回显的 X-Request-Id
}
```

传输层与本地校验的异常独立于上表:

| 异常 | 含义 |
| --- | --- |
| `CanonicalizationException` | query 含裸保留字符、非法 percent 转义或非法 UTF-8,本地直接拒绝 |
| `ConfigurationException` | 密钥缺失、PEM 非法、外部路径含版本前缀、nonce 不合规 |
| `ResponseSignatureException` | 响应验签失败或应有签名而缺失;响应体已丢弃 |
| `EnvelopeException` | 信封结构非法、AAD 不匹配、GCM 认证失败、明文超过 1 MiB |
| `WebhookSignatureException` / `WebhookPayloadException` | Webhook 验签 / 解密与交叉校验失败 |
| `TransportException` | cURL 连接失败、超时、TLS 握手失败 |

重试规则:`API.TIMESTAMP_EXPIRED`、`API.NONCE_REUSED`、429 与 5xx 可重试,
**重试必须重新生成 timestamp + nonce 并重新签名**,业务幂等靠 `X-Idempotency-Key`。
`ApiException::isRetryable()` 已封装该判断。

## 底层 API

需要脱离内置 HTTP 客户端时可直接使用各组件:

```php
use SlaunchX\Plutus\RequestSigner;
use SlaunchX\Plutus\ResponseVerifier;
use SlaunchX\Plutus\EnvelopeCodec;

$signed = (new RequestSigner($config))->sign('POST', '/card-products/cards/freeze', body: $payload);
$signed->headers;          // 完整请求头
$signed->canonicalString;  // 所选协议的规范串, 排障时逐行比对
```

接入自有 HTTP 栈时实现 `SlaunchX\Plutus\Http\TransportInterface` 并传给 `PlutusClient`
的第二个构造参数即可。实现必须**原样发送**传入的 body 字节。

## 测试

```bash
composer install
composer test
```

测试直接加载 `../shared/test-vectors.json`,覆盖 `canonicalQuery`(21 例,含 6 例拒绝断言)、
`bodyHash`(7)、`requestSignature`(7,规范串逐行 + 签名逐字节比对)、
`responseSignature`(3)、`encryptedEnvelope`(3 + 加密方向 round-trip)、`webhook`(2),
并附加篡改规范串 / 篡改 AAD 的负向断言。

包络成功判定与缺签名头策略用本地 fixture 覆盖(`tests/UnifiedEnvelopeTest.php` 与
`tests/PlutusClientTest.php`);「签名字节 == 发送字节」不变量由
`PlutusClientTest::testSignedBodyBytesAreExactlyTheTransmittedBytes()` 与
`testEncryptedRequestSignsExactlyTheTransmittedEnvelopeBytes()` 断言。

## 实现说明

**为什么不引入 phpseclib。** 协议要求 `OAEP(hash=SHA-256, MGF1=SHA-256)`,而 PHP 的
`ext-openssl` 只暴露 `OPENSSL_PKCS1_OAEP_PADDING`,其摘要与 MGF1 均硬编码为 SHA-1,
且没有任何接口可以改写。SDK 因此在 `OPENSSL_NO_PADDING`(裸 RSA 模幂)之上自行实现
RFC 8017 的 EME-OAEP 编解码与 MGF1(`Support\Oaep`),label 取空串。该路径由测试向量
的三条 `encryptedEnvelope` 与两条 `webhook` 解密用例、以及加密方向的 round-trip 覆盖。
结果是 SDK 运行期**零第三方依赖**,商户接入不引入额外供应链面。

AES-256-GCM 使用 `openssl_encrypt` / `openssl_decrypt`,密文布局固定为
`IV(12) || 密文 || 认证标签(16)`。
