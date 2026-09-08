# @slaunchx/plutus-sdk (Node.js / TypeScript)

## product 接入

接入 product 时显式选择以下配置；默认仍使用 Alpha 规则，不会在验签失败后自动切换。

```ts
import { ProtocolProfile } from '@slaunchx/plutus-sdk';
// 在 PlutusClient 配置中增加：
protocolProfile: ProtocolProfile.PRODUCT_V1
```

product 请求按 7 行签名、响应按 5 行验签。URL 参数按 product 的排序和编码规则处理。SDK 自动发送并保存请求编号；响应缺少 `X-Request-Id` 时，用本次发送的编号验签。响应已有编号时使用返回值，验签失败仍报错。

这些改动仅在本地验证，尚未发布；下文未特别说明的协议细节和原有黄金向量使用默认 Alpha 规则。

SlaunchX Plutus 商户 API 的官方 Node.js SDK,实现协议 `SLAUNCHX-PLUTUS-API-V1`。

覆盖四层密码学处理与 Webhook:

| 能力 | 方向 | 机制 |
| --- | --- | --- |
| 请求签名 | 商户 → 平台 | RSA-SHA256 (PKCS#1 v1.5) 对 8 行规范串签名 |
| 请求加密 | 商户 → 平台 | RSA-OAEP-SHA256 + AES-256-GCM 混合信封 |
| 响应验签 | 平台 → 商户 | RSA-SHA256 对 10 行 `SLAUNCHX-API-RESPONSE-V1` 规范串验签 |
| 敏感响应解密 | 平台 → 商户 | 同一混合信封,`routeTemplate` 为空串 |
| Webhook | 平台 → 商户 | Base64 body 摘要验签 + 信封解密(`routeTemplate` 为 `webhook`) |

范围只到传输层:SDK 不封装任何业务端点模型,请求路径与请求/响应体结构由调用方给出。

- 运行时依赖:**零**。只使用 `node:crypto`、内置 `fetch` 与 `Buffer`。
- 运行环境:Node.js >= 18(需要内置 `fetch`);编译目标 ES2022。
- 产物:CommonJS + ESM 双份,附带 `.d.ts` 类型声明。
- 一致性依据:`shared/test-vectors.json`(由服务端参考实现生成,`shared/tools/verify_vectors.py` 可独立复算验证)。

---

## 安装

### 从 npm registry(尚未发布,占位)

```bash
npm install @slaunchx/plutus-sdk
```

> 该包目前**未发布到公共 registry**。上述命令在发布后可用;在此之前请用下面任一方式。

### 从 git 仓库

SDK 位于 monorepo 的 `node/` 子目录,npm 不支持直接安装 git 仓库的子目录,因此需要先克隆再打包:

```bash
git clone <slaunchx-plutus-sdk 仓库地址>
cd slaunchx-plutus-sdk/node
npm install          # 安装构建所需的 devDependencies
npm run build        # 产出 dist/esm 与 dist/cjs
npm pack             # 得到 slaunchx-plutus-sdk-1.0.0.tgz

# 回到你的项目
npm install /绝对路径/slaunchx-plutus-sdk/node/slaunchx-plutus-sdk-1.0.0.tgz
```

也可以直接以本地目录方式引用(注意:需先在 `node/` 内执行过 `npm run build`,
npm 对本地目录依赖不保证执行 `prepare`):

```bash
npm install /绝对路径/slaunchx-plutus-sdk/node
```

### 私有 registry

若贵司有内部 registry,推荐在 CI 中于 `node/` 目录执行 `npm publish`,之后按第一种方式安装。

---

## 准备密钥

商户与平台之间共有 4 把 RSA 密钥对,职责严格分离:

| 密钥 | 商户持有 | SDK 中的配置项 | 用途 |
| --- | --- | --- | --- |
| `merchant_auth` | 私钥 | `keys.merchantAuthPrivateKey` | 签请求规范串 |
| `platform_auth` | 公钥 | `keys.platformAuthPublicKey` | 验响应签名与 Webhook 签名 |
| `merchant_enc` | 私钥 | `keys.merchantEncPrivateKey` | 解密敏感响应与 Webhook |
| `platform_enc` | 公钥 | `keys.platformEncPublicKey` | 加密请求体 |

生成商户侧密钥对:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 \
  -out merchant_auth_private.pem
openssl rsa -in merchant_auth_private.pem -pubout -out merchant_auth_public.pem
```

公钥必须是 PEM 编码的 SPKI(`-----BEGIN PUBLIC KEY-----`),模数 2048–4096 位,
公开指数恰为 65537。私钥为 PKCS#8(`-----BEGIN PRIVATE KEY-----`)。
SDK 在装载时强制校验这些约束,不满足会抛 `PlutusKeyError`。

**不要把私钥写进代码或日志。** 建议从环境变量或密钥管理系统读取。

---

## 快速开始

### 1. 普通签名调用

```ts
import { PlutusClient } from '@slaunchx/plutus-sdk';

const client = new PlutusClient({
  apiVersion: '1',
  baseUrl: 'https://consumer-api.slaunchx.example',
  apiKey: process.env.SLAUNCHX_API_KEY!,
  keys: {
    merchantAuthPrivateKey: process.env.MERCHANT_AUTH_PRIVATE_PEM!,
    platformAuthPublicKey: process.env.PLATFORM_AUTH_PUBLIC_PEM!,
  },
});

// GET,带 query。query 会被严格规范化后参与签名;实际发送的也是规范化结果(默认行为,
// 由 sendCanonicalQuery 控制)。
const page = await client.request<{ items: unknown[] }>({
  method: 'GET',
  path: '/card-products/cards/page',
  query: { pageSize: 20, status: 'IN_USE' },
});
console.log(page.status, page.signatureVerified, page.data);

// POST,幂等写端点必须带幂等键;其余端点可选,但发送即参与签名。
const frozen = await client.request({
  method: 'POST',
  path: '/card-products/cards/freeze',
  body: { reasonCategory: 'USER_REQUESTED' },
  idempotencyKey: crypto.randomUUID(),
});
console.log(frozen.operationId);
```

要点:

- `path` 是**外部路径**,不含 `/api`、`/v1`、`/consumer` 等前缀;版本走 `X-API-VERSION` 头。
- `body` 传对象时 SDK 只序列化**一次**,同一份字节既用于摘要也用于发送。
- `GET` / `HEAD` / `DELETE` 一律用空 body 摘要签名,即使传了 `body`。
- 响应被判定为失败时抛出类型化错误(判定规则见下文「统一响应包络与成功判定」),
  不返回未验签的数据。

### 2. 加密端点

对 `ENCRYPTED_ROUTE_TEMPLATES` 列出的加密端点,加 `encrypt: true` 即可。SDK 会:
生成 `X-Request-Id` → 构造 AAD(`requestId | 外部路径 | X-Timestamp | 平台加密公钥指纹`)→
RSA-OAEP-SHA256 + AES-256-GCM 封装 → 用**信封 JSON 字节**的摘要签名 → 发送。

```ts
const client = new PlutusClient({
  apiVersion: '1',
  baseUrl: 'https://consumer-api.slaunchx.example',
  apiKey: process.env.SLAUNCHX_API_KEY!,
  keys: {
    merchantAuthPrivateKey: process.env.MERCHANT_AUTH_PRIVATE_PEM!,
    platformAuthPublicKey: process.env.PLATFORM_AUTH_PUBLIC_PEM!,
    platformEncPublicKey: process.env.PLATFORM_ENC_PUBLIC_PEM!,
    merchantEncPrivateKey: process.env.MERCHANT_ENC_PRIVATE_PEM!,
  },
});

const created = await client.request({
  method: 'POST',
  path: '/card-products/10010106/shared/cards/create',
  body: { platformCardProductBizId: 'pcp_example_001', quantity: 2 },
  encrypt: true,
  idempotencyKey: crypto.randomUUID(),
});
```

响应体返回敏感信封时,加 `decryptResponse: true` 自动解密(需要 `merchantEncPrivateKey`):

```ts
const sensitive = await client.request<{ cardNumber: string; cvv: string }>({
  method: 'GET',
  path: '/card-products/cards/sensitive',
  decryptResponse: true,
});
console.log(sensitive.data.cardNumber);
```

也可以只用底层能力,自行控制传输:

```ts
import { EnvelopeCodec, RequestSigner } from '@slaunchx/plutus-sdk';

const timestamp = String(Date.now());
const { envelope, bodyBytes, keyId } = EnvelopeCodec.sealRequest(
  { platformCardProductBizId: 'pcp_example_001', quantity: 2 },
  {
    requestId: 'req_0001',
    routeTemplate: '/card-products/10010106/shared/cards/create',
    timestamp,
    platformEncPublicKey: process.env.PLATFORM_ENC_PUBLIC_PEM!,
  },
);

const signer = new RequestSigner({ apiVersion: '1',
  apiKey: process.env.SLAUNCHX_API_KEY!,
  merchantAuthPrivateKey: process.env.MERCHANT_AUTH_PRIVATE_PEM!,
});
const signed = signer.sign({
  method: 'POST',
  path: '/card-products/10010106/shared/cards/create',
  body: bodyBytes,            // 摘要与发送必须是同一份字节
  timestamp,                  // 与 AAD 中的 timestamp 必须相同
  requestId: 'req_0001',
  platformEncryptionKeyId: keyId,
});
await fetch(url, { method: 'POST', headers: signed.headers, body: bodyBytes });
```

### 3. 接收 Webhook

**必须拿到未被解析器改写的原始 body 字节**:签名覆盖的是加密信封 JSON 的原始字节,
`express.json()` 之类的中间件会重新序列化,导致摘要不一致、验签必然失败。

```ts
import express from 'express';
import { WebhookHandler, PlutusWebhookError } from '@slaunchx/plutus-sdk';

const handler = new WebhookHandler({
  platformAuthPublicKey: process.env.PLATFORM_AUTH_PUBLIC_PEM!,
  merchantEncPrivateKey: process.env.MERCHANT_ENC_PRIVATE_PEM!,
  apiKeyBizId: process.env.SLAUNCHX_API_KEY!,   // 用于校验 X-SlaunchX-Key-Id 并构造 AAD
});

const app = express();

// 关键:用 express.raw 拿 Buffer,不要用 express.json
app.post('/webhooks/slaunchx', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    // handle() 内部顺序:验签 → 解析信封 → 重建 AAD → 解密 → 与传输头交叉校验
    const delivery = handler.handle(req.body as Buffer, req.headers);

    // 按 deliveryBizId 去重:自动重试与人工重放共用同一个 deliveryBizId
    if (await alreadyProcessed(delivery.headers.deliveryBizId)) {
      return res.status(204).end();
    }
    await enqueue(delivery.payload);            // 业务处理建议异步化,先快速返回
    return res.status(204).end();
  } catch (err) {
    if (err instanceof PlutusWebhookError) {
      return res.status(400).json({ error: err.sdkCode });
    }
    return res.status(500).end();
  }
});
```

其它框架取原始 body 的方式:

- **Fastify**:`fastify.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => done(null, body))`
- **Koa**:`koa-bodyparser` 的 `enableRawChecking`,或直接用 `raw-body` 读取 `ctx.req`
- **原生 `node:http`**:自行累积 `data` 事件得到 `Buffer.concat(chunks)`
- **Next.js Route Handler**:`Buffer.from(await request.arrayBuffer())`

注意金额是 `{currency, amount}` 结构,`amount` 为**十进制字符串**,
不要解析成浮点数。

---

## 统一响应包络与成功判定

平台所有响应共用同一个包络:

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
- `code` 是**字符串**。成功族为 `"2000"` `"2001"` `"2002"` `"2004"` `"2006"`,
  另有 `"2101"`(账号待审批:登录成功但不签发 JWT,`success` 仍为 `true`)。
  失败时网关层为 `域.名称`(如 `API.SIGNATURE_INVALID`),业务层为 4xxx/5xxx 的数字字符串
  (如 `"4022"`)。
- `message` 是结果或错误消息。

SDK 的成功判定算法(`isSuccessResponse(body, status)`):

1. 若响应体是 JSON 对象,且键 `success` 存在且其值是**布尔类型**,返回该布尔值;
2. 否则回退到 HTTP 状态:`200 <= status < 300`。

缺失、为 `null`、为字符串或数字的 `success` 一律不算权威,走 HTTP 回退。
`code` **不参与**成功判定。

```ts
import { isSuccessResponse, isSuccessCode, SUCCESS_CODES, ACCOUNT_PENDING_APPROVAL } from '@slaunchx/plutus-sdk';

// client.request() 内部即用此规则;判定为失败时抛类型化错误,不返回 data。
const res = await client.request<{ items: unknown[] }>({ method: 'GET', path: '/card-products/cards/page' });
console.log(res.body?.success, res.body?.code, res.data);

// 自定义传输层时,自行判定:
if (isSuccessResponse(parsedBody, httpStatus)) {
  // 成功分支
}

// SUCCESS_CODES / isSuccessCode / ACCOUNT_PENDING_APPROVAL 仅供文档与便利判断,
// 不是成功判定依据。例如识别"账号待审批"这一特殊成功态:
if (res.body?.code === ACCOUNT_PENDING_APPROVAL) {
  // 登录成功但未签发 JWT
}
console.log(SUCCESS_CODES.has('2000'), isSuccessCode('4022'));   // true false
```

失败时的错误码取包络的 `code` 字段,数字会被字符串化 —— 业务错误码本来就是 `"4022"`
这样的数字字符串,不会因为"看起来是数字"而被丢弃;错误消息取 `message`。
`errorCode` / `error.code` / `msg` 仅作次级回退。

## 响应验签与缺签名头策略

`verifyResponseSignature` 默认 `true`。在此前提下:

| 情形 | 行为 |
| --- | --- |
| 响应带 `X-Response-Signature` | 强制验签;失败抛 `PlutusSignatureError` 并丢弃响应体 |
| HTTP 2xx 且缺签名头 | 抛 `PlutusSignatureError` |
| 非 2xx 且缺签名头 | 不抛验签异常;`signatureVerified` 为 `false`,按类型化 API 错误抛出 |
| 非 2xx 且缺签名头 + `requireSignatureOnErrorResponses: true` | 抛 `PlutusSignatureError` |

严格开关为 `requireSignatureOnErrorResponses`,**默认 `false`**。SDK 不做状态码白名单
(不存在 `allowUnsignedStatuses` 这类配置):平台契约并未穷举哪些状态码不带签名头,
因此只按 2xx / 非 2xx 区分。该策略属于 SDK 自身约定,不是平台强制契约。

被放行的响应可从两处看到未验签结果:成功响应看 `PlutusResponse.signatureVerified`,
失败响应看 `PlutusApiError.signatureVerified`。

```ts
try {
  const res = await client.request({ method: 'GET', path: '/card-products/cards/page' });
  console.log(res.signatureVerified);            // 2xx 路径下恒为 true(除非关闭了验签)
} catch (err) {
  if (err instanceof PlutusApiError) {
    console.log(err.code, err.signatureVerified); // 非 2xx 缺签名头时为 false,错误内容不可信
  }
}
```

## 实际发送的 query 形态

SDK 参与签名的始终是**规范化后**的 query。实际发送的 query 由
`sendCanonicalQuery` 控制,**默认 `true`,即发送规范化结果**(参数按名称排序、按 RFC 3986
重新百分号编码),而非调用方传入的原样串。置为 `false` 时发送原样串;两者在平台侧等价,
发送规范化结果可消除本地差异带来的验签风险。

```ts
await client.request({ method: 'GET', path: '/x', query: 'pageSize=20&status=IN_USE&cursor=' });
// 默认实际请求 URL:/x?cursor=&pageSize=20&status=IN_USE
```

无法通过严格规范化的 query(裸保留字符、非法 `%XX`、非 ASCII 等)在本地就抛
`PlutusCanonicalizationError`,不会发出必然被拒的请求。

## Webhook 时间戳容差

`WebhookHandler` 的 `timestampToleranceMs` **可配置,默认 `undefined` 即关闭**:
不传该项时 SDK 不做时间戳新鲜度校验。协议未规定该窗口是否启用与窗口大小,
因此 SDK 不硬编码默认值,由调用方按自身风险偏好显式设置(例如 `300_000`)。

```ts
const handler = new WebhookHandler({
  platformAuthPublicKey: process.env.PLATFORM_AUTH_PUBLIC_PEM!,
  merchantEncPrivateKey: process.env.MERCHANT_ENC_PRIVATE_PEM!,
  apiKeyBizId: process.env.SLAUNCHX_API_KEY!,
  timestampToleranceMs: 300_000,   // 显式开启 ±5 分钟窗口
});
```

---

## 签名排障

平台验签失败时**不返回诊断信息**,商户只能靠客户端自检定位问题。生产环境已知的最常见
单点根因是 `baseUrl` 配错(配成源站地址,或自行拼接了 `/prometheus`、`/api/v1/consumer`
前缀——见上文「配置项」`baseUrl` 一行的正确/错误示例)。排查步骤:

### 1. 只签名,不发送请求

`PlutusClient.signOnly()` 复用与 `request()` 完全相同的组装逻辑(含加密分支),但不发起
网络调用,直接拿到 `SignedRequest`:

```ts
const client = new PlutusClient({ baseUrl, apiKey, keys: { merchantAuthPrivateKey } });
const { signed, url, headers } = client.signOnly({
  method: 'POST',
  path: '/card-products/10010106/shared/cards/create',
  body: { platformCardProductBizId: 'pcp_example_001', quantity: 2 },
  idempotencyKey: 'idem-0001',
});

console.log(signed.canonicalString);        // 8 行规范串,逐行核对下表
console.log(signed.requestCanonicalSha256); // 规范串本身的 SHA-256(响应验签第 2 行要用到)
console.log(signed.signature);              // 最终 Base64 签名,即 X-Signature
console.log(url, headers);                  // 实际会发往的 URL 与全部请求头
```

不想实例化完整 `PlutusClient`(例如尚未拿到 `baseUrl`)时,可以直接用更底层的
`RequestSigner`,签名逻辑与 `signOnly()` 完全一致:

```ts
import { RequestSigner } from '@slaunchx/plutus-sdk';

const signer = new RequestSigner({ apiVersion: '1',
  apiKey: process.env.SLAUNCHX_API_KEY!,
  merchantAuthPrivateKey: process.env.MERCHANT_AUTH_PRIVATE_PEM!,
});
const signed = signer.sign({
  method: 'POST',
  path: '/card-products/10010106/shared/cards/create',
  body: Buffer.from(JSON.stringify({ platformCardProductBizId: 'pcp_example_001', quantity: 2 }), 'utf8'),
  idempotencyKey: 'idem-0001',
});

console.log(signed.canonicalString);
console.log(signed.requestCanonicalSha256);
console.log(signed.signature);
```

两者都不发起任何网络请求;`RequestSigner.sign()` 本身就是一次纯本地计算。

### 2. 逐行核对规范串(8 行,`buildRequestCanonicalString` 的真实顺序)

| 行号 | 字段 | 自检要点 |
| --- | --- | --- |
| 1 | `METHOD` | 大写,如 `GET` / `POST` |
| 2 | `EXTERNAL_PATH` | **外部路径**:必须是商户对外发出的路径,不含 `/api/v1/consumer`、不含 `/prometheus`、不含 `/v1`,不做大小写或末尾斜杠归一 |
| 3 | `CANONICAL_QUERY` | 已按「严格解码 → RFC 3986 重编码 → 按 `(key, value)` 字节序排序」规范化;无 query 时该行为**空行**,不是省略整行 |
| 4 | `TIMESTAMP` | 必须是 Unix **毫秒**十进制字符串(13 位左右),不是秒 |
| 5 | `NONCE` | 满足 `^[A-Za-z0-9._~-]{16,128}$` |
| 6 | `API_VERSION` | 与 `X-API-VERSION` 头原值一致,当前恒为 `1` |
| 7 | `IDEMPOTENCY_KEY` | 未发送 `X-Idempotency-Key` 时该行为**空行**,不是省略整行 |
| 8 | `BODY_SHA256_HEX` | 对**实际要发送的字节**求 SHA-256、小写 hex;`GET`/`HEAD`/`DELETE` **强制**空 body 摘要(`EMPTY_BODY_SHA256`),即使传了 `body` 也一样 |

排障时优先检查第 2 行(`baseUrl`/`path` 配置)与第 8 行(body 是否被序列化了两次、
GET 是否误用了实际 body 摘要)——这两处是生产事故里最常见的两类根因。

### 3. 独立复算规范串的原语

`buildRequestCanonicalString` / `bodyDigestHex` / `signedBodyDigest` / `canonicalizeQuery`
均从 `canonical.ts` 导出,不涉及任何密钥材料,可脱离 `PlutusClient` 单独调用,逐分量核对:

```ts
import { buildRequestCanonicalString, canonicalizeQuery, signedBodyDigest } from '@slaunchx/plutus-sdk';

const method = 'POST';
const bodyBytes = Buffer.from(JSON.stringify({ quantity: 2 }), 'utf8');
const canonicalString = buildRequestCanonicalString({
  method,
  externalPath: '/card-products/10010106/shared/cards/create',
  canonicalQuery: canonicalizeQuery(''),
  timestamp: String(Date.now()),
  nonce: 'nonce-0000000000000001',
  apiVersion: '1',
  idempotencyKey: 'idem-0001',
  bodyDigest: signedBodyDigest(method, bodyBytes),
});
```

## 错误处理

```ts
import {
  PlutusApiError,
  PlutusAuthenticationError,
  PlutusRateLimitError,
  PlutusSignatureError,
  PlutusCanonicalizationError,
} from '@slaunchx/plutus-sdk';

try {
  await client.request({ method: 'GET', path: '/card-products/cards/page' });
} catch (err) {
  if (err instanceof PlutusRateLimitError) {
    await sleep((err.retryAfterSeconds ?? 1) * 1000);   // 按 Retry-After 退避
  } else if (err instanceof PlutusAuthenticationError) {
    // API.SIGNATURE_INVALID / API.KEY_* 属于实现或配置错误,不要重试
    logger.error({ code: err.code, requestId: err.requestId });
  } else if (err instanceof PlutusSignatureError) {
    // 响应验签失败按安全事故处理:响应体已被丢弃,不会交给业务代码
  } else if (err instanceof PlutusApiError && err.retryable) {
    // 重试时 SDK 会重新生成 timestamp 与 nonce 并重新签名
  }
}
```

错误类与错误码族的对应:

| 错误类 | 错误码族 / 触发条件 |
| --- | --- |
| `PlutusAuthenticationError` | `API.*`(KEY / TIMESTAMP / NONCE / SIGNATURE / VERSION) |
| `PlutusPermissionError` | `ACCESS.*`、`API.IP_NOT_ALLOWED`、`API.WORKSPACE_UNAVAILABLE` |
| `PlutusValidationError` | `VALIDATION.*` |
| `PlutusNotFoundError` | `RESOURCE.NOT_FOUND` |
| `PlutusConflictError` | `REQUEST.CONFLICT`、`REQUEST.STALE_VERSION` |
| `PlutusRateLimitError` | `REQUEST.RATE_LIMITED` |
| `PlutusSecureChannelError` | `SECURE_CHANNEL.INVALID_PAYLOAD` |
| `PlutusServerError` | `SYSTEM.*` 与 5xx |
| `PlutusSignatureError` | 响应验签失败,或按策略必须有签名却缺失(见「响应验签与缺签名头策略」) |
| `PlutusEnvelopeError` | 信封形状非法、AAD 不匹配、GCM 认证失败、明文超限 |
| `PlutusWebhookError` | Webhook 验签失败、信封形状不符、交叉校验不一致 |
| `PlutusCanonicalizationError` | query 无法通过严格规范化(本地抛出,不发请求) |
| `PlutusRequestError` / `PlutusConfigError` / `PlutusKeyError` | 本地入参、配置或密钥材料非法 |
| `PlutusTransportError` | 网络错误、超时、被取消 |

全部继承自 `PlutusError`,带稳定的 `sdkCode` 字段便于日志检索。

---

## 配置项

> 协议头由 SDK 自动补齐,调用方只需配置下表项;各字段是否进入签名串由下表说明标注。
> 平台**不读取** `X-Workspace-Id`,SDK 也不发送该头。

`new PlutusClient(config)` 的 `PlutusConfig`:

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `baseUrl` | `string` | — | **必填**。CONSUMER API 主机根地址,不含链/版本/门户前缀。必须是**对外 CONSUMER API 域名**,不能是源站地址,不能自行拼接 `/prometheus`、`/api/v1/consumer` 前缀(见下方示例与「签名排障」一节) |
| `apiKey` | `string` | — | **必填**。API Key 业务 ID,写入 `X-Api-Key` |
| `keys.merchantAuthPrivateKey` | `string \| Buffer \| KeyObject` | — | **必填**。商户认证私钥 |
| `keys.platformAuthPublicKey` | 同上 | — | 启用响应验签时必填 |
| `keys.merchantEncPrivateKey` | 同上 | — | 解密敏感响应 / Webhook 时必填 |
| `keys.platformEncPublicKey` | 同上 | — | 调用加密端点时必填 |
| `apiVersion` | `string` | 无（必填） | `X-API-VERSION`,参与签名 |
| `verifyResponseSignature` | `boolean` | `true` | 是否验证响应签名 |
| `requireSignatureOnErrorResponses` | `boolean` | `false` | 非 2xx 缺签名头时是否也报错(2xx 缺签名头一律报错) |
| `timeoutMs` | `number` | `30000` | 单次请求超时;`0` 表示不设超时 |
| `nonceGenerator` | `() => string` | 16 字节 CSPRNG 的 hex | 必须满足 `^[A-Za-z0-9._~-]{16,128}$` |
| `requestIdGenerator` | `() => string` | `req_` + 16 字节 hex | 加密端点的 `X-Request-Id` |
| `now` | `() => number` | `Date.now` | 毫秒时钟,便于测试注入 |
| `fetch` | `typeof fetch` | 全局 `fetch` | 注入自定义传输实现 |
| `defaultHeaders` | `Record<string,string>` | `{}` | 附加到每个请求;不得覆盖签名头 |
| `userAgent` | `string` | `slaunchx-plutus-sdk-node/<version>` | `User-Agent` |
| `sendCanonicalQuery` | `boolean` | `true` | 默认发送规范化 query 而非原样串(两者在平台侧等价) |
| `strictKeyValidation` | `boolean` | `true` | 是否强制密钥格式校验(SPKI/PKCS#8 PEM、模数 2048–4096 位、公开指数 65537,见「准备密钥」) |
| `maxPlaintextBytes` | `number` | `1048576` | 信封解密的明文长度上限 |
| `strictEncryptedRouteValidation` | `boolean` | `false` | 加密请求的 `routeTemplate` 是否必须属于 `ENCRYPTED_ROUTE_TEMPLATES`(见「加密请求 routeTemplate 校验」) |

`baseUrl` 正确/错误示例:

```ts
// 正确:baseUrl 是对外 CONSUMER API 域名;path 是外部路径,SDK 对 /card-products/xxx 签名
const client = new PlutusClient({
  apiVersion: '1',
  baseUrl: 'https://consumer-api.slaunchx.example',
  // ...
});
await client.request({ method: 'POST', path: '/card-products/10010106/shared/cards/create', /* ... */ });
```

```ts
// 错误:baseUrl 是源站地址,并自行拼接了 /prometheus/api/v1/consumer 前缀 —— 签名必然失败
const client = new PlutusClient({
  apiVersion: '1',
  baseUrl: 'https://origin-host.internal/prometheus/api/v1/consumer',
  // ...
});
```

商户必须把 `baseUrl` 配成对外 CONSUMER API 域名,`path` 始终传外部路径;链 / 版本 / 门户前缀的改写
由边缘(Cloudflare / nginx)完成,SDK 与商户都不应参与拼接。详见「签名排障」一节。

### 加密请求 routeTemplate 校验

`options.encrypt` 为 `true`(未显式给 `routeTemplate`)时,SDK 默认用请求的 `path` 作为混合加密
信封 AAD 的 `routeTemplate` 分量。该值默认会与已知加密端点表 `ENCRYPTED_ROUTE_TEMPLATES`
做一次已知性校验:

- **默认(非严格)模式**:未知 `routeTemplate` 不阻断请求,只通过 `process.emitWarning(...)`
  输出一次警告——平台后续新增加密端点后,SDK 若在此处 fail-closed,会让商户在 SDK 升级前
  无法调用新端点,体验比“放行 + 警告”更差。
- **严格模式**(`strictEncryptedRouteValidation: true`):未知 `routeTemplate` 直接抛出
  `PlutusRequestError`,不发出请求。适合需要强校验、宁可拒绝也不接受未知路由的商户。

```ts
import { ENCRYPTED_ROUTE_TEMPLATES, isKnownEncryptedRoute } from '@slaunchx/plutus-sdk';

isKnownEncryptedRoute('/card-products/10010106/shared/cards/create'); // true
isKnownEncryptedRoute('/card-products/some-new-endpoint');            // false,但默认不阻断
```

`client.request(options)` 的 `PlutusRequestOptions`:

| 选项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `method` | `string` | — | **必填**。HTTP 方法 |
| `path` | `string` | — | **必填**。外部路径,以 `/` 开头 |
| `query` | `string \| Record<string, ...>` | — | 原始 query 串或参数对象(对象按 RFC 3986 编码) |
| `body` | `unknown` | — | 对象走 `JSON.stringify`;字符串按 UTF-8;`Uint8Array` 原样使用 |
| `contentType` | `string` | 有 body 时 `application/json` | 覆盖 `Content-Type` |
| `headers` | `Record<string,string>` | — | 附加头;签名相关头不可覆盖 |
| `idempotencyKey` | `string` | — | `X-Idempotency-Key`,发送即参与签名 |
| `requestId` | `string` | 加密时自动生成 | `X-Request-Id` |
| `encrypt` | `boolean \| { routeTemplate }` | `false` | 是否加密请求体;`routeTemplate` 默认取 `path`,会按「加密请求 routeTemplate 校验」做已知性检查 |
| `decryptResponse` | `boolean` | `false` | 响应 `data` 为信封时自动解密 |
| `timeoutMs` | `number` | 取配置值 | 覆盖超时 |
| `signal` | `AbortSignal` | — | 外部取消 |

`new WebhookHandler(options)` 的 `WebhookHandlerOptions`:

| 选项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `platformAuthPublicKey` | 密钥入参 | — | **必填**。验签公钥 |
| `merchantEncPrivateKey` | 密钥入参 | — | **必填**。解密私钥 |
| `apiKeyBizId` | `string` | 必填 | 校验 `X-SlaunchX-Key-Id` 并作为 AAD 第四分量 |
| `timestampToleranceMs` | `number` | `undefined`(关闭) | 时间戳容差。协议未规定该窗口,SDK 不硬编码默认值 |
| `crossCheckPayload` | `boolean` | `true` | 校验明文 `deliveryBizId` / `eventType` / `payloadSchemaVersion` |
| `maxPlaintextBytes` | `number` | `1048576` | 明文长度上限 |
| `strictKeyValidation` | `boolean` | `true` | 密钥格式校验 |

---

## 公开 API

顶层导出(`import { ... } from '@slaunchx/plutus-sdk'`):

- **客户端**:`PlutusClient`、`serializeBody`
- **签名**:`RequestSigner`、`signCanonicalString`、`verifyCanonicalSignature`、`generateNonce`、
  `SIGNATURE_ALGORITHM`、`DEFAULT_API_VERSION`
- **验签**:`ResponseVerifier`、`readHeader`、`snapshotHeaders`
- **信封**:`EnvelopeCodec`(`seal` / `open` / `openText` / `openJson` / `sealRequest` /
  `openSensitiveResponse`)、`parseSensitiveResponseAad`、`ENVELOPE_ALGORITHM`、
  `AES_KEY_BYTES`、`IV_BYTES`、`TAG_BYTES`、`MAX_PLAINTEXT_BYTES`
- **Webhook**:`WebhookHandler`、`extractWebhookHeaders`、`assertWebhookEnvelope`、
  `assertPayloadMatchesHeaders`、`WEBHOOK_ROUTE_TEMPLATE`
- **加密端点路由表**:`ENCRYPTED_ROUTE_TEMPLATES`、`isKnownEncryptedRoute`
- **协议原语**:`canonicalizeQuery`、`canonicalizeComponent`、`percentEncode`、
  `percentDecodeStrict`、`encodeQueryParams`、`bodyDigestHex`、`signedBodyDigest`、
  `isForcedEmptyBodyMethod`、`buildRequestCanonicalString`、`requestCanonicalSha256`、
  `buildResponseCanonicalString`、`buildAad`、`buildWebhookCanonicalString`、
  `webhookBodyDigestBase64`、`isValidNonce`、`EMPTY_BODY_SHA256`、`NONCE_PATTERN`、
  `RESPONSE_CANONICAL_PREFIX`、`FORCED_EMPTY_BODY_METHODS`
- **密钥**:`loadPublicKey`、`loadPrivateKey`、`keyFingerprint`、`constantTimeEquals`、
  `MIN_MODULUS_BITS`、`MAX_MODULUS_BITS`、`REQUIRED_PUBLIC_EXPONENT`
- **响应**:`isSuccessResponse`、`isSuccessCode`、`SUCCESS_CODES`、`ACCOUNT_PENDING_APPROVAL`、
  `extractRateLimit`、`toApiError`
- **配置**:`resolveConfig`、`SDK_VERSION`
- **错误**:`PlutusError` 及全部子类、`createApiError`、`errorFamily`

类型导出:`PlutusConfig`、`PlutusKeyMaterial`、`PlutusRequestOptions`、`PlutusResponse`、
`ApiResponse`、`RateLimitInfo`、`PublicErrorCode`、`ErrorFamily`、`SignableRequest`、
`SignedRequest`、`HybridEnvelope`、`WebhookEnvelope`、`WebhookHeaders`、`WebhookPayload`、
`WebhookDelivery`、`AadComponents`、`KeyInput`、`HeaderSource` 等。

---

## 开发

```bash
npm install      # 安装 devDependencies(typescript / vitest / @types/node)
npm run build    # 产出 dist/esm 与 dist/cjs(含 .d.ts)
npm test         # 跑黄金测试向量与负向用例
npm run typecheck
```

测试直接加载 `../shared/test-vectors.json`,覆盖全部向量组:
`canonicalQuery` 21 例(含 6 条拒绝断言)、`bodyHash` 7 例、`requestSignature` 7 例
(规范串逐行比对 + 验签 + 用私钥重签比对)、`responseSignature` 3 例、
`encryptedEnvelope` 3 例(解密比对明文)+ 加密方向 round-trip、`webhook` 2 例(验签 + 解密),
另有篡改规范串 / AAD / 密文 / 响应头的负向断言。

`dist/` 与 `node_modules/` 不入库:`dist` 完全由 `src` 决定,入库只会带来构建产物与源码不同步
的风险;分发通过 `npm pack`(会触发 `prepare` 构建)或 registry 发布完成。

## 常见坑

1. body 序列化两次 —— 必须序列化一次拿到字节数组,摘要与发送共用。SDK 的 `request()` 已保证。
2. query 用了 `URLSearchParams` / `querystring` —— 它们把空格编成 `+`、`~` 编成 `%7E`,
   规则与本协议不同。用 `encodeQueryParams()` 或直接传参数对象。
3. `GET` / `DELETE` 带 body 却用了实际 body 摘要 —— SDK 已强制空体摘要。
4. `X-Timestamp` 用了秒 —— 必须是毫秒。SDK 默认用 `Date.now()`。
5. OAEP 的 MGF1 用了默认 SHA-1 —— SDK 显式设为 SHA-256。
6. 直接用信封回显的 `aad` 解密 —— SDK 一律自行重建 AAD 并常量时间比对后再解密。
7. Webhook 先解密后验签,或对解密后的明文验签 —— SDK 强制先验签后解密。
8. Webhook body 摘要用 hex —— Webhook 用 Base64,API 链用小写 hex,SDK 分别提供了函数。
9. 重试时复用整套签名头 —— 时间戳会过期、nonce 会判重放。重试请重新调用 `request()`,
   业务幂等靠 `X-Idempotency-Key`。

`X-API-VERSION` 必须由调用方通过版本配置显式填写，没有默认值；当前 product 填 `1`。遗漏、空串或纯空白会在本地报错。


## Webhook 接收方校验修复版本

修复源码版本：`f16cdbf`；语言包尚未发布，安装源码需包含此提交。PHP 对应修复为 `58a2893`。

`WebhookHandlerOptions.apiKeyBizId` 现在必填，不允许遗漏、空串或纯空白。必须配置本地登记的 API Key 业务 ID，不能从当前投递头动态赋值，也不是公钥指纹。

处理器先验证签名，再将 `X-SlaunchX-Key-Id` 与本地 API Key 比较；不一致即拒绝。AAD 第四段使用已核对的本地 API Key，两个 API Key 即使共用同一对加密密钥也不能互收投递。product 的 Webhook 签名规范串、信封和 AAD 四段协议没有改变。

旧版本的接收方配置可选，调用方必须显式设置上述配置才能启用比较；无法升级时应确保验签后、解密前比较接收方，不得只凭解密成功认定投递属于本地 API Key。
