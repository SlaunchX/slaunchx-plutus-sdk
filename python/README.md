# SlaunchX Plutus 商户 Python SDK

协议 `SLAUNCHX-PLUTUS-API-V1` 的 Python 实现,只覆盖传输层:请求签名、响应验签、
混合加密信封、Webhook 验签与解密。**不建立业务端点模型** —— 外部路径与业务载荷由调用方给出,
因此平台新增端点时无需升级 SDK。

实现依据是协议 `SLAUNCHX-PLUTUS-API-V1` 与 [`shared/test-vectors.json`](../shared/test-vectors.json)。
向量为最高权威。

- Python >= 3.9
- 依赖:`cryptography>=41`、`requests>=2.28`

## 安装

PyPI 包名 `slaunchx-plutus-sdk`(尚未发布,占位)。当前从 Git 仓库安装,SDK 位于仓库的
`python/` 子目录,需要 `#subdirectory=python`:

```bash
# HTTPS
pip install "slaunchx-plutus-sdk @ git+https://github.com/slaunchx/slaunchx-plutus-sdk.git#subdirectory=python"

# SSH
pip install "slaunchx-plutus-sdk @ git+ssh://git@github.com/slaunchx/slaunchx-plutus-sdk.git#subdirectory=python"

# 指定 tag / commit
pip install "slaunchx-plutus-sdk @ git+https://github.com/slaunchx/slaunchx-plutus-sdk.git@v0.1.0#subdirectory=python"
```

`requirements.txt` 写法:

```
slaunchx-plutus-sdk @ git+https://github.com/slaunchx/slaunchx-plutus-sdk.git@v0.1.0#subdirectory=python
```

本地开发:

```bash
cd python
python3 -m venv .venv && .venv/bin/pip install -e ".[test]"
.venv/bin/python -m pytest
```

PyPI 发布后可直接 `pip install slaunchx-plutus-sdk`。

## 密钥

四把 RSA 密钥对职责严格分离,按需配置。私钥用 PKCS#8 PEM(`BEGIN PRIVATE KEY`),
公钥用 SPKI PEM(`BEGIN PUBLIC KEY`,不是 PKCS#1),模数 2048–4096 位,公开指数恰为 65537。

| 配置项 | 密钥 | 用途 |
| --- | --- | --- |
| `merchant_auth_private_key` | 商户认证私钥 | 对请求规范串签名 |
| `platform_auth_public_key` | 平台认证公钥 | 验证响应签名与 Webhook 签名 |
| `platform_enc_public_key` | 平台加密公钥 | 加密请求体 |
| `merchant_enc_private_key` | 商户加密私钥 | 解密敏感响应与 Webhook |

四个字段都接受 PEM 文本、PEM 字节、PEM 文件路径,或已加载的 `cryptography` 密钥对象。

## `base_url` 必须是对外 CONSUMER API 域名

生产环境签名失败的最常见单点根因是 `base_url` 配错。签名只对**外部路径**
(如 `/card-products/10010106/shared/cards/create`)生效;边缘(Cloudflare/nginx 等)
负责把外部路径改写为源站内部路径(如 `/api/v1/consumer/...`),源站还可能带
`/prometheus` 之类的 context-path。这些改写与内部前缀**完全不参与签名**,SDK 也不知道它们的存在。

`base_url` 必须配成对外 CONSUMER API 域名本身,不能是源站地址,也不能自行拼上
`/prometheus`、`/api/v1/consumer` 等内部前缀:

```python
# 正确:base_url 是对外 CONSUMER API 域名,path 是外部路径
config = PlutusConfig(
    base_url="https://consumer-api.example.com",
    api_key="apk_xxxxxxxx",
    ...
)
client.post("/card-products/10010106/shared/cards/create", json_body={...}, encrypt=True)
# 实际请求 URL: https://consumer-api.example.com/card-products/10010106/shared/cards/create
# 签名 PATH:   /card-products/10010106/shared/cards/create
```

```python
# 错误:base_url 用了源站地址,并且自行拼了内部前缀 —— 验签必然失败
config = PlutusConfig(
    base_url="https://origin-host/prometheus/api/v1/consumer",
    ...
)
```

## 快速开始

### 1. 普通签名调用

```python
from slaunchx_plutus_sdk import PlutusClient, PlutusConfig

client = PlutusClient(PlutusConfig(
    base_url="https://consumer-api.slaunchx.example",
    api_key="apk_xxxxxxxx",
    merchant_auth_private_key="/etc/slaunchx/merchant_auth_private.pem",
    platform_auth_public_key="/etc/slaunchx/platform_auth_public.pem",
))

# GET:query 由 SDK 规范化后参与签名并发出;GET/HEAD/DELETE 强制空 body 摘要
page = client.get("/card-products/cards/page", query={"pageSize": 20, "status": "IN_USE"})
# is_success 取包络的 success 布尔;缺失或非布尔时回退到 HTTP 2xx
print(page.is_success, page.code, page.message, page.data, page.signature_verified)

# POST:业务对象只序列化一次,同一份字节既算摘要也发送
created = client.post(
    "/card-products/cards/freeze",
    json_body={"cardBizId": "card_example_001", "reasonCategory": "USER_REQUESTED"},
    idempotency_key="freeze-card_example_001-20260830",
)
print(created.operation_id, created.data)
```

外部路径**不含** `/api`、`/v1`、`/consumer` 前缀,版本走 `X-API-VERSION` 头。

失败(包括 HTTP 200 + `success:false`)默认抛出类型化异常,网关层错误码按 `域.名称` 映射:

```python
from slaunchx_plutus_sdk import ApiError, RateLimitedError, TimestampExpiredError

try:
    client.post("/card-products/cards/freeze", json_body={...})
except TimestampExpiredError:
    ...   # 校正时钟后重新签名重试一次
except RateLimitedError as exc:
    ...   # 按 exc.retry_after 退避
except ApiError as exc:
    # exc.code 是包络的 code 字符串:网关层 "API.SIGNATURE_INVALID",业务层 "4022"
    print(exc.code, exc.status_code, exc.request_id, exc.retryable)
```

关闭 `raise_on_http_error` / `raise_on_business_error` 后改为返回响应对象,自行判定:

```python
resp = client.get("/card-products/cards/page")
if resp.is_success:
    handle(resp.data)
else:
    log(resp.code, resp.message)
```

重试必须重新生成 timestamp + nonce 并重新签名 —— 直接再调一次 `client.request` 即可;
业务幂等靠 `X-Idempotency-Key`,不靠复用签名。

### 2. 加密端点

对 `ENCRYPTED_ROUTE_TEMPLATES` 列出的加密端点传 `encrypt=True`,SDK 会用平台加密公钥封装请求体、
生成 `X-Request-Id` 与 `X-Platform-Encryption-Key-Id`,并对**信封 JSON 字节**计算 body 摘要:

```python
client = PlutusClient(PlutusConfig(
    base_url="https://consumer-api.slaunchx.example",
    api_key="apk_xxxxxxxx",
    merchant_auth_private_key="/etc/slaunchx/merchant_auth_private.pem",
    platform_auth_public_key="/etc/slaunchx/platform_auth_public.pem",
    platform_enc_public_key="/etc/slaunchx/platform_enc_public.pem",
    merchant_enc_private_key="/etc/slaunchx/merchant_enc_private.pem",
))

resp = client.post(
    "/card-products/10010106/shared/cards/create",
    json_body={"platformCardProductBizId": "pcp_example_001", "quantity": 2},
    encrypt=True,
)
```

6 个已知加密端点收录在
`slaunchx_plutus_sdk.routes.ENCRYPTED_ROUTE_TEMPLATES`(`is_known_encrypted_route(route)`
判断某路由是否在表中)。`encrypt=True` 时最终使用的 `route_template`(`route_template` 参数,
缺省取 `path`)如果不在这张表中:默认(非严格)模式只发出
`UnknownEncryptedRouteWarning`(`warnings.warn`,不阻断请求)——平台可能已上线尚未收录进
SDK 常量表的新端点;需要强校验时把 `PlutusConfig.strict_encrypted_route_validation` 置为
`True`,未知路由会改为抛出 `ConfigurationError`。已知端点在两种模式下都不受影响。

响应里返回敏感信封时用商户加密私钥解开。AAD 的 `routeTemplate` 分量固定为空串,
`timestamp` 从信封回显的 `aad` 解析后重建比对:

```python
import json

envelope = resp.data["secure"]              # 端点约定的信封字段
plaintext = client.decrypt_sensitive(envelope, request_id=resp.request_id)
card = json.loads(plaintext)
```

### 3. 接收 Webhook

**必须对原始 HTTP body 字节验签**,不能用框架解析后重新序列化的 JSON。
顺序固定:验签 → 解密 → 与传输头交叉校验 → 按 `delivery_id` 去重。

Flask:

```python
from flask import Flask, request
from slaunchx_plutus_sdk import WebhookReceiver, WebhookError, load_private_key, load_public_key

app = Flask(__name__)
receiver = WebhookReceiver(
    load_public_key("/etc/slaunchx/platform_auth_public.pem"),
    load_private_key("/etc/slaunchx/merchant_enc_private.pem"),
    api_key="apk_xxxxxxxx",
)

@app.post("/webhooks/slaunchx")
def slaunchx_webhook():
    try:
        # request.get_data() 拿原始字节;不要用 request.get_json()
        event = receiver.handle(request.get_data(), request.headers)
    except WebhookError:
        return "", 400
    if already_processed(event.delivery_id):   # 去重键是 deliveryBizId
        return "", 200
    dispatch(event.event_type, event.payload)
    return "", 200
```

FastAPI:

```python
from fastapi import FastAPI, Request, Response
from slaunchx_plutus_sdk import WebhookReceiver, WebhookError

app = FastAPI()

@app.post("/webhooks/slaunchx")
async def slaunchx_webhook(request: Request) -> Response:
    raw = await request.body()          # 原始字节;不要用 await request.json()
    try:
        event = receiver.handle(raw, request.headers)
    except WebhookError:
        return Response(status_code=400)
    ...
    return Response(status_code=200)
```

注意事项:

- 任何会重新格式化 body 的中间件(美化 JSON、追加换行、重编码)都会破坏验签,须绕开。
- 金额是 `{"currency": "USD", "amount": "25.80"}` 形式的**十进制字符串**,不要解析成 float。
- 自动重试与人工重放共用同一个 `deliveryBizId`;`eventId` 是业务事件标识,可能投递到多个 endpoint。
- 协议未规定 Webhook 时间戳容差,`timestamp_tolerance_ms` 默认关闭。需要时自行设定,
  不要当成协议要求。

### 4. 只用协议原语

不使用内置 HTTP 客户端时,可以只取签名/验签原语:

```python
from slaunchx_plutus_sdk import RequestSigner, ResponseVerifier, serialize_json, load_private_key

signer = RequestSigner(load_private_key("merchant_auth_private.pem"), "apk_xxxxxxxx")
body = serialize_json({"quantity": 2})      # 只序列化一次
signed = signer.sign("POST", "/card-products/cards/freeze", body=body)

# signed.headers 直接铺进请求头;signed.body 就是要发送的那份字节
# signed.canonical_sha256 缓存下来,用于响应验签的第 2 行
```

## 签名排障

平台验签失败时不返回诊断信息,商户只能靠客户端自检。`slaunchx_plutus_sdk.signer` 已经公开了
「只签名不发送」的原语,足以在本地复现某次请求的 8 行规范串、其 SHA-256、最终 Base64 签名,
再逐行比对下方 checklist。

用 `RequestSigner.sign(...)` 复现:传入与失败请求完全相同的 `method`、`external_path`、
`query`、`body`、`idempotency_key`,并显式传回当时用的 `timestamp` / `nonce`(从请求日志或
`X-Timestamp` / `X-Nonce` 头取得),即可拿到与当时**逐字节相同**的规范串:

```python
import hashlib

from slaunchx_plutus_sdk import RequestSigner, load_private_key

private_key = load_private_key("/etc/slaunchx/merchant_auth_private.pem")
signer = RequestSigner(private_key, api_key="apk_xxxxxxxx")

signed = signer.sign(
    "POST",
    "/card-products/10010106/shared/cards/create",   # 外部路径,不含 /api/v1/consumer、/prometheus
    query=None,
    body=b'{"platformCardProductBizId":"pcp_example_001","quantity":2}',
    idempotency_key=None,
    timestamp="1755600003000",   # 复现失败请求时传回当时的 X-Timestamp
    nonce="nonce-vector-0000000004",  # 复现失败请求时传回当时的 X-Nonce
)

print(signed.canonical_string)   # 8 行规范串(LF 连接),逐行核对下方 checklist
print(signed.body_hash)          # 规范串第 8 行:body_sha256_hex 的结果
print(signed.canonical_sha256)   # 规范串本身的 SHA-256(64 位小写 hex)
print(signed.signature)          # RSASSA-PKCS1v15 + SHA-256 签名,Base64,即 X-Signature 头的值
```

不经过 `RequestSigner` 也可以只用底层函数手工拼规范串(`build_request_canonical_string`
按位置参数接收 8 行的值,`canonicalize_query` 做 query 规范化,`body_sha256_hex` 算第 8 行摘要,
`sign_canonical_string` 做最终签名):

```python
from slaunchx_plutus_sdk import (
    body_sha256_hex,
    build_request_canonical_string,
    canonicalize_query,
    sign_canonical_string,
)

canonical_query = canonicalize_query("pageSize=20&status=IN_USE")
body_hash = body_sha256_hex(b'{"pageSize":20}', method="GET")  # GET 强制空体摘要,忽略传入的 body
canonical_string = build_request_canonical_string(
    "GET", "/card-products/cards/page", canonical_query,
    "1755600000123", "nonce-vector-0000000001", "1", None, body_hash,
)
signature = sign_canonical_string(private_key, canonical_string)
```

逐行核对 checklist(顺序即规范串的 8 行顺序,与 `signer.py` 的
`build_request_canonical_string` 形参顺序一致):

1. **METHOD** —— HTTP 方法是否大写。
2. **EXTERNAL_PATH** —— 是否为外部路径:不含 `/api/v1/consumer` 前缀,不含 `/prometheus`
   等源站 context-path,不含 query。参见「`base_url` 必须是对外 CONSUMER API 域名」。
3. **CANONICAL_QUERY** —— 是否已按「严格解码 → RFC 3986 重编码 → 按
   `(key, value)` 字节序排序 → 重组」规范化;无 query 时本行必须是**空串**,不是 `None` 或省略。
   本地可用 `canonicalize_query(raw_query)` 复现。
4. **TIMESTAMP** —— 是否为 Unix **毫秒**十进制字符串(不是秒),且与 `X-Timestamp` 头原值
   逐字符一致。
5. **NONCE** —— 是否与 `X-Nonce` 头原值逐字符一致,满足 `^[A-Za-z0-9._~-]{16,128}$`。
6. **API_VERSION** —— 是否与 `X-API-VERSION` 头原值一致,当前恒为 `"1"`,不可为空。
7. **IDEMPOTENCY_KEY** —— 有 `X-Idempotency-Key` 头则填其原值;**没有该头时本行必须是空串,
   不是把这一行整体去掉**(8 行结构固定,少一行会导致后续所有行错位)。
8. **BODY_SHA256_HEX** —— 是否对**实际要发送的字节**(不是发送前的业务对象、不是美化后的
   JSON)求 SHA-256,64 位小写 hex;`GET` / `HEAD` / `DELETE` 是否强制使用空体摘要
   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
   (即使这些方法实际携带了 body)。

8 行之间用 `\n`(LF)连接,末尾**不带**换行。

## 统一响应包络与成功判定

平台响应统一为下列包络:

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

`ApiResponse` 逐字段映射:`version`、`timestamp_ms`、`success_flag`、`code`、`message`、`data`;
包络之外的顶层键落入 `extras`,原始解析结果在 `json_body`。

判定算法:

```
is_success(parsed_body, http_status):
    如果 parsed_body 是 JSON 对象,且键 "success" 存在且其值是布尔类型:
        返回 该布尔值
    否则:
        返回 200 <= http_status < 300
```

- `success` 的**布尔值**是唯一权威。`success_flag` 只在该键存在且为 `bool` 时非 `None`;
  字符串 `"true"`、数字 `1`、`null` 一律不算权威,走 HTTP 2xx 回退。
  (Python 中 `isinstance(True, int)` 为真,SDK 内部一律用 `isinstance(v, bool)` 判定。)
- `code` 是**字符串**。SDK 把数字码字符串化后存入 `ApiResponse.code`,原值仍可从
  `json_body` 读取。错误码不因「看起来是数字」被丢弃 —— 业务错误码本就是 `"4022"` 这类数字字符串。
- 不要用 `code == 0` 或 `code == "0"` 判成功,平台从未使用该形态。
- `is_error` 是 `is_success` 的反面,与 HTTP 状态码无直接关系。

成功码常量仅供文档与便利判断,**不参与**上述判定:

```python
from slaunchx_plutus_sdk import SUCCESS_CODES, ACCOUNT_PENDING_APPROVAL, is_success_code

SUCCESS_CODES            # frozenset({"2000","2001","2002","2004","2006","2101"})
ACCOUNT_PENDING_APPROVAL # "2101",账号待审批:登录成功但不签发 JWT,success 仍为 true
is_success_code("2101")  # True
```

默认配置下的抛错规则:HTTP >= 400 抛 `ApiError`(`raise_on_http_error`),
包络 `success` 明确为 `False` 抛 `ApiError`(`raise_on_business_error`)。
两者合起来意味着 **HTTP 200 + `success:false` 默认会抛错**。

## 响应缺签名头的默认策略

在 `verify_response_signature=True`(默认)前提下:

| 情形 | 行为 |
| --- | --- |
| 响应带 `X-Response-Signature` | 强制验签;失败抛 `ResponseSignatureError` 并丢弃响应体 |
| HTTP 2xx 且缺签名头 | 抛 `ResponseSignatureError` |
| 非 2xx 且缺签名头 | 放行,`response.signature_verified is False`,按类型化 `ApiError` 抛出/返回 |
| 非 2xx 且缺签名头 + `require_signature_on_error_responses=True` | 抛 `ResponseSignatureError` |

严格开关是 `PlutusConfig.require_signature_on_error_responses`,默认 `False`。
SDK 不做「按状态码白名单放行」:成功响应必须可证明来源,错误响应默认放行以便拿到错误码。
被放行的响应可通过 `signature_verified is False` 识别,其内容不具备平台来源证明。

## Query 发送形态

**本 SDK 总是发送规范化后的 query,且不可配置。** `client.request` 先把 `query`
(字符串、映射或键值对序列)编码,再执行「严格解码 → RFC 3986 重编码 → 按字节序排序」的
规范化算法,规范化结果既参与签名,
也直接拼进请求 URL。原始串不会被发出。

- 规范化结果可从 `response.signed_request.canonical_query` 读取。
- 非法输入(裸保留字符含 `+`、裸非 ASCII、非法或截断的 `%XX`、解码后非 UTF-8)在本地
  抛 `CanonicalQueryError`,请求不会发出,不做任何回退。
- 空格写作 `%20`,字面加号写作 `%2B`。

## 配置项

> 协议头由 SDK 自动补齐,调用方只需配置下表字段;各字段是否进入签名串由下表说明标注。
> 平台**不读取** `X-Workspace-Id`,SDK 也不发送该头。

`PlutusConfig` 字段:

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `base_url` | `str` | 必填 | 对外 CONSUMER API 基址,尾部斜杠自动去除;不能是源站地址,不能自行拼 `/prometheus`、`/api/v1/consumer` 等内部前缀(见「`base_url` 必须是对外 CONSUMER API 域名」) |
| `api_key` | `str` | 必填 | API Key 业务 ID,填入 `X-Api-Key` |
| `merchant_auth_private_key` | PEM / 路径 / 密钥对象 | `None` | 商户认证私钥;使用 `PlutusClient` 时必填 |
| `platform_auth_public_key` | PEM / 路径 / 密钥对象 | `None` | 平台认证公钥,验响应与 Webhook 签名 |
| `platform_enc_public_key` | PEM / 路径 / 密钥对象 | `None` | 平台加密公钥,加密请求体 |
| `merchant_enc_private_key` | PEM / 路径 / 密钥对象 | `None` | 商户加密私钥,解密敏感响应与 Webhook |
| `api_version` | `str` | `"1"` | `X-API-VERSION`,参与签名;当前只服务 `1` |
| `timeout` | `float` 或 `(connect, read)` | `30.0` | requests 超时,秒 |
| `verify_response_signature` | `bool` | `True` | 是否验证响应签名。关闭仅限联调 |
| `require_signature_on_error_responses` | `bool` | `False` | 非 2xx 响应缺签名头是否也报错。2xx 缺签名头始终报错,不受此开关影响 |
| `raise_on_http_error` | `bool` | `True` | HTTP >= 400 抛出类型化 `ApiError` |
| `raise_on_business_error` | `bool` | `True` | 包络 `success` 明确为 `False` 时抛出类型化 `ApiError`(覆盖 HTTP 200 的业务失败) |
| `max_plaintext_bytes` | `int` | `1048576` | 信封明文上限,1 MiB |
| `strict_encrypted_route_validation` | `bool` | `False` | 加密请求的 `route_template` 不在 `ENCRYPTED_ROUTE_TEMPLATES` 中时是否抛错。默认仅发出 `UnknownEncryptedRouteWarning`,不阻断请求 |
| `default_headers` | `dict` | `{}` | 附加到每个请求的固定头 |
| `user_agent` | `str` | `"slaunchx-plutus-sdk-python"` | `User-Agent` |

`WebhookReceiver` 参数:

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `platform_auth_public_key` | 必填 | 验证 `X-SlaunchX-Signature` |
| `merchant_enc_private_key` | `None` | 解密信封;只验签可不传 |
| `api_key` | `None` | 传入后校验 `X-SlaunchX-Key-Id` 与之相等 |
| `timestamp_tolerance_ms` | `None` | 时间戳容差(毫秒),默认关闭 |
| `max_plaintext_bytes` | `1048576` | 解密明文上限 |

## 公开 API

| 模块 | 主要导出 |
| --- | --- |
| `client` | `PlutusClient`、`ApiResponse`、`serialize_json`、`generate_request_id`、`UnknownEncryptedRouteWarning` |
| `routes` | `ENCRYPTED_ROUTE_TEMPLATES`、`is_known_encrypted_route` |
| `result_codes` | `SUCCESS_CODES`、`ACCOUNT_PENDING_APPROVAL`、`is_success_code` |
| `config` | `PlutusConfig`、`load_private_key`、`load_public_key`、`spki_fingerprint` |
| `signer` | `RequestSigner`、`SignedRequest`、`canonicalize_query`、`encode_query`、`body_sha256_hex`、`build_request_canonical_string`、`canonical_sha256`、`sign_canonical_string`、`generate_nonce`、`validate_nonce` |
| `verifier` | `ResponseVerifier`、`build_response_canonical_string`、`response_body_sha256_hex`、`verify_signature` |
| `envelope` | `build_aad`、`parse_aad`、`encrypt_envelope`、`decrypt_envelope`、`encrypt_request_payload`、`decrypt_sensitive_response` |
| `webhook` | `WebhookReceiver`、`WebhookEvent`、`webhook_body_digest_base64`、`build_webhook_canonical_string` |
| `errors` | `PlutusError` 及其子类、`PublicErrorCode` |

全部符号也从包根 `slaunchx_plutus_sdk` 导出。

## 行为约定

- **一次序列化。** `json_body` 在 SDK 内只序列化一次,同一份字节既算 body 摘要也发送。
  自行序列化时用 `body=` 传字节,不要传对象。
- **query 严格模式。** 裸保留字符(含 `+`)、裸非 ASCII、非法或截断的 `%XX`、解码后非 UTF-8
  一律在本地抛 `CanonicalQueryError`,不做任何回退。空格写作 `%20`,字面加号写作 `%2B`。
  实际发出的 query 恒为规范化结果,不可配置(见「Query 发送形态」)。
- **GET / HEAD / DELETE 强制空 body 摘要**,且 SDK 不会发送 body,即使调用方传了。
- **响应验签默认强制。** 验签失败抛 `ResponseSignatureError`,响应体不交给业务代码。
  规范串第 2 行的请求绑定摘要由本地计算,`Content-Type` 使用响应头原值不做归一化。
  缺签名头的处理见「响应缺签名头的默认策略」。
- **成功判定只看包络的 `success` 布尔**,缺失或非布尔时回退到 HTTP 2xx;`code` 不参与判定。
- **AAD 永远本地重建。** 信封回显的 `aad` 只用于常量时间比对,不作权威值;比对通过后
  用重建的 AAD 做 GCM 解密。
- SDK 不内置自动重试。5xx / 网络错误的退避重试由调用方实现,写操作重试必须带
  `X-Idempotency-Key`。

## 测试

测试直接加载 `../shared/test-vectors.json`,覆盖全部 6 个向量分组(含拒绝用例与篡改负向),
另有加密方向的 round-trip 与客户端端到端用例:

```bash
cd python
.venv/bin/python -m pytest -q
```
