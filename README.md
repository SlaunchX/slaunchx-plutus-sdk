# SlaunchX Plutus 商户 SDK (monorepo)

SlaunchX Plutus 平台面向商户的官方 API SDK 集合。Java / PHP / Node.js / Python / Go
五个实现共用同一份协议规范与同一套黄金测试向量,保证跨语言行为逐字节一致。

## 定位

- **覆盖范围**:CONSUMER 门户 / API 链的商户对外接口 —— 请求签名、请求加密、响应验签、
  敏感响应解密、Webhook 验签与解密。SDK 只做传输层,不建立业务端点模型。
- **不覆盖**:平台内部 WEB 链 (system / tenant / partner 控制台)、Provider 对接、
  内部事件总线。
- **一致性依据**:[`shared/test-vectors.json`](shared/test-vectors.json)——由服务端参考实现
  生成的黄金测试向量,`shared/tools/verify_vectors.py` 可独立复算验证。各语言实现均以
  通过全部向量为准。

## 协议要点摘要

下表概览核心机制,完整实现细节与代码示例见各语言 README。

| 环节 | 机制 |
| --- | --- |
| 请求签名 | RSA-SHA256 (PKCS#1 v1.5) 对 **8 行**规范串签名 |
| Query 规范化 | 严格 percent-decode → RFC 3986 重编码 → 按 (key, value) 字节序排序 |
| Body 摘要 | 对**原始发送字节**求 SHA-256;GET / HEAD / DELETE 强制空体摘要 |
| 响应验签 | RSA-SHA256 对 **10 行**规范串签名,第 2 行绑定本次请求规范串的 SHA-256 |
| 混合加密信封 | RSA-OAEP-SHA256 包裹 AES-256-GCM 数据密钥,AAD 参与认证 |
| Webhook | 平台签名 + 加密信封,防重放靠 AAD 常量时间比对与 `deliveryBizId` 去重 |
| 统一响应包络 | `{version, timestamp, success, code, message, data}` |
| SDK 自定约定 | 缺签名头策略、query 发送形态、Webhook 容差默认值、加密端点 routeTemplate 本地校验,五语言的一致与差异见「各语言状态」一节 |
| 请求/响应头 | 逐头的必填性、格式约束、失败错误码、是否入签名串与加密 AAD、重试时的变化规则见各语言 README「配置项」一节;`X-Workspace-Id` 服务端不读取,SDK 不发送 |

`baseUrl` 必须配成商户对外可见的 **CONSUMER API 域名**,而不是源站地址或自行拼接的
`/prometheus/api/v1/consumer` 前缀——这是生产环境统计出的签名失败头号根因,
正确/错误配置对照示例见各语言 README 的 `BaseURL` / `baseUrl` 配置一节。
服务端验签失败不返回诊断信息,排障只能靠客户端自检:各语言 README 均有「签名排障」一节,
说明如何离线拿到 8 行规范串、其 SHA-256 与最终签名逐项核对。

四条跨语言硬约束:

1. **逐字节一致。** body 只序列化一次,同一份字节既用于计算摘要也用于发送。
2. **请求绑定摘要本地计算。** 响应规范串第 2 行绝不能从响应头读取。
3. **成功判定以包络的 `success` 布尔字段为唯一权威**,字段缺失时才回退 HTTP 2xx。
   不得用 `code == 0` 判成功。
4. **验签失败按安全事故处理**:丢弃响应体,不把未验证的数据交给业务代码。

## 各语言状态

五个实现均已就绪,全部通过黄金向量与各自的单元测试。

| 目录 | 语言 | 包名 / 模块 | 最低版本 | 测试数 | 安装与用法 |
| --- | --- | --- | --- | --- | --- |
| [`java/`](java/) | Java | `com.slaunchx:plutus-sdk` | Java 17 | 135 | [java/README.md](java/README.md) |
| [`php/`](php/) | PHP | `slaunchx/plutus-sdk` | PHP 8.1 | 164 | [php/README.md](php/README.md) |
| [`node/`](node/) | Node.js / TypeScript | `@slaunchx/plutus-sdk` | Node.js 18 | 230 | [node/README.md](node/README.md) |
| [`python/`](python/) | Python | `slaunchx-plutus-sdk` | Python 3.9 | 247 (另 1 跳过) | [python/README.md](python/README.md) |
| [`go/`](go/) | Go | `github.com/slaunchx/slaunchx-plutus-sdk/go` | Go 1.21 | 100 (含子测试) | [go/README.md](go/README.md) |
| [`shared/`](shared/) | — | 规范 + 向量 + 独立校验器 | — | 133 条断言 | 见下 |

各语言的测试命令:

```bash
cd java   && mvn test
cd php    && composer install && vendor/bin/phpunit
cd node   && npm install && npm test
cd python && pip install -e '.[test]' && pytest
cd go     && go test ./...
```

跨语言行为一致的部分与刻意保留差异的部分:
成功判定、缺签名头策略与 Webhook 时间戳容差五语言完全一致;query 发送形态五语言默认一致
(发送规范化结果),但 PHP 与 Node.js 额外提供开关可改回原样发送。

## 目录结构

```
slaunchx-plutus-sdk/
├── README.md                   本文件
├── .editorconfig               五语言统一的文件格式约定 (UTF-8 + LF)
├── .gitignore                  聚合各语言构建产物
├── shared/
│   ├── test-vectors.json       跨语言黄金测试向量 (由服务端真实代码生成)
│   └── tools/
│       └── verify_vectors.py   向量独立校验器 (Python,不依赖任何 SDK)
├── java/                       Java SDK    (Maven)
├── php/                        PHP SDK     (Composer)
├── node/                       Node.js SDK (npm, ESM + CJS 双产物)
├── python/                     Python SDK  (pip / setuptools)
└── go/                         Go SDK      (Go module)
```

## shared/ 的作用

### `shared/test-vectors.json`

由服务端真实实现类生成的**黄金测试向量**,是跨语言一致性的裁决依据。六组用例:

| 组 | 条数 | 内容 |
| --- | --- | --- |
| `canonicalQuery` | 21 | query 规范化,含 `expectError=true` 的拒绝用例 |
| `bodyHash` | 7 | body 摘要,含 GET / DELETE 强制空体 |
| `requestSignature` | 7 | 8 行规范串 + 逐行拆分 + 绑定摘要 + Base64 签名 + 示例头 |
| `responseSignature` | 3 | 10 行响应规范串 + 签名,通过 `requestVectorId` 关联到请求向量 |
| `encryptedEnvelope` | 3 | 固定信封 (请求方向 / 敏感响应方向) + AAD 各分量 + 期望明文 |
| `webhook` | 2 | 完整通知 (头 + 签名 + 加密 body + AAD 分量 + 期望明文) |

每个 SDK 都须覆盖以上六组用例的全部断言,作为最低测试要求。

两点必须注意:

- **向量不可修改。** 签名对字节计算,改动任何一个参与签名的字段,该条向量即作废。
- **`responseSignature` 组的 `responseBody` 只是签名载荷,不代表响应包络 schema。**
  那些示例 body 形如 `{"code":0,...}`,与真实的统一响应包络(见上文「协议要点摘要」表,
  `{version, timestamp, success, code, message, data}`)不符,保持原样不修正。
  成功判定的单元测试必须使用符合该结构的本地 fixture。

### `shared/tools/verify_vectors.py`

用 Python 独立重新实现协议并复算全部向量的校验器。它**不依赖服务端代码,
也不依赖任何 SDK**,因此向量不是自我循环:Java 生成,Python 复算。

```bash
pip install cryptography
python3 shared/tools/verify_vectors.py            # 当前输出:133 条断言全通过
python3 shared/tools/verify_vectors.py --verbose  # 打印每条断言
```

退出码 `0` 表示全部通过,`1` 表示存在失败。任何一个语言 SDK 改动协议实现后,
都应先跑这个脚本确认向量本身仍然自洽。

## 每个 SDK 的验收标准

1. 通过 `shared/test-vectors.json` 全部向量组的断言。
2. 加密方向做 round-trip 自测 (AES-GCM 使用随机 IV,密文无法静态比对)。
3. 公开 API 至少提供:签名请求构造、响应验签、加密请求构造、敏感响应解密、
   Webhook 验签与解密。
4. 成功判定以 `success` 布尔字段为唯一权威、缺签名头策略、Webhook 容差默认值、
   加密端点 routeTemplate 本地校验,均与「各语言状态」一节所述行为一致。
5. 有测试覆盖「签名字节 == 发送字节」不变量。
6. 不把私钥写入日志;错误信息不泄露密钥材料与明文。

## 安全提示

`shared/test-vectors.json` 内含 4 对 RSA-2048 私钥。它们是**为测试现场生成的一次性密钥**,
仅用于跨语言一致性校验,**绝不可用于任何真实环境**。
