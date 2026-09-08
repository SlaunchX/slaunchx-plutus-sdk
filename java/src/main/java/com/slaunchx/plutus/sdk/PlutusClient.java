package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.slaunchx.plutus.sdk.crypto.Digests;
import com.slaunchx.plutus.sdk.crypto.EncryptedRoutes;
import com.slaunchx.plutus.sdk.crypto.EncryptionAad;
import com.slaunchx.plutus.sdk.crypto.Envelope;
import com.slaunchx.plutus.sdk.crypto.EnvelopeCodec;
import com.slaunchx.plutus.sdk.crypto.RsaSignatures;
import com.slaunchx.plutus.sdk.exception.PlutusApiException;
import com.slaunchx.plutus.sdk.exception.PlutusConfigurationException;
import com.slaunchx.plutus.sdk.exception.PlutusCryptoException;
import com.slaunchx.plutus.sdk.exception.PlutusException;
import com.slaunchx.plutus.sdk.exception.PlutusSignatureException;
import com.slaunchx.plutus.sdk.exception.PlutusTransportException;
import com.slaunchx.plutus.sdk.model.ApiResponse;
import com.slaunchx.plutus.sdk.signing.RequestSigner;
import com.slaunchx.plutus.sdk.signing.ResponseSignatureContext;
import com.slaunchx.plutus.sdk.signing.ResponseVerifier;
import com.slaunchx.plutus.sdk.signing.SignedRequest;
import com.slaunchx.plutus.sdk.signing.SigningInput;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.UUID;

/**
 * 商户 API 客户端:组装协议头、序列化一次 body、对同一份字节签名并发送、校验响应签名。
 *
 * <p>典型用法:
 *
 * <pre>{@code
 * PlutusConfig config = PlutusConfig.builder()
 *         .baseUrl("https://consumer-api.example.com")
 *         .apiKey("apk_xxx")
 *         .merchantAuthPrivateKeyPem(merchantAuthPrivatePem)
 *         .platformAuthPublicKeyPem(platformAuthPublicPem)
 *         .build();
 * try (PlutusClient client = new PlutusClient(config)) {
 *     ApiResponse response = client.call(PlutusRequest.get("/card-products/cards/page")
 *             .queryParam("pageSize", "20")
 *             .build());
 * }
 * }</pre>
 *
 * <p>本类线程安全,建议按 API Key 复用单个实例。
 */
public final class PlutusClient implements AutoCloseable {

    private static final System.Logger LOGGER = System.getLogger(PlutusClient.class.getName());

    private final PlutusConfig config;
    private final RequestSigner signer;
    private final ResponseVerifier verifier;
    private final EnvelopeCodec envelopeCodec;

    /**
     * @param config SDK 配置
     */
    public PlutusClient(PlutusConfig config) {
        if (config.baseUrl() == null) {
            throw new PlutusConfigurationException("使用 PlutusClient 时必须配置 baseUrl");
        }
        this.config = config;
        this.signer = new RequestSigner(config.merchantAuthPrivateKey(), config.protocolProfile());
        this.verifier = config.platformAuthPublicKey() == null
                ? null : new ResponseVerifier(config.platformAuthPublicKey(), config.protocolProfile());
        this.envelopeCodec = new EnvelopeCodec();
    }

    /**
     * @return 当前配置
     */
    public PlutusConfig config() {
        return config;
    }

    /**
     * 发起一次调用:签名、发送、按配置验证响应签名。不对业务错误码抛异常。
     *
     * @param request 请求描述
     * @return 响应
     * @throws PlutusSignatureException 响应验签失败
     * @throws PlutusTransportException 传输层失败
     */
    public PlutusResponse request(PlutusRequest request) {
        String timestamp = Long.toString(System.currentTimeMillis());
        String nonce = config.nonceGenerator().generate();
        if (!NonceGenerator.isValid(nonce)) {
            throw new PlutusException("nonce 不满足 [A-Za-z0-9._~-]{16,128} 约束");
        }
        String requestId = request.requestId();
        if (config.protocolProfile() == ProtocolProfile.PRODUCT_V1) {
            var ids = request.extraHeaders().entrySet().stream()
                    .filter(entry -> entry.getKey().equalsIgnoreCase(PlutusHeaders.REQUEST_ID)).toList();
            if (ids.size() > 1 || (!ids.isEmpty() && requestId != null)) {
                throw new PlutusException("X-Request-Id must not be specified more than once");
            }
            if (!ids.isEmpty()) requestId = ids.get(0).getValue();
            if (requestId != null && (requestId.contains("\r") || requestId.contains("\n"))) {
                throw new PlutusException("X-Request-Id must not contain newlines");
            }
            requestId = requestId == null ? "" : requestId.trim();
            if (requestId.isEmpty()) requestId = "req_" + UUID.randomUUID().toString().replace("-", "");
        }
        if (request.encrypted() && (requestId == null || requestId.isBlank())) {
            requestId = "req_" + UUID.randomUUID().toString().replace("-", "");
        }

        byte[] wireBody = serializeBody(request);
        String platformEncKeyId = null;
        if (request.encrypted()) {
            if (config.platformEncPublicKey() == null) {
                throw new PlutusConfigurationException("加密端点调用必须配置 platformEncPublicKeyPem");
            }
            if (!EncryptedRoutes.isKnown(request.path())) {
                if (config.strictEncryptedRouteValidation()) {
                    throw new PlutusException(
                            "加密请求的外部路径不在 EncryptedRoutes 已知表中: "
                                    + request.method() + " " + request.path()
                                    + "; 如确认该路径是平台新增的加密端点, 请关闭 strictEncryptedRouteValidation"
                                    + " 或升级 SDK 版本");
                }
                LOGGER.log(Level.WARNING,
                        "加密请求的外部路径 {0} {1} 不在 EncryptedRoutes 已知表中, "
                                + "可能是路径拼写错误, 也可能是平台新增了加密端点而 SDK 常量表尚未同步; "
                                + "请求继续正常发送, 如需强校验请开启 strictEncryptedRouteValidation",
                        request.method(), request.path());
            }
            platformEncKeyId = config.platformEncFingerprint();
            EncryptionAad aad = EncryptionAad.forEncryptedRequest(
                    requestId, request.path(), timestamp, platformEncKeyId);
            Envelope envelope = envelopeCodec.seal(wireBody == null ? new byte[0] : wireBody,
                    config.platformEncPublicKey(), platformEncKeyId, aad);
            wireBody = writeJson(envelope.toMap());
        }

        SigningInput input = new SigningInput(request.method(), request.path(), request.rawQuery(),
                timestamp, nonce, config.apiVersion(), request.idempotencyKey(), wireBody);
        SignedRequest signed = signer.sign(input);

        HttpRequest.Builder http = HttpRequest.newBuilder()
                .uri(buildUri(request.path(), signed.canonicalQuery()))
                .timeout(config.requestTimeout())
                .method(request.method(), wireBody == null || wireBody.length == 0
                        ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofByteArray(wireBody));

        for (Map.Entry<String, String> entry : request.extraHeaders().entrySet()) {
            if (config.protocolProfile() == ProtocolProfile.PRODUCT_V1
                    && entry.getKey().equalsIgnoreCase(PlutusHeaders.REQUEST_ID)) continue;
            http.header(entry.getKey(), entry.getValue());
        }
        http.header(PlutusHeaders.API_KEY, config.apiKey());
        http.header(PlutusHeaders.API_VERSION, config.apiVersion());
        http.header(PlutusHeaders.TIMESTAMP, timestamp);
        http.header(PlutusHeaders.NONCE, nonce);
        http.header(PlutusHeaders.SIGNATURE, signed.signatureBase64());
        http.header(PlutusHeaders.SIGNATURE_ALGORITHM, RsaSignatures.ALGORITHM_HEADER_VALUE);
        if (request.idempotencyKey() != null) {
            http.header(PlutusHeaders.IDEMPOTENCY_KEY, request.idempotencyKey());
        }
        if (requestId != null && !requestId.isBlank()) {
            http.header(PlutusHeaders.REQUEST_ID, requestId);
        }
        if (platformEncKeyId != null) {
            http.header(PlutusHeaders.PLATFORM_ENCRYPTION_KEY_ID, platformEncKeyId);
        }
        if (wireBody != null && wireBody.length > 0) {
            http.header(PlutusHeaders.CONTENT_TYPE,
                    request.contentType() == null ? "application/json" : request.contentType());
        } else if (request.contentType() != null) {
            http.header(PlutusHeaders.CONTENT_TYPE, request.contentType());
        }

        HttpResponse<byte[]> httpResponse;
        try {
            httpResponse = config.httpClient().send(http.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new PlutusTransportException("请求发送失败: " + request.method() + " " + request.path(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PlutusTransportException("请求被中断: " + request.method() + " " + request.path(), e);
        }

        boolean verified = verifyResponse(request, signed, httpResponse, requestId);
        return new PlutusResponse(httpResponse.statusCode(), httpResponse.headers(), httpResponse.body(),
                signed, verified, config.objectMapper());
    }

    /**
     * 发起调用并断言业务成功。
     *
     * @param request 请求描述
     * <p>成功判定以统一响应包络的 {@code success} 布尔字段为准,缺失时回退到 HTTP 2xx,
     * 详见 {@link ApiResponse#successful()}。
     *
     * @return 解析后的统一响应
     * @throws PlutusApiException 判定为失败时抛出
     */
    public ApiResponse call(PlutusRequest request) {
        return request(request).requireSuccess();
    }

    /**
     * 解密敏感响应信封。
     *
     * <p>AAD 按 SPEC 9 节重建:{@code routeTemplate} 固定为空串,{@code keyId} 为商户加密公钥
     * 指纹,{@code timestamp} 从信封回显的 {@code aad} 中解析(平台生成的时间戳在响应体外无处可得)。
     * 重建后与回显值做常量时间比对,再用重建的 AAD 解密。
     *
     * @param envelopeNode 响应体中的信封 JSON 节点
     * @param requestId    本次请求的关联 ID;无关联上下文时传空串
     * @return 明文字符串
     * @throws PlutusCryptoException 指纹不符、AAD 不一致或解密失败时抛出
     */
    public String decryptSensitivePayload(JsonNode envelopeNode, String requestId) {
        return decryptSensitivePayload(Envelope.fromJson(envelopeNode), requestId);
    }

    /**
     * 解密敏感响应信封。
     *
     * @param envelope  信封
     * @param requestId 本次请求的关联 ID;无关联上下文时传空串
     * @return 明文字符串
     * @throws PlutusCryptoException 指纹不符、AAD 不一致或解密失败时抛出
     */
    public String decryptSensitivePayload(Envelope envelope, String requestId) {
        if (config.merchantEncPrivateKey() == null) {
            throw new PlutusConfigurationException("解密敏感响应必须配置 merchantEncPrivateKeyPem");
        }
        envelope.requireApiShape();
        String fingerprint = config.merchantEncFingerprint();
        if (!fingerprint.equals(envelope.keyFingerprint())) {
            throw new PlutusCryptoException(
                    "信封 keyFingerprint 与商户加密公钥指纹不一致, 可能是密钥轮换未生效");
        }
        String timestamp = EncryptionAad.parseBase64(envelope.aad()).timestamp();
        EncryptionAad expected = EncryptionAad.forSensitiveResponse(
                requestId == null ? "" : requestId, timestamp, fingerprint);
        return envelopeCodec.openToString(envelope, config.merchantEncPrivateKey(), expected);
    }

    /**
     * 单独封装一份加密请求载荷,便于自行发送或排障。
     *
     * @param plaintext    明文字节
     * @param externalPath 端点外部路径,用作 AAD 的 {@code routeTemplate}
     * @param requestId    {@code X-Request-Id},必填非空
     * @param timestamp    {@code X-Timestamp},与签名使用同一个值
     * @return 信封
     */
    public Envelope encryptRequestPayload(byte[] plaintext, String externalPath,
                                          String requestId, String timestamp) {
        if (config.platformEncPublicKey() == null) {
            throw new PlutusConfigurationException("加密请求必须配置 platformEncPublicKeyPem");
        }
        if (requestId == null || requestId.isBlank()) {
            throw new PlutusCryptoException("加密请求的 X-Request-Id 不可为空");
        }
        EncryptionAad aad = EncryptionAad.forEncryptedRequest(
                requestId, externalPath, timestamp, config.platformEncFingerprint());
        return envelopeCodec.seal(plaintext, config.platformEncPublicKey(),
                config.platformEncFingerprint(), aad);
    }

    /**
     * 空操作,仅为支持 try-with-resources 写法。
     *
     * <p>SDK 以 Java 17 为编译目标,{@code java.net.http.HttpClient} 在该版本尚未实现
     * {@code AutoCloseable};底层连接由 JDK 自行回收。
     */
    @Override
    public void close() {
        // no-op
    }

    private boolean verifyResponse(PlutusRequest request, SignedRequest signed,
                                   HttpResponse<byte[]> httpResponse, String sentRequestId) {
        if (!config.verifyResponseSignature()) {
            return false;
        }
        String signature = httpResponse.headers()
                .firstValue(PlutusHeaders.RESPONSE_SIGNATURE).orElse(null);
        if (signature == null) {
            // SPEC「SDK 约定 (非平台契约)」: 平台契约未穷举哪些状态码不带响应签名,
            // 因此不按状态码白名单放行。SDK 统一约定: HTTP 2xx 缺签名头一律视为异常,
            // 不把未验证的数据交给业务代码; 非 2xx 缺签名头默认放行, 让调用方读到平台错误码,
            // 此时 signatureVerified 为 false。requireSignatureOnErrorResponses 打开后,
            // 非 2xx 缺签名头同样抛验签异常。
            boolean http2xx = httpResponse.statusCode() >= 200 && httpResponse.statusCode() < 300;
            if (!http2xx && !config.requireSignatureOnErrorResponses()) {
                return false;
            }
            throw new PlutusSignatureException(
                    "响应缺少 " + PlutusHeaders.RESPONSE_SIGNATURE + " 头: status="
                            + httpResponse.statusCode()
                            + "; 如确需接受未签名响应请关闭 verifyResponseSignature"
                            + (http2xx ? "" : ", 或关闭 requireSignatureOnErrorResponses"));
        }
        String responseRequestId = httpResponse.headers().firstValue(PlutusHeaders.REQUEST_ID).orElse(null);
        if (responseRequestId == null && config.protocolProfile() == ProtocolProfile.PRODUCT_V1) {
            if (sentRequestId == null || sentRequestId.isBlank()) {
                throw new PlutusSignatureException("product response missing X-Request-Id and no sent ID retained");
            }
            responseRequestId = sentRequestId;
        }
        ResponseSignatureContext context = new ResponseSignatureContext(
                signed.requestCanonicalSha256(),
                config.apiVersion(),
                request.path(),
                httpResponse.headers().firstValue(PlutusHeaders.OPERATION_ID).orElse(null),
                responseRequestId,
                httpResponse.statusCode(),
                httpResponse.headers().firstValue(PlutusHeaders.CONTENT_TYPE).orElse(null),
                httpResponse.headers().firstValue(PlutusHeaders.RESPONSE_TIMESTAMP).orElse(null),
                Digests.sha256Hex(httpResponse.body() == null ? new byte[0] : httpResponse.body()));
        verifier.requireValid(context, signature);
        return true;
    }

    private byte[] serializeBody(PlutusRequest request) {
        if (request.body() != null) {
            return request.body();
        }
        if (request.jsonBody() != null) {
            return writeJson(request.jsonBody());
        }
        return null;
    }

    private byte[] writeJson(Object value) {
        try {
            return config.objectMapper().writeValueAsBytes(value);
        } catch (Exception e) {
            throw new PlutusException("请求体 JSON 序列化失败", e);
        }
    }

    private URI buildUri(String path, String canonicalQuery) {
        StringBuilder sb = new StringBuilder(config.baseUrl().toString()).append(path);
        if (canonicalQuery != null && !canonicalQuery.isEmpty()) {
            sb.append('?').append(canonicalQuery);
        }
        return URI.create(sb.toString());
    }
}
