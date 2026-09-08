package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.slaunchx.plutus.sdk.crypto.PemKeys;
import com.slaunchx.plutus.sdk.exception.PlutusConfigurationException;

import java.net.URI;
import java.net.http.HttpClient;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;

/**
 * SDK 配置。
 *
 * <p>四把密钥职责严格分离,不得混用:
 * <ul>
 *   <li>{@code merchant_auth} <b>私钥</b>:对请求规范串签名。必填。</li>
 *   <li>{@code platform_auth} <b>公钥</b>:验证响应签名与 Webhook 签名。
 *       {@link Builder#verifyResponseSignature(boolean)} 为 {@code true}(默认)时必填。</li>
 *   <li>{@code merchant_enc} <b>私钥</b>:解密敏感响应与 Webhook 载荷。使用相应功能时必填。</li>
 *   <li>{@code platform_enc} <b>公钥</b>:加密请求体。调用加密端点时必填。</li>
 * </ul>
 */
public final class PlutusConfig {

    private final ProtocolProfile protocolProfile;
    private final URI baseUrl;
    private final String apiKey;
    private final String apiVersion;
    private final RSAPrivateKey merchantAuthPrivateKey;
    private final RSAPublicKey platformAuthPublicKey;
    private final RSAPrivateKey merchantEncPrivateKey;
    private final RSAPublicKey merchantEncPublicKey;
    private final RSAPublicKey platformEncPublicKey;
    private final String merchantEncFingerprint;
    private final String platformEncFingerprint;
    private final boolean verifyResponseSignature;
    private final boolean requireSignatureOnErrorResponses;
    private final boolean strictEncryptedRouteValidation;
    private final NonceGenerator nonceGenerator;
    private final HttpClient httpClient;
    private final Duration requestTimeout;
    private final ObjectMapper objectMapper;

    private PlutusConfig(Builder b) {
        if (b.protocolProfile == null) throw new PlutusConfigurationException("protocolProfile is required");
        this.protocolProfile = b.protocolProfile;
        if (b.apiKey == null || b.apiKey.isBlank()) {
            throw new PlutusConfigurationException("缺少 apiKey");
        }
        if (b.merchantAuthPrivateKeyPem == null) {
            throw new PlutusConfigurationException("缺少 merchantAuthPrivateKeyPem");
        }
        if (b.apiVersion == null || b.apiVersion.isBlank()) {
            throw new PlutusConfigurationException("apiVersion 不可为空");
        }
        this.baseUrl = b.baseUrl == null ? null : URI.create(stripTrailingSlash(b.baseUrl));
        this.apiKey = b.apiKey;
        this.apiVersion = b.apiVersion;
        this.merchantAuthPrivateKey = PemKeys.parsePrivateKey(b.merchantAuthPrivateKeyPem);
        this.platformAuthPublicKey = b.platformAuthPublicKeyPem == null
                ? null : PemKeys.parsePublicKey(b.platformAuthPublicKeyPem);
        this.merchantEncPrivateKey = b.merchantEncPrivateKeyPem == null
                ? null : PemKeys.parsePrivateKey(b.merchantEncPrivateKeyPem);
        this.platformEncPublicKey = b.platformEncPublicKeyPem == null
                ? null : PemKeys.parsePublicKey(b.platformEncPublicKeyPem);
        this.verifyResponseSignature = b.verifyResponseSignature;
        this.requireSignatureOnErrorResponses = b.requireSignatureOnErrorResponses;
        this.strictEncryptedRouteValidation = b.strictEncryptedRouteValidation;
        if (this.verifyResponseSignature && this.platformAuthPublicKey == null) {
            throw new PlutusConfigurationException(
                    "启用响应验签时必须提供 platformAuthPublicKeyPem; 如确需关闭请显式调用 verifyResponseSignature(false)");
        }

        RSAPublicKey merchantEncPublic = null;
        if (b.merchantEncPublicKeyPem != null) {
            merchantEncPublic = PemKeys.parsePublicKey(b.merchantEncPublicKeyPem);
        } else if (this.merchantEncPrivateKey != null) {
            merchantEncPublic = PemKeys.derivePublicKey(this.merchantEncPrivateKey);
        }
        this.merchantEncPublicKey = merchantEncPublic;
        this.merchantEncFingerprint = merchantEncPublic == null ? null : PemKeys.fingerprint(merchantEncPublic);
        this.platformEncFingerprint = this.platformEncPublicKey == null
                ? null : PemKeys.fingerprint(this.platformEncPublicKey);

        this.nonceGenerator = b.nonceGenerator == null ? NonceGenerator.secureRandomHex() : b.nonceGenerator;
        this.requestTimeout = b.requestTimeout == null ? Duration.ofSeconds(30) : b.requestTimeout;
        this.objectMapper = b.objectMapper == null ? new ObjectMapper() : b.objectMapper;
        this.httpClient = b.httpClient == null
                ? HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
                : b.httpClient;
    }

    private static String stripTrailingSlash(String url) {
        String trimmed = url.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    /**
     * @return 新的构造器
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * 必须是<b>对外 CONSUMER API 域名</b>,不能是源站地址,也不能自行拼接
     * {@code /prometheus}、{@code /api/v1/consumer} 等边缘/源站前缀——边缘(Cloudflare/nginx)
     * 负责把外部路径改写为源站内部路径,SDK 与商户都不应感知该改写。正确示例:
     * {@code https://<consumer-api-host>}(配合 {@code path} 传 {@code /card-products/xxx});
     * 错误示例:{@code https://origin-host/prometheus/api/v1/consumer}(签名必然失败)。
     *
     * @return 商户 API 基地址,不含路径;仅在使用 {@link PlutusClient} 时必填
     */
    public ProtocolProfile protocolProfile() { return protocolProfile; }

    public URI baseUrl() {
        return baseUrl;
    }

    /** @return API Key 业务 ID */
    public String apiKey() {
        return apiKey;
    }

    /** @return 契约主版本,默认 {@code 1} */
    public String apiVersion() {
        return apiVersion;
    }

    /** @return 商户认证私钥 */
    public RSAPrivateKey merchantAuthPrivateKey() {
        return merchantAuthPrivateKey;
    }

    /** @return 平台认证公钥;未配置时为 {@code null} */
    public RSAPublicKey platformAuthPublicKey() {
        return platformAuthPublicKey;
    }

    /** @return 商户加密私钥;未配置时为 {@code null} */
    public RSAPrivateKey merchantEncPrivateKey() {
        return merchantEncPrivateKey;
    }

    /** @return 商户加密公钥(显式配置或从私钥推导);未配置时为 {@code null} */
    public RSAPublicKey merchantEncPublicKey() {
        return merchantEncPublicKey;
    }

    /** @return 平台加密公钥;未配置时为 {@code null} */
    public RSAPublicKey platformEncPublicKey() {
        return platformEncPublicKey;
    }

    /** @return 商户加密公钥指纹,用于敏感响应 AAD 与信封 {@code keyFingerprint} 校验 */
    public String merchantEncFingerprint() {
        return merchantEncFingerprint;
    }

    /** @return 平台加密公钥指纹,用于 {@code X-Platform-Encryption-Key-Id} 与加密请求 AAD */
    public String platformEncFingerprint() {
        return platformEncFingerprint;
    }

    /** @return 是否强制验证响应签名,默认 {@code true} */
    public boolean verifyResponseSignature() {
        return verifyResponseSignature;
    }

    /**
     * 非 2xx 响应缺签名头时是否也强制验签,默认 {@code false}。
     *
     * <p>在 {@link #verifyResponseSignature()} 为 {@code true} 的前提下,响应缺少
     * {@code X-Response-Signature} 时的默认策略是:HTTP 2xx 一律抛
     * {@link com.slaunchx.plutus.sdk.exception.PlutusSignatureException};非 2xx 放行,
     * {@link PlutusResponse#signatureVerified()} 为 {@code false}。本开关打开后,非 2xx
     * 缺签名头同样抛验签异常。
     *
     * @return 严格要求错误响应携带签名返回 {@code true}
     */
    public boolean requireSignatureOnErrorResponses() {
        return requireSignatureOnErrorResponses;
    }

    /**
     * 加密端点的 routeTemplate(即请求外部路径)是否必须命中
     * {@link com.slaunchx.plutus.sdk.crypto.EncryptedRoutes} 已知表,默认 {@code false}。
     *
     * <p>关闭(默认)时,未登记路由只触发一次 WARNING 级日志,不阻断请求——避免平台新增
     * 加密端点后, 尚未升级 SDK 常量表的商户请求集体失败。打开后, 未登记路由直接抛
     * {@link com.slaunchx.plutus.sdk.exception.PlutusException},已登记路由不受影响。
     *
     * @return 是否启用加密端点路由严格校验
     */
    public boolean strictEncryptedRouteValidation() {
        return strictEncryptedRouteValidation;
    }

    /** @return nonce 生成器 */
    public NonceGenerator nonceGenerator() {
        return nonceGenerator;
    }

    /** @return HTTP 客户端 */
    public HttpClient httpClient() {
        return httpClient;
    }

    /** @return 单次请求超时 */
    public Duration requestTimeout() {
        return requestTimeout;
    }

    /** @return JSON 序列化器 */
    public ObjectMapper objectMapper() {
        return objectMapper;
    }

    /**
     * {@link PlutusConfig} 构造器。密钥以 PEM 文本传入,由 SDK 解析并校验。
     */
    public static final class Builder {

        private ProtocolProfile protocolProfile = ProtocolProfile.REQUEST_BOUND_V1;

        public Builder protocolProfile(ProtocolProfile value) { this.protocolProfile = value; return this; }

        private String baseUrl;
        private String apiKey;
        private String apiVersion = "1";
        private String merchantAuthPrivateKeyPem;
        private String platformAuthPublicKeyPem;
        private String merchantEncPrivateKeyPem;
        private String merchantEncPublicKeyPem;
        private String platformEncPublicKeyPem;
        private boolean verifyResponseSignature = true;
        private boolean requireSignatureOnErrorResponses = false;
        private boolean strictEncryptedRouteValidation = false;
        private NonceGenerator nonceGenerator;
        private HttpClient httpClient;
        private Duration requestTimeout;
        private ObjectMapper objectMapper;

        private Builder() {
        }

        /**
         * 必须是<b>对外 CONSUMER API 域名</b>,不能是源站地址,也不能自行拼接
         * {@code /prometheus}、{@code /api/v1/consumer} 等边缘/源站前缀。正确示例:
         * {@code baseUrl("https://<consumer-api-host>")},配合
         * {@code PlutusRequest.post("/card-products/10010106/shared/cards/create")}；
         * 错误示例:{@code baseUrl("https://origin-host/prometheus/api/v1/consumer")}
         * ——边缘会再次改写路径, 签名必然失败。
         *
         * @param baseUrl 商户 API 基地址,如 {@code https://consumer-api.example.com};末尾斜杠会被去除
         * @return 自身
         */
        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        /**
         * @param apiKey API Key 业务 ID,写入 {@code X-Api-Key}
         * @return 自身
         */
        public Builder apiKey(String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        /**
         * @param apiVersion 契约主版本,默认 {@code 1};参与签名,不可为空
         * @return 自身
         */
        public Builder apiVersion(String apiVersion) {
            this.apiVersion = apiVersion;
            return this;
        }

        /**
         * @param pem {@code merchant_auth} PKCS#8 私钥 PEM
         * @return 自身
         */
        public Builder merchantAuthPrivateKeyPem(String pem) {
            this.merchantAuthPrivateKeyPem = pem;
            return this;
        }

        /**
         * @param pem {@code platform_auth} SPKI 公钥 PEM
         * @return 自身
         */
        public Builder platformAuthPublicKeyPem(String pem) {
            this.platformAuthPublicKeyPem = pem;
            return this;
        }

        /**
         * @param pem {@code merchant_enc} PKCS#8 私钥 PEM
         * @return 自身
         */
        public Builder merchantEncPrivateKeyPem(String pem) {
            this.merchantEncPrivateKeyPem = pem;
            return this;
        }

        /**
         * 可选。不提供时从 {@code merchant_enc} 私钥推导,用于计算自身指纹。
         *
         * @param pem {@code merchant_enc} SPKI 公钥 PEM
         * @return 自身
         */
        public Builder merchantEncPublicKeyPem(String pem) {
            this.merchantEncPublicKeyPem = pem;
            return this;
        }

        /**
         * @param pem {@code platform_enc} SPKI 公钥 PEM
         * @return 自身
         */
        public Builder platformEncPublicKeyPem(String pem) {
            this.platformEncPublicKeyPem = pem;
            return this;
        }

        /**
         * @param verify 是否强制验证响应签名,默认 {@code true};关闭意味着放弃响应完整性保护
         * @return 自身
         */
        public Builder verifyResponseSignature(boolean verify) {
            this.verifyResponseSignature = verify;
            return this;
        }

        /**
         * 非 2xx 响应缺签名头时是否也强制验签,默认 {@code false}。
         *
         * <p>响应缺少 {@code X-Response-Signature} 时的默认策略:HTTP 2xx 一律抛
         * {@link com.slaunchx.plutus.sdk.exception.PlutusSignatureException},不把未验证的数据
         * 交给业务代码;非 2xx 默认放行,{@link PlutusResponse#signatureVerified()} 为
         * {@code false},调用方仍可读到平台返回的错误码。打开本开关后,非 2xx 缺签名头也抛
         * 验签异常。
         *
         * <p>本开关只在 {@link #verifyResponseSignature(boolean)} 为 {@code true} 时生效。
         *
         * @param require 是否严格要求错误响应携带签名,默认 {@code false}
         * @return 自身
         */
        public Builder requireSignatureOnErrorResponses(boolean require) {
            this.requireSignatureOnErrorResponses = require;
            return this;
        }

        /**
         * 加密端点的 routeTemplate 是否必须命中
         * {@link com.slaunchx.plutus.sdk.crypto.EncryptedRoutes} 已知表,默认 {@code false}。
         *
         * <p>默认(非严格)模式下,未登记路由只触发一次 WARNING 级日志提示,不阻断请求——
         * 平台新增加密端点是可预期的演进,若直接拒绝会让尚未升级 SDK 常量表的商户请求集体
         * 失败。打开严格模式后,未登记路由直接抛
         * {@link com.slaunchx.plutus.sdk.exception.PlutusException},已登记路由不受影响;
         * 适合需要提前发现路径拼写错误或平台端点变更的商户。
         *
         * @param strict 是否启用严格校验,默认 {@code false}
         * @return 自身
         */
        public Builder strictEncryptedRouteValidation(boolean strict) {
            this.strictEncryptedRouteValidation = strict;
            return this;
        }

        /**
         * @param generator 自定义 nonce 生成器,默认为 32 字符十六进制
         * @return 自身
         */
        public Builder nonceGenerator(NonceGenerator generator) {
            this.nonceGenerator = generator;
            return this;
        }

        /**
         * @param httpClient 自定义 JDK HTTP 客户端
         * @return 自身
         */
        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        /**
         * @param timeout 单次请求超时,默认 30 秒
         * @return 自身
         */
        public Builder requestTimeout(Duration timeout) {
            this.requestTimeout = timeout;
            return this;
        }

        /**
         * @param mapper 自定义 Jackson 实例
         * @return 自身
         */
        public Builder objectMapper(ObjectMapper mapper) {
            this.objectMapper = mapper;
            return this;
        }

        /**
         * @return 配置实例
         * @throws PlutusConfigurationException 必填项缺失或密钥不合规时抛出
         */
        public PlutusConfig build() {
            return new PlutusConfig(this);
        }
    }
}
