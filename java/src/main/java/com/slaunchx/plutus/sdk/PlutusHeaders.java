package com.slaunchx.plutus.sdk;

/**
 * 协议头名常量。
 *
 * <p>线格式上 {@code X-API-VERSION} 为全大写,其余为 {@code X-Xxx-Yyy} 形式。
 * HTTP 头名本身大小写不敏感,但部分商户框架会原样透传,建议照抄。
 */
public final class PlutusHeaders {

    /** API Key 业务 ID。 */
    public static final String API_KEY = "X-Api-Key";
    /** 契约主版本,参与签名。 */
    public static final String API_VERSION = "X-API-VERSION";
    /** Unix 毫秒时间戳,参与签名。 */
    public static final String TIMESTAMP = "X-Timestamp";
    /** 一次性随机数,参与签名。 */
    public static final String NONCE = "X-Nonce";
    /** Base64 请求签名。 */
    public static final String SIGNATURE = "X-Signature";
    /** 签名算法字面量,不参与签名。 */
    public static final String SIGNATURE_ALGORITHM = "X-Signature-Algorithm";
    /** 幂等键,发送即参与签名。 */
    public static final String IDEMPOTENCY_KEY = "X-Idempotency-Key";
    /** 请求关联 ID,不参与请求签名,但参与加密请求 AAD 与响应规范串。 */
    public static final String REQUEST_ID = "X-Request-Id";
    /** 平台加密公钥指纹,加密请求必填。 */
    public static final String PLATFORM_ENCRYPTION_KEY_ID = "X-Platform-Encryption-Key-Id";
    /** 内容类型。 */
    public static final String CONTENT_TYPE = "Content-Type";

    /** 响应签名时间戳。 */
    public static final String RESPONSE_TIMESTAMP = "X-Response-Timestamp";
    /** Base64 响应签名。 */
    public static final String RESPONSE_SIGNATURE = "X-Response-Signature";
    /** 响应签名算法字面量。 */
    public static final String RESPONSE_SIGNATURE_ALGORITHM = "X-Response-Signature-Algorithm";
    /** 平台认证公钥指纹。 */
    public static final String PLATFORM_SIGNING_KEY_ID = "X-Platform-Signing-Key-Id";
    /** 幂等写操作的稳定业务恢复身份,参与响应规范串。 */
    public static final String OPERATION_ID = "X-Operation-Id";
    /** 限流退避提示。 */
    public static final String RETRY_AFTER = "Retry-After";

    private PlutusHeaders() {
    }
}
