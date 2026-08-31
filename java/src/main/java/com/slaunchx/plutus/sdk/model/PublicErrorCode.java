package com.slaunchx.plutus.sdk.model;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 平台对外错误码(SPEC 13 节),形式为 {@code 域.名称}。
 *
 * <p>业务判定应基于本枚举,而不是网关阶段码({@code GATEWAY_*} 形式)。
 * 平台未来可能新增错误码,{@link #from(String)} 对未知码返回空值,调用方应保留原始字符串。
 */
public enum PublicErrorCode {

    /** 缺 {@code X-Api-Key}。 */
    API_KEY_MISSING("API.KEY_MISSING", false),
    /** API Key 不存在或签名公钥未登记。 */
    API_KEY_INVALID("API.KEY_INVALID", false),
    /** API Key 已禁用。 */
    API_KEY_DISABLED("API.KEY_DISABLED", false),
    /** 连续凭据类失败触发节流锁定。 */
    API_KEY_LOCKED("API.KEY_LOCKED", false),
    /** 缺 {@code X-Timestamp}。 */
    API_TIMESTAMP_REQUIRED("API.TIMESTAMP_REQUIRED", false),
    /** {@code X-Timestamp} 非数字或不是毫秒量级。 */
    API_TIMESTAMP_INVALID("API.TIMESTAMP_INVALID", false),
    /** 时间戳超出 ±60 秒窗口;校正时钟后可重新签名重试一次。 */
    API_TIMESTAMP_EXPIRED("API.TIMESTAMP_EXPIRED", true),
    /** 缺 {@code X-API-VERSION}。 */
    API_VERSION_REQUIRED("API.VERSION_REQUIRED", false),
    /** 版本不在服务表内。 */
    API_VERSION_UNSUPPORTED("API.VERSION_UNSUPPORTED", false),
    /** 端点已下线。 */
    API_ENDPOINT_RETIRED("API.ENDPOINT_RETIRED", false),
    /** 缺 {@code X-Nonce}。 */
    API_NONCE_REQUIRED("API.NONCE_REQUIRED", false),
    /** nonce 不满足字符集或长度约束。 */
    API_NONCE_INVALID("API.NONCE_INVALID", false),
    /** nonce 重放;换新 nonce 重新签名后可重试。 */
    API_NONCE_REUSED("API.NONCE_REUSED", true),
    /** 缺 {@code X-Signature} 或 {@code X-Signature-Algorithm}。 */
    API_SIGNATURE_REQUIRED("API.SIGNATURE_REQUIRED", false),
    /** {@code X-Signature-Algorithm} 不是 {@code RSA-SHA256}。 */
    API_SIGNATURE_ALGORITHM_INVALID("API.SIGNATURE_ALGORITHM_INVALID", false),
    /** 验签失败,绝大多数是规范串拼装错误。不重试。 */
    API_SIGNATURE_INVALID("API.SIGNATURE_INVALID", false),
    /** 源 IP 不在白名单。 */
    API_IP_NOT_ALLOWED("API.IP_NOT_ALLOWED", false),
    /** 缺 workspace 上下文。 */
    API_WORKSPACE_REQUIRED("API.WORKSPACE_REQUIRED", false),
    /** workspace 不可用或类型不匹配。 */
    API_WORKSPACE_UNAVAILABLE("API.WORKSPACE_UNAVAILABLE", false),
    /** API Key 权限不足,或门户不匹配。 */
    ACCESS_PERMISSION_DENIED("ACCESS.PERMISSION_DENIED", false),
    /** 加密信封无效:AAD 不匹配 / GCM 认证失败 / 明文超限。 */
    SECURE_CHANNEL_INVALID_PAYLOAD("SECURE_CHANNEL.INVALID_PAYLOAD", false),
    /** 限流;按 {@code Retry-After} 退避重试。 */
    REQUEST_RATE_LIMITED("REQUEST.RATE_LIMITED", true),
    /** 幂等冲突或业务冲突。 */
    REQUEST_CONFLICT("REQUEST.CONFLICT", false),
    /** 乐观锁版本过期。 */
    REQUEST_STALE_VERSION("REQUEST.STALE_VERSION", false),
    /** 参数校验失败。 */
    VALIDATION_INVALID_PARAMETER("VALIDATION.INVALID_PARAMETER", false),
    /** 资源不存在。 */
    RESOURCE_NOT_FOUND("RESOURCE.NOT_FOUND", false),
    /** 平台内部错误;可指数退避重试,写操作必须带幂等键。 */
    SYSTEM_INTERNAL_ERROR("SYSTEM.INTERNAL_ERROR", true);

    private static final Map<String, PublicErrorCode> BY_CODE;

    static {
        Map<String, PublicErrorCode> index = new HashMap<>();
        for (PublicErrorCode value : values()) {
            index.put(value.code, value);
        }
        BY_CODE = Collections.unmodifiableMap(index);
    }

    private final String code;
    private final boolean retryable;

    PublicErrorCode(String code, boolean retryable) {
        this.code = code;
        this.retryable = retryable;
    }

    /**
     * @return 线格式错误码字符串,如 {@code API.SIGNATURE_INVALID}
     */
    public String code() {
        return code;
    }

    /**
     * 是否属于 SPEC 13 节建议重试的错误族。
     *
     * <p>重试必须重新生成时间戳与 nonce 并重新签名;写操作必须携带 {@code X-Idempotency-Key}。
     *
     * @return 建议重试返回 {@code true}
     */
    public boolean retryable() {
        return retryable;
    }

    /**
     * 按线格式字符串查找错误码。
     *
     * @param code 错误码字符串,允许为 {@code null}
     * @return 匹配的枚举;未知或为空时返回 {@link Optional#empty()}
     */
    public static Optional<PublicErrorCode> from(String code) {
        return code == null ? Optional.empty() : Optional.ofNullable(BY_CODE.get(code));
    }
}
