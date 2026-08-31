package com.slaunchx.plutus.sdk;

import com.slaunchx.plutus.sdk.exception.PlutusException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 一次商户 API 调用的描述。
 *
 * <p>路径必须是<b>外部路径</b>:以 {@code /} 开头,不含 {@code /api}、{@code /v1}、
 * {@code /consumer} 等链、版本、门户前缀;版本走 {@code X-API-VERSION} 头。
 *
 * <p>body 有两种给法:{@link Builder#body(byte[])} 直接给字节,或
 * {@link Builder#jsonBody(Object)} 交由 SDK 序列化一次。无论哪种,SDK 都只序列化一次,
 * 对同一份字节计算摘要并发送。
 */
public final class PlutusRequest {

    private final String method;
    private final String path;
    private final String rawQuery;
    private final byte[] body;
    private final Object jsonBody;
    private final String contentType;
    private final String idempotencyKey;
    private final String requestId;
    private final boolean encrypted;
    private final Map<String, String> extraHeaders;

    private PlutusRequest(Builder b) {
        if (b.method == null || b.method.isBlank()) {
            throw new PlutusException("请求缺少 method");
        }
        if (b.path == null || !b.path.startsWith("/")) {
            throw new PlutusException("外部路径必须以 / 开头: " + b.path);
        }
        if (b.path.contains("?")) {
            throw new PlutusException("外部路径不得包含 query, 请使用 query(...)");
        }
        if (b.body != null && b.jsonBody != null) {
            throw new PlutusException("body 与 jsonBody 只能二选一");
        }
        this.method = b.method;
        this.path = b.path;
        this.rawQuery = buildRawQuery(b);
        this.body = b.body;
        this.jsonBody = b.jsonBody;
        this.contentType = b.contentType;
        this.idempotencyKey = b.idempotencyKey;
        this.requestId = b.requestId;
        this.encrypted = b.encrypted;
        this.extraHeaders = Collections.unmodifiableMap(new LinkedHashMap<>(b.extraHeaders));
    }

    private static String buildRawQuery(Builder b) {
        if (b.rawQuery != null) {
            return b.rawQuery;
        }
        if (b.queryParams.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (String[] kv : b.queryParams) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(kv[0]).append('=').append(kv[1]);
        }
        return sb.toString();
    }

    /**
     * @return 新的构造器
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * @param path 外部路径
     * @return 预置为 GET 的构造器
     */
    public static Builder get(String path) {
        return builder().method("GET").path(path);
    }

    /**
     * @param path 外部路径
     * @return 预置为 POST 的构造器
     */
    public static Builder post(String path) {
        return builder().method("POST").path(path);
    }

    /**
     * @param path 外部路径
     * @return 预置为 DELETE 的构造器
     */
    public static Builder delete(String path) {
        return builder().method("DELETE").path(path);
    }

    /** @return HTTP 方法 */
    public String method() {
        return method;
    }

    /** @return 外部路径 */
    public String path() {
        return path;
    }

    /** @return 原始 query 串;无 query 时为 {@code null} */
    public String rawQuery() {
        return rawQuery;
    }

    /** @return 直接给定的 body 字节;未给定时为 {@code null} */
    public byte[] body() {
        return body;
    }

    /** @return 待序列化的 body 对象;未给定时为 {@code null} */
    public Object jsonBody() {
        return jsonBody;
    }

    /** @return 自定义 {@code Content-Type};未给定时由 SDK 按有无 body 决定 */
    public String contentType() {
        return contentType;
    }

    /** @return 幂等键;为 {@code null} 时不发送该头,规范串第 7 行为空 */
    public String idempotencyKey() {
        return idempotencyKey;
    }

    /** @return {@code X-Request-Id};为 {@code null} 时加密请求会自动生成 */
    public String requestId() {
        return requestId;
    }

    /** @return 是否为加密端点调用 */
    public boolean encrypted() {
        return encrypted;
    }

    /** @return 附加头,不覆盖协议头 */
    public Map<String, String> extraHeaders() {
        return extraHeaders;
    }

    /**
     * {@link PlutusRequest} 构造器。
     */
    public static final class Builder {

        private String method;
        private String path;
        private String rawQuery;
        private final List<String[]> queryParams = new ArrayList<>();
        private byte[] body;
        private Object jsonBody;
        private String contentType;
        private String idempotencyKey;
        private String requestId;
        private boolean encrypted;
        private final Map<String, String> extraHeaders = new LinkedHashMap<>();

        private Builder() {
        }

        /**
         * @param method HTTP 方法,建议大写
         * @return 自身
         */
        public Builder method(String method) {
            this.method = method;
            return this;
        }

        /**
         * @param path 外部路径
         * @return 自身
         */
        public Builder path(String path) {
            this.path = path;
            return this;
        }

        /**
         * 直接给定原始 query 串。与 {@link #queryParam(String, String)} 互斥,后者会被忽略。
         *
         * @param rawQuery 原始 query,不含前导 {@code ?};必须已按 RFC 3986 编码,
         *                 出现裸保留字符时会在签名阶段被拒绝
         * @return 自身
         */
        public Builder query(String rawQuery) {
            this.rawQuery = rawQuery;
            return this;
        }

        /**
         * 追加一个 query 参数。键与值会按 RFC 3986 unreserved 集合 percent 编码,
         * 空格编为 {@code %20},加号编为 {@code %2B}。
         *
         * @param name  参数名
         * @param value 参数值,{@code null} 按空串处理
         * @return 自身
         */
        public Builder queryParam(String name, String value) {
            String encodedName = com.slaunchx.plutus.sdk.signing.CanonicalQuery
                    .percentEncode(name.getBytes(StandardCharsets.UTF_8));
            String encodedValue = com.slaunchx.plutus.sdk.signing.CanonicalQuery
                    .percentEncode((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
            queryParams.add(new String[]{encodedName, encodedValue});
            return this;
        }

        /**
         * @param body 已序列化的 body 字节,SDK 原样摘要并发送
         * @return 自身
         */
        public Builder body(byte[] body) {
            this.body = body;
            return this;
        }

        /**
         * @param body UTF-8 文本 body
         * @return 自身
         */
        public Builder body(String body) {
            this.body = body == null ? null : body.getBytes(StandardCharsets.UTF_8);
            return this;
        }

        /**
         * @param jsonBody 交由 SDK 用配置的 Jackson 实例序列化一次的对象
         * @return 自身
         */
        public Builder jsonBody(Object jsonBody) {
            this.jsonBody = jsonBody;
            return this;
        }

        /**
         * @param contentType 自定义 {@code Content-Type}
         * @return 自身
         */
        public Builder contentType(String contentType) {
            this.contentType = contentType;
            return this;
        }

        /**
         * @param idempotencyKey 幂等键;发送即参与签名。同一幂等键必须配同一份请求内容
         * @return 自身
         */
        public Builder idempotencyKey(String idempotencyKey) {
            this.idempotencyKey = idempotencyKey;
            return this;
        }

        /**
         * @param requestId {@code X-Request-Id};加密请求必填,未给定时由 SDK 生成
         * @return 自身
         */
        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        /**
         * 标记为加密端点调用:body 会被封装为混合加密信封,签名对信封字节计算,
         * 并自动补齐 {@code X-Request-Id} 与 {@code X-Platform-Encryption-Key-Id}。
         *
         * @param encrypted 是否加密
         * @return 自身
         */
        public Builder encrypted(boolean encrypted) {
            this.encrypted = encrypted;
            return this;
        }

        /**
         * @param name  头名
         * @param value 头值
         * @return 自身
         */
        public Builder header(String name, String value) {
            extraHeaders.put(name, value);
            return this;
        }

        /**
         * @return 请求实例
         */
        public PlutusRequest build() {
            return new PlutusRequest(this);
        }
    }
}
