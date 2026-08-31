package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.slaunchx.plutus.sdk.exception.PlutusApiException;
import com.slaunchx.plutus.sdk.exception.PlutusException;
import com.slaunchx.plutus.sdk.model.ApiResponse;
import com.slaunchx.plutus.sdk.signing.SignedRequest;

import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * 一次调用的响应。
 *
 * <p>{@link #signatureVerified()} 为 {@code true} 表示响应签名已通过校验;
 * 配置关闭验签,或非 2xx 响应未携带签名头而被默认放行时为 {@code false}。
 * HTTP 2xx 缺签名头不会走到这里 —— 客户端直接抛
 * {@link com.slaunchx.plutus.sdk.exception.PlutusSignatureException}。
 */
public final class PlutusResponse {

    private final int statusCode;
    private final HttpHeaders headers;
    private final byte[] body;
    private final SignedRequest signedRequest;
    private final boolean signatureVerified;
    private final ObjectMapper objectMapper;

    PlutusResponse(int statusCode, HttpHeaders headers, byte[] body,
                   SignedRequest signedRequest, boolean signatureVerified, ObjectMapper objectMapper) {
        this.statusCode = statusCode;
        this.headers = headers;
        this.body = body == null ? new byte[0] : body;
        this.signedRequest = signedRequest;
        this.signatureVerified = signatureVerified;
        this.objectMapper = objectMapper;
    }

    /** @return HTTP 状态码 */
    public int statusCode() {
        return statusCode;
    }

    /** @return 响应头 */
    public HttpHeaders headers() {
        return headers;
    }

    /**
     * @param name 头名,大小写不敏感
     * @return 首个匹配的头值
     */
    public Optional<String> header(String name) {
        return headers.firstValue(name);
    }

    /** @return 原始响应体字节 */
    public byte[] body() {
        return body;
    }

    /** @return 按 UTF-8 解码的响应体 */
    public String bodyAsString() {
        return new String(body, StandardCharsets.UTF_8);
    }

    /** @return 本次请求的签名结果,含规范串与绑定摘要,便于排障 */
    public SignedRequest signedRequest() {
        return signedRequest;
    }

    /** @return 响应签名是否已通过校验 */
    public boolean signatureVerified() {
        return signatureVerified;
    }

    /**
     * @return 响应体的 JSON 树
     * @throws PlutusException 响应体非法 JSON 时抛出
     */
    public JsonNode json() {
        try {
            return objectMapper.readTree(body);
        } catch (Exception e) {
            throw new PlutusException("响应体不是合法 JSON: HTTP " + statusCode, e);
        }
    }

    /**
     * @return 按统一结构解析的响应
     */
    public ApiResponse apiResponse() {
        return ApiResponse.parse(objectMapper, statusCode, body);
    }

    /**
     * 断言调用成功,否则抛出类型化异常。
     *
     * <p>成功判定见 {@link ApiResponse#successful()}:以包络的 {@code success} 布尔字段为准,
     * 缺失时回退到 HTTP 2xx。
     *
     * @return 解析结果
     * @throws PlutusApiException 判定为失败时抛出
     */
    public ApiResponse requireSuccess() {
        ApiResponse parsed = apiResponse();
        if (!parsed.successful()) {
            throw new PlutusApiException(parsed, header(PlutusHeaders.REQUEST_ID).orElse(null));
        }
        return parsed;
    }
}
