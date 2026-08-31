package com.slaunchx.plutus.sdk.exception;

import com.slaunchx.plutus.sdk.model.ApiResponse;
import com.slaunchx.plutus.sdk.model.PublicErrorCode;

import java.util.Optional;

/**
 * 平台返回了业务或协议错误。
 *
 * <p>响应本身可能已通过验签(平台对认证成功的错误响应也签名),因此错误信息是可信的。
 */
public class PlutusApiException extends PlutusException {

    private final transient ApiResponse response;
    private final String requestId;

    /**
     * @param response  已解析的响应
     * @param requestId 响应头 {@code X-Request-Id};可为 {@code null}
     */
    public PlutusApiException(ApiResponse response, String requestId) {
        super(buildMessage(response, requestId));
        this.response = response;
        this.requestId = requestId;
    }

    private static String buildMessage(ApiResponse response, String requestId) {
        StringBuilder sb = new StringBuilder("平台返回错误: HTTP ").append(response.httpStatus());
        if (response.rawCode() != null) {
            sb.append(", code=").append(response.rawCode());
        }
        if (response.message() != null) {
            sb.append(", message=").append(response.message());
        }
        if (requestId != null) {
            sb.append(", requestId=").append(requestId);
        }
        return sb.toString();
    }

    /**
     * @return HTTP 状态码
     */
    public int httpStatus() {
        return response.httpStatus();
    }

    /**
     * @return 网关层错误码枚举;业务层数字码(如 {@code "4022"})与未知码时为空,
     *         原始字符串见 {@link ApiResponse#rawCode()}
     */
    public Optional<PublicErrorCode> errorCode() {
        return response.errorCode();
    }

    /**
     * @return 完整的解析结果,含原始 JSON 树
     */
    public ApiResponse response() {
        return response;
    }

    /**
     * @return 响应头回显的请求关联 ID;可为 {@code null}
     */
    public String requestId() {
        return requestId;
    }

    /**
     * @return 是否属于 SPEC 13 节建议重试的错误族
     */
    public boolean retryable() {
        return response.errorCode().map(PublicErrorCode::retryable).orElse(false);
    }
}
