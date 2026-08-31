package com.slaunchx.plutus.sdk.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.slaunchx.plutus.sdk.exception.PlutusException;

import java.util.Optional;
import java.util.OptionalLong;

/**
 * 平台统一响应包络的解析结果。
 *
 * <p>权威结构:
 *
 * <pre>{@code
 * {
 *   "version": "2.0.0",
 *   "timestamp": 1755600000123,
 *   "success": true,
 *   "code": "2000",
 *   "message": "Success",
 *   "data": { }
 * }
 * }</pre>
 *
 * <p>SDK 只覆盖传输层,不建立业务端点模型:{@link #data()} 保持为 {@link JsonNode},
 * 由调用方按端点自行映射。
 *
 * <p><b>成功判定</b>见 {@link #successful()}:顶层 {@code success} 为布尔类型时以其为准,
 * 否则回退到 HTTP 2xx。不再使用 {@code code == 0} 之类的判定。
 *
 * <p><b>错误码</b>取顶层 {@code code}(数字则字符串化);{@code errorCode} / {@code error.code}
 * 保留为次级回退。<b>错误消息</b>取顶层 {@code message};{@code msg} / {@code error.message}
 * 保留为次级回退。业务错误码本身就是数字字符串(如 {@code "4022"}),{@link #rawCode()}
 * 原样返回,不做丢弃。原始响应体始终可通过 {@link #raw()} 获得。
 */
public final class ApiResponse {

    private final int httpStatus;
    private final JsonNode raw;
    private final String version;
    private final Long timestamp;
    private final Boolean successFlag;
    private final String rawCode;
    private final String message;
    private final JsonNode data;

    private ApiResponse(int httpStatus, JsonNode raw, String version, Long timestamp,
                        Boolean successFlag, String rawCode, String message, JsonNode data) {
        this.httpStatus = httpStatus;
        this.raw = raw;
        this.version = version;
        this.timestamp = timestamp;
        this.successFlag = successFlag;
        this.rawCode = rawCode;
        this.message = message;
        this.data = data;
    }

    /**
     * 解析响应体。
     *
     * @param mapper     Jackson 实例
     * @param httpStatus HTTP 状态码
     * @param body       原始响应体字节,允许为空
     * @return 解析结果
     * @throws PlutusException 响应体非法 JSON 时抛出
     */
    public static ApiResponse parse(ObjectMapper mapper, int httpStatus, byte[] body) {
        JsonNode root;
        if (body == null || body.length == 0) {
            root = mapper.nullNode();
        } else {
            try {
                root = mapper.readTree(body);
            } catch (Exception e) {
                throw new PlutusException("响应体不是合法 JSON: HTTP " + httpStatus, e);
            }
        }
        JsonNode error = root.path("error");
        String code = firstText(root.path("code"), root.path("errorCode"), error.path("code"));
        String message = firstText(root.path("message"), root.path("msg"), error.path("message"));
        JsonNode data = root.hasNonNull("data") ? root.get("data") : null;

        // success 只有在 JSON 布尔类型时才是权威值; 缺失 / null / 字符串 / 数字一律视为未提供。
        JsonNode successNode = root.path("success");
        Boolean successFlag = successNode.isBoolean() ? successNode.booleanValue() : null;

        JsonNode versionNode = root.path("version");
        String version = versionNode.isTextual() ? versionNode.textValue()
                : (versionNode.isMissingNode() || versionNode.isNull() ? null : versionNode.toString());

        JsonNode timestampNode = root.path("timestamp");
        Long timestamp = null;
        if (timestampNode.isNumber()) {
            timestamp = timestampNode.longValue();
        } else if (timestampNode.isTextual()) {
            try {
                timestamp = Long.valueOf(timestampNode.textValue().trim());
            } catch (NumberFormatException ignored) {
                timestamp = null;
            }
        }

        return new ApiResponse(httpStatus, root, version, timestamp, successFlag, code, message, data);
    }

    private static String firstText(JsonNode... candidates) {
        for (JsonNode node : candidates) {
            if (node != null && !node.isMissingNode() && !node.isNull()) {
                return node.isTextual() ? node.asText() : node.toString();
            }
        }
        return null;
    }

    /**
     * @return HTTP 状态码
     */
    public int httpStatus() {
        return httpStatus;
    }

    /**
     * @return 原始 JSON 树;空响应体时为 JSON null 节点
     */
    public JsonNode raw() {
        return raw;
    }

    /**
     * @return 包络版本 {@code version};不存在时为 {@code null}
     */
    public String version() {
        return version;
    }

    /**
     * @return 包络时间戳 {@code timestamp}(Unix 毫秒);不存在或无法解析为整数时为 {@code null}
     */
    public Long timestampMillis() {
        return timestamp;
    }

    /**
     * @return 包络时间戳 {@code timestamp}(Unix 毫秒);不存在或无法解析为整数时为空
     */
    public OptionalLong timestamp() {
        return timestamp == null ? OptionalLong.empty() : OptionalLong.of(timestamp);
    }

    /**
     * 权威的 {@code success} 布尔字段。
     *
     * <p>只有响应体顶层 {@code success} 是 <b>JSON 布尔类型</b>时才有值;缺失、为 {@code null}、
     * 为字符串或数字时一律为空,此时 {@link #successful()} 回退到 HTTP 2xx。
     *
     * @return {@code success} 布尔值;未以布尔类型提供时为空
     */
    public Optional<Boolean> successFlag() {
        return Optional.ofNullable(successFlag);
    }

    /**
     * @return 顶层 {@code code} 的原始字符串;不存在时为 {@code null}。业务错误码为数字字符串
     *         (如 {@code "4022"})时原样返回
     */
    public String rawCode() {
        return rawCode;
    }

    /**
     * 网关层错误码枚举。
     *
     * <p>{@link PublicErrorCode} 只登记 {@code 域.名称} 形式的对外错误码;业务层的数字错误码
     * (如 {@code "4022"})不在其中,此时返回空,原始字符串见 {@link #rawCode()}。
     *
     * @return 平台错误码枚举;未在 {@link PublicErrorCode} 中登记时为空
     */
    public Optional<PublicErrorCode> errorCode() {
        return PublicErrorCode.from(rawCode);
    }

    /**
     * @return 错误或提示消息;不存在时为 {@code null}
     */
    public String message() {
        return message;
    }

    /**
     * @return {@code data} 节点;不存在或为 JSON null 时为 {@code null}
     */
    public JsonNode data() {
        return data;
    }

    /**
     * 成功判定。
     *
     * <pre>
     * 如果响应体是 JSON 对象, 且键 "success" 存在且其值是布尔类型:
     *     返回 该布尔值
     * 否则:
     *     返回 200 &lt;= httpStatus &lt; 300
     * </pre>
     *
     * <p>成功码常量见 {@link ResultCodes},仅作文档用途,不参与本判定。
     *
     * @return 成功返回 {@code true}
     */
    public boolean successful() {
        if (successFlag != null) {
            return successFlag;
        }
        return httpStatus >= 200 && httpStatus < 300;
    }

    /**
     * 把 {@code data} 映射为业务类型。
     *
     * @param mapper Jackson 实例
     * @param type   目标类型
     * @param <T>    目标类型
     * @return 映射结果;{@code data} 不存在时为 {@code null}
     * @throws PlutusException 映射失败时抛出
     */
    public <T> T data(ObjectMapper mapper, Class<T> type) {
        if (data == null) {
            return null;
        }
        try {
            return mapper.treeToValue(data, type);
        } catch (Exception e) {
            throw new PlutusException("响应 data 无法映射为 " + type.getName(), e);
        }
    }

    @Override
    public String toString() {
        return "ApiResponse{httpStatus=" + httpStatus + ", success=" + successFlag
                + ", code=" + rawCode + ", message=" + message + '}';
    }
}
