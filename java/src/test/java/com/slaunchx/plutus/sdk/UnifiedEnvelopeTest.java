package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.slaunchx.plutus.sdk.model.ApiResponse;
import com.slaunchx.plutus.sdk.model.PublicErrorCode;
import com.slaunchx.plutus.sdk.model.ResultCodes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 统一响应包络的成功判定测试:全部使用本地 fixture,不依赖向量文件与网络。
 *
 * <p>判定算法:响应体是 JSON 对象且顶层 {@code success} 为布尔类型时以其为准,
 * 否则回退到 HTTP 2xx。
 */
class UnifiedEnvelopeTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ApiResponse parse(int httpStatus, String body) {
        return ApiResponse.parse(MAPPER, httpStatus,
                body == null ? null : body.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("标准成功: HTTP 200, success=true, code=2000")
    void standardSuccess() {
        ApiResponse parsed = parse(200,
                "{\"version\":\"2.0.0\",\"timestamp\":1755600000123,\"success\":true,"
                        + "\"code\":\"2000\",\"message\":\"Success\",\"data\":{\"ok\":true}}");
        assertTrue(parsed.successful());
        assertEquals(Boolean.TRUE, parsed.successFlag().orElseThrow());
        assertEquals("2000", parsed.rawCode());
        assertEquals("Success", parsed.message());
        assertEquals("2.0.0", parsed.version());
        assertEquals(1755600000123L, parsed.timestamp().orElseThrow());
        assertEquals(1755600000123L, parsed.timestampMillis());
        assertTrue(parsed.data().get("ok").asBoolean());
        assertTrue(parsed.errorCode().isEmpty(), "数字业务码不在 PublicErrorCode 中登记");
    }

    @Test
    @DisplayName("创建成功: HTTP 201, success=true, code=2001")
    void createdSuccess() {
        ApiResponse parsed = parse(201,
                "{\"version\":\"2.0.0\",\"timestamp\":1755600000123,\"success\":true,"
                        + "\"code\":\"2001\",\"message\":\"Created\",\"data\":{}}");
        assertTrue(parsed.successful());
        assertEquals("2001", parsed.rawCode());
    }

    @Test
    @DisplayName("待审批成功: HTTP 200, success=true, code=2101")
    void pendingApprovalIsSuccess() {
        ApiResponse parsed = parse(200,
                "{\"version\":\"2.0.0\",\"timestamp\":1755600000123,\"success\":true,"
                        + "\"code\":\"2101\",\"message\":\"Account pending approval\",\"data\":null}");
        assertTrue(parsed.successful(), "2101 是成功码, 账号待审批但登录成功");
        assertEquals(ResultCodes.ACCOUNT_PENDING_APPROVAL, parsed.rawCode());
        assertNull(parsed.data(), "data 为 JSON null 时映射为 null");
    }

    @Test
    @DisplayName("业务失败但 HTTP 200: success=false, code=4022")
    void businessFailureWithHttp200() {
        ApiResponse parsed = parse(200,
                "{\"version\":\"2.0.0\",\"timestamp\":1755600000123,\"success\":false,"
                        + "\"code\":\"4022\",\"message\":\"Validation Error\"}");
        assertFalse(parsed.successful(), "success=false 优先于 HTTP 2xx");
        assertEquals("4022", parsed.rawCode(), "数字业务错误码必须原样保留");
        assertEquals("Validation Error", parsed.message());
        assertTrue(parsed.errorCode().isEmpty(), "PublicErrorCode 只登记 域.名称 形式的码");
    }

    @Test
    @DisplayName("网关失败: HTTP 401, success=false, code=API.SIGNATURE_INVALID")
    void gatewayFailure() {
        ApiResponse parsed = parse(401,
                "{\"version\":\"2.0.0\",\"timestamp\":1755600000123,\"success\":false,"
                        + "\"code\":\"API.SIGNATURE_INVALID\",\"message\":\"signature is invalid\"}");
        assertFalse(parsed.successful());
        assertEquals("API.SIGNATURE_INVALID", parsed.rawCode());
        assertEquals(PublicErrorCode.API_SIGNATURE_INVALID, parsed.errorCode().orElseThrow());
    }

    @Test
    @DisplayName("无 success 字段: HTTP 200 回退为成功")
    void missingSuccessFieldFallsBackToHttp200() {
        ApiResponse parsed = parse(200, "{\"data\":{}}");
        assertTrue(parsed.successful());
        assertTrue(parsed.successFlag().isEmpty());
        assertNull(parsed.rawCode());
        assertNull(parsed.version());
        assertTrue(parsed.timestamp().isEmpty());
    }

    @Test
    @DisplayName("无 success 字段: HTTP 500 回退为失败")
    void missingSuccessFieldFallsBackToHttp500() {
        ApiResponse parsed = parse(500, "{\"message\":\"boom\"}");
        assertFalse(parsed.successful());
        assertTrue(parsed.successFlag().isEmpty());
        assertEquals("boom", parsed.message());
    }

    @Test
    @DisplayName("success 非布尔类型时不作数, 一律回退到 HTTP 状态码")
    void nonBooleanSuccessIsIgnored() {
        assertTrue(parse(200, "{\"success\":\"true\",\"code\":\"2000\"}").successful());
        assertFalse(parse(500, "{\"success\":\"true\"}").successful(),
                "字符串 success 不是权威值, 回退到 HTTP 500");
        assertFalse(parse(500, "{\"success\":1}").successful(), "数字 success 不是权威值");
        assertTrue(parse(200, "{\"success\":null}").successful(), "null success 不是权威值");
        assertTrue(parse(200, "{\"success\":\"true\"}").successFlag().isEmpty());
    }

    @Test
    @DisplayName("不再以 code 判定成功: code=0 且 HTTP 500 仍是失败, success=false 且 code=0 也是失败")
    void codeZeroIsNotSuccessSignal() {
        assertFalse(parse(500, "{\"code\":0}").successful());
        assertFalse(parse(200, "{\"success\":false,\"code\":0}").successful());
        assertTrue(parse(200, "{\"code\":\"API.SIGNATURE_INVALID\"}").successful(),
                "无 success 字段时只看 HTTP 状态码, 不看 code");
    }

    @Test
    @DisplayName("空响应体按 HTTP 状态码判定")
    void emptyBody() {
        assertTrue(parse(204, null).successful());
        assertTrue(parse(200, "").successful());
        assertFalse(parse(502, null).successful());
    }

    @Test
    @DisplayName("次级回退: errorCode / error.code / msg 仍可解析")
    void legacyFallbackFields() {
        ApiResponse parsed = parse(400, "{\"errorCode\":\"VALIDATION.INVALID_PARAMETER\",\"msg\":\"bad\"}");
        assertFalse(parsed.successful());
        assertEquals(PublicErrorCode.VALIDATION_INVALID_PARAMETER, parsed.errorCode().orElseThrow());
        assertEquals("bad", parsed.message());

        ApiResponse nested = parse(404,
                "{\"error\":{\"code\":\"RESOURCE.NOT_FOUND\",\"message\":\"missing\"}}");
        assertEquals(PublicErrorCode.RESOURCE_NOT_FOUND, nested.errorCode().orElseThrow());
        assertEquals("missing", nested.message());
    }

    @Test
    @DisplayName("权威 code / message 优先于次级回退字段")
    void authoritativeFieldsWin() {
        ApiResponse parsed = parse(200,
                "{\"success\":false,\"code\":\"4022\",\"message\":\"Validation Error\","
                        + "\"errorCode\":\"RESOURCE.NOT_FOUND\",\"msg\":\"ignored\"}");
        assertEquals("4022", parsed.rawCode());
        assertEquals("Validation Error", parsed.message());
    }

    @Test
    @DisplayName("成功码常量集合与判定函数")
    void successCodeConstants() {
        assertEquals(java.util.Set.of("2000", "2001", "2002", "2004", "2006", "2101"),
                ResultCodes.SUCCESS_CODES);
        assertTrue(ResultCodes.isSuccessCode("2000"));
        assertTrue(ResultCodes.isSuccessCode(ResultCodes.ACCOUNT_PENDING_APPROVAL));
        assertEquals("2101", ResultCodes.ACCOUNT_PENDING_APPROVAL);
        assertFalse(ResultCodes.isSuccessCode("4022"));
        assertFalse(ResultCodes.isSuccessCode(null));
    }
}
