package com.slaunchx.plutus.sdk.signing;

import com.slaunchx.plutus.sdk.crypto.RsaSignatures;
import com.slaunchx.plutus.sdk.exception.PlutusSignatureException;

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;
import com.slaunchx.plutus.sdk.ProtocolProfile;

/**
 * 响应验签器(SPEC 6 节)。
 *
 * <p>规范串共 10 行,LF 连接,无尾换行,首行是固定字面量
 * {@code SLAUNCHX-API-RESPONSE-V1}:
 *
 * <pre>
 * SLAUNCHX-API-RESPONSE-V1
 * REQUEST_CANONICAL_SHA256
 * API_VERSION
 * EXTERNAL_PATH
 * OPERATION_ID
 * REQUEST_ID
 * HTTP_STATUS
 * CONTENT_TYPE
 * RESPONSE_TIMESTAMP
 * RESPONSE_BODY_SHA256_HEX
 * </pre>
 *
 * <p>验签失败按安全事故处理:丢弃响应体,不得把未验证的数据交给业务代码。
 */
public final class ResponseVerifier {

    /** 响应规范串的固定首行。 */
    public static final String CANONICAL_PREFIX = "SLAUNCHX-API-RESPONSE-V1";

    private final ProtocolProfile protocolProfile;
    private final RSAPublicKey platformAuthPublicKey;

    /**
     * @param platformAuthPublicKey 平台认证公钥({@code platform_auth})
     */
    public ResponseVerifier(RSAPublicKey platformAuthPublicKey) {
        this(platformAuthPublicKey, ProtocolProfile.REQUEST_BOUND_V1);
    }

    public ResponseVerifier(RSAPublicKey platformAuthPublicKey, ProtocolProfile protocolProfile) {
        this.protocolProfile = Objects.requireNonNull(protocolProfile);
        this.platformAuthPublicKey = platformAuthPublicKey;
    }

    /**
     * 拼装 10 行响应规范串。
     *
     * @param context 规范串输入
     * @return 规范串
     */
    public static String canonicalString(ResponseSignatureContext context) {
        return canonicalString(context, ProtocolProfile.REQUEST_BOUND_V1);
    }

    public static String canonicalString(ResponseSignatureContext context, ProtocolProfile profile) {
        return String.join("\n", canonicalStringLines(context, profile));
    }

    /**
     * 拼装 10 行响应规范串,返回逐行结果,便于排障比对。
     *
     * @param context 规范串输入
     * @return 10 个元素的列表
     */
    public static List<String> canonicalStringLines(ResponseSignatureContext context) {
        return canonicalStringLines(context, ProtocolProfile.REQUEST_BOUND_V1);
    }

    public static List<String> canonicalStringLines(ResponseSignatureContext context, ProtocolProfile profile) {
        Objects.requireNonNull(profile);
        if (profile == ProtocolProfile.PRODUCT_V1) {
            return List.of(nullToEmpty(context.requestId()), Integer.toString(context.httpStatus()),
                    nullToEmpty(context.contentType()), nullToEmpty(context.responseTimestamp()),
                    nullToEmpty(context.responseBodySha256Hex()));
        }
        return List.of(
                CANONICAL_PREFIX,
                nullToEmpty(context.requestCanonicalSha256()),
                nullToEmpty(context.apiVersion()),
                nullToEmpty(context.externalPath()),
                nullToEmpty(context.operationId()),
                nullToEmpty(context.requestId()),
                Integer.toString(context.httpStatus()),
                nullToEmpty(context.contentType()),
                nullToEmpty(context.responseTimestamp()),
                nullToEmpty(context.responseBodySha256Hex()));
    }

    /**
     * 验签。
     *
     * @param context         规范串输入
     * @param signatureBase64 响应头 {@code X-Response-Signature}
     * @return 验签通过返回 {@code true}
     */
    public boolean verify(ResponseSignatureContext context, String signatureBase64) {
        return RsaSignatures.verify(platformAuthPublicKey, canonicalString(context, protocolProfile), signatureBase64);
    }

    /**
     * 验签,不通过即抛异常。
     *
     * @param context         规范串输入
     * @param signatureBase64 响应头 {@code X-Response-Signature}
     * @throws PlutusSignatureException 验签不通过时抛出
     */
    public void requireValid(ResponseSignatureContext context, String signatureBase64) {
        if (!verify(context, signatureBase64)) {
            throw new PlutusSignatureException(
                    "响应验签失败, 响应体已丢弃: status=" + context.httpStatus()
                            + ", path=" + context.externalPath());
        }
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
