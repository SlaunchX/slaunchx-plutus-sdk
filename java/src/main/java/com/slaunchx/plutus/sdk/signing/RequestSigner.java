package com.slaunchx.plutus.sdk.signing;

import com.slaunchx.plutus.sdk.crypto.Digests;
import com.slaunchx.plutus.sdk.crypto.RsaSignatures;

import java.security.interfaces.RSAPrivateKey;
import java.util.List;
import java.util.Objects;
import com.slaunchx.plutus.sdk.ProtocolProfile;

/**
 * 请求签名器(SPEC 4 节)。
 *
 * <p>规范串由 8 个字段用 LF 连接,结尾无换行:
 *
 * <pre>
 * METHOD
 * EXTERNAL_PATH
 * CANONICAL_QUERY
 * TIMESTAMP
 * NONCE
 * API_VERSION
 * IDEMPOTENCY_KEY
 * BODY_SHA256_HEX
 * </pre>
 *
 * <p>{@code X-Signature-Algorithm} 是固定字面量 {@code RSA-SHA256},<b>不参与</b>规范串。
 */
public final class RequestSigner {

    private final ProtocolProfile protocolProfile;
    private final RSAPrivateKey merchantAuthPrivateKey;

    /**
     * @param merchantAuthPrivateKey 商户认证私钥({@code merchant_auth})
     */
    public RequestSigner(RSAPrivateKey merchantAuthPrivateKey) {
        this(merchantAuthPrivateKey, ProtocolProfile.REQUEST_BOUND_V1);
    }

    public RequestSigner(RSAPrivateKey merchantAuthPrivateKey, ProtocolProfile protocolProfile) {
        this.protocolProfile = Objects.requireNonNull(protocolProfile);
        this.merchantAuthPrivateKey = merchantAuthPrivateKey;
    }

    /**
     * 拼装 8 行请求规范串。
     *
     * @param input         签名输入
     * @param bodySha256Hex 已计算好的 body 摘要
     * @return 规范串
     */
    public static String canonicalString(SigningInput input, String bodySha256Hex) {
        return canonicalString(input, bodySha256Hex, ProtocolProfile.REQUEST_BOUND_V1);
    }

    public static String canonicalString(SigningInput input, String bodySha256Hex, ProtocolProfile profile) {
        return String.join("\n", canonicalStringLines(input, bodySha256Hex, profile));
    }

    /**
     * 拼装 8 行请求规范串,返回逐行结果,便于排障比对。
     *
     * @param input         签名输入
     * @param bodySha256Hex 已计算好的 body 摘要
     * @return 8 个元素的列表
     */
    public static List<String> canonicalStringLines(SigningInput input, String bodySha256Hex) {
        return canonicalStringLines(input, bodySha256Hex, ProtocolProfile.REQUEST_BOUND_V1);
    }

    public static List<String> canonicalStringLines(SigningInput input, String bodySha256Hex, ProtocolProfile profile) {
        Objects.requireNonNull(profile);
        if (profile == ProtocolProfile.PRODUCT_V1) {
            return List.of(input.method(), input.externalPath(), ProductCanonicalQuery.canonicalize(input.rawQuery()),
                    input.timestamp(), input.nonce(), input.apiVersion(), bodySha256Hex);
        }
        return List.of(
                input.method(),
                input.externalPath(),
                CanonicalQuery.canonicalize(input.rawQuery()),
                input.timestamp(),
                input.nonce(),
                input.apiVersion(),
                input.idempotencyKey() == null ? "" : input.idempotencyKey(),
                bodySha256Hex);
    }

    /**
     * 计算规范串并签名。
     *
     * @param input 签名输入
     * @return 签名结果,含规范串、绑定摘要与 Base64 签名
     */
    public SignedRequest sign(SigningInput input) {
        String bodyHash = Digests.bodySha256Hex(input.method(), input.body());
        String canonicalQuery = protocolProfile == ProtocolProfile.PRODUCT_V1
                ? ProductCanonicalQuery.canonicalize(input.rawQuery()) : CanonicalQuery.canonicalize(input.rawQuery());
        String canonical = canonicalString(input, bodyHash, protocolProfile);
        return new SignedRequest(canonicalQuery,
                bodyHash,
                canonical,
                Digests.sha256Hex(canonical),
                RsaSignatures.sign(merchantAuthPrivateKey, canonical));
    }
}
