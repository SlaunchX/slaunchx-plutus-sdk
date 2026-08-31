package com.slaunchx.plutus.sdk.signing;

import com.slaunchx.plutus.sdk.crypto.Digests;
import com.slaunchx.plutus.sdk.crypto.RsaSignatures;

import java.security.interfaces.RSAPrivateKey;
import java.util.List;

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

    private final RSAPrivateKey merchantAuthPrivateKey;

    /**
     * @param merchantAuthPrivateKey 商户认证私钥({@code merchant_auth})
     */
    public RequestSigner(RSAPrivateKey merchantAuthPrivateKey) {
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
        return String.join("\n", canonicalStringLines(input, bodySha256Hex));
    }

    /**
     * 拼装 8 行请求规范串,返回逐行结果,便于排障比对。
     *
     * @param input         签名输入
     * @param bodySha256Hex 已计算好的 body 摘要
     * @return 8 个元素的列表
     */
    public static List<String> canonicalStringLines(SigningInput input, String bodySha256Hex) {
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
        String canonicalQuery = CanonicalQuery.canonicalize(input.rawQuery());
        String canonical = String.join("\n",
                input.method(),
                input.externalPath(),
                canonicalQuery,
                input.timestamp(),
                input.nonce(),
                input.apiVersion(),
                input.idempotencyKey() == null ? "" : input.idempotencyKey(),
                bodyHash);
        return new SignedRequest(canonicalQuery,
                bodyHash,
                canonical,
                Digests.sha256Hex(canonical),
                RsaSignatures.sign(merchantAuthPrivateKey, canonical));
    }
}
