package com.slaunchx.plutus.sdk.exception;

/**
 * 签名生成或验签失败。
 *
 * <p>响应验签失败按安全事故处理:调用方不得使用响应体中的任何数据。
 */
public class PlutusSignatureException extends PlutusException {

    /**
     * @param message 诊断信息
     */
    public PlutusSignatureException(String message) {
        super(message);
    }

    /**
     * @param message 诊断信息
     * @param cause   底层原因
     */
    public PlutusSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
