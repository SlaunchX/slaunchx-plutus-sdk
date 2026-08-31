package com.slaunchx.plutus.sdk.exception;

/**
 * SDK 所有异常的基类。
 *
 * <p>为非受检异常,便于在函数式调用链中使用。异常消息不包含私钥材料与解密后的明文。
 */
public class PlutusException extends RuntimeException {

    /**
     * @param message 诊断信息
     */
    public PlutusException(String message) {
        super(message);
    }

    /**
     * @param message 诊断信息
     * @param cause   底层原因
     */
    public PlutusException(String message, Throwable cause) {
        super(message, cause);
    }
}
