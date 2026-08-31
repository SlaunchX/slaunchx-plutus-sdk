package com.slaunchx.plutus.sdk.exception;

/**
 * HTTP 传输层失败(连接、超时、中断、响应读取)。
 *
 * <p>与业务错误无关;是否重试见 SPEC 13 节的重试建议,写操作重试必须携带幂等键。
 */
public class PlutusTransportException extends PlutusException {

    /**
     * @param message 诊断信息
     * @param cause   底层原因
     */
    public PlutusTransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
