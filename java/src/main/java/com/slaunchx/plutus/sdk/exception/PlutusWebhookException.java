package com.slaunchx.plutus.sdk.exception;

/**
 * Webhook 投递处理失败:传输头缺失、验签失败、信封形状不合规、解密失败或明文交叉校验不通过。
 */
public class PlutusWebhookException extends PlutusException {

    /**
     * @param message 诊断信息
     */
    public PlutusWebhookException(String message) {
        super(message);
    }

    /**
     * @param message 诊断信息
     * @param cause   底层原因
     */
    public PlutusWebhookException(String message, Throwable cause) {
        super(message, cause);
    }
}
