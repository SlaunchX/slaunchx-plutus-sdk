package com.slaunchx.plutus.sdk.exception;

/**
 * 配置或密钥材料不合法。
 *
 * <p>典型场景:缺少必填配置项、PEM 解析失败、公钥不满足 SPKI / 2048-4096 位 / 指数 65537 的约束。
 */
public class PlutusConfigurationException extends PlutusException {

    /**
     * @param message 诊断信息
     */
    public PlutusConfigurationException(String message) {
        super(message);
    }

    /**
     * @param message 诊断信息
     * @param cause   底层原因
     */
    public PlutusConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
