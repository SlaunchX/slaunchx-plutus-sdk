package com.slaunchx.plutus.sdk.exception;

/**
 * 混合加密信封的封装或拆封失败。
 *
 * <p>包括 AAD 不匹配、算法标识不符、RSA-OAEP 解包失败、AES 密钥长度不为 32 字节、
 * GCM 认证失败、明文超过 1 MiB 上限等。异常消息不含明文与密钥材料。
 */
public class PlutusCryptoException extends PlutusException {

    /**
     * @param message 诊断信息
     */
    public PlutusCryptoException(String message) {
        super(message);
    }

    /**
     * @param message 诊断信息
     * @param cause   底层原因
     */
    public PlutusCryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
