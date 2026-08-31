package com.slaunchx.plutus.sdk.exception;

/**
 * Query 规范化失败。
 *
 * <p>按 SPEC 4.2,原始 query 中出现裸保留字符、裸非 ASCII 字符、非法或截断的 percent 转义、
 * 或 percent 解码后不是合法 UTF-8 时,一律在本地拒绝,不发出必然被平台拒绝的请求。
 */
public class PlutusCanonicalizationException extends PlutusException {

    /**
     * @param message 诊断信息
     */
    public PlutusCanonicalizationException(String message) {
        super(message);
    }
}
