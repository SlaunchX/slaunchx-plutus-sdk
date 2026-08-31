package com.slaunchx.plutus.sdk.signing;

import com.slaunchx.plutus.sdk.exception.PlutusCanonicalizationException;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Query 规范化(SPEC 4.2):严格解码 → RFC 3986 重编码 → 排序 → 重组。
 *
 * <p>关键规则:
 * <ul>
 *   <li>不接受任何未编码的保留字符与非 ASCII 字符,一律在本地拒绝,不做回退。</li>
 *   <li>{@code +} <b>不</b>表示空格;空格必须写作 {@code %20},字面加号写作 {@code %2B}。</li>
 *   <li>percent 十六进制输出统一大写,输入允许小写。</li>
 *   <li>过度编码会被还原:{@code %2D} 解码为 {@code -},重编码后输出裸 {@code -}。</li>
 *   <li>排序是 (key, value) 二元组的字节序,不是仅按 key。</li>
 *   <li>空值保留 {@code =};无 {@code =} 的片段补上 {@code =}。</li>
 * </ul>
 *
 * <p>规范化结果只用于签名;由于平台会对收到的原始 query 重新执行同一算法,
 * 直接发送规范化后的 query 与发送原始 query 等价。
 */
public final class CanonicalQuery {

    private CanonicalQuery() {
    }

    /**
     * 规范化原始 query 串。
     *
     * @param rawQuery 原始 query,不含前导 {@code ?};允许为 {@code null}
     * @return 规范化结果;{@code null}、空串或全空白输入返回空串
     * @throws PlutusCanonicalizationException 出现裸保留字符、裸非 ASCII、非法或截断的
     *                                         percent 转义、或解码后不是合法 UTF-8 时抛出
     */
    public static String canonicalize(String rawQuery) {
        if (rawQuery == null || rawQuery.isBlank()) {
            return "";
        }
        String[] segments = rawQuery.split("&", -1);
        List<String[]> pairs = new ArrayList<>(segments.length);
        for (String segment : segments) {
            int idx = segment.indexOf('=');
            String rawKey = idx < 0 ? segment : segment.substring(0, idx);
            String rawValue = idx < 0 ? "" : segment.substring(idx + 1);
            pairs.add(new String[]{canonicalizeComponent(rawKey), canonicalizeComponent(rawValue)});
        }
        pairs.sort(Comparator.<String[], String>comparing(p -> p[0]).thenComparing(p -> p[1]));
        StringBuilder out = new StringBuilder(rawQuery.length() + 8);
        for (int i = 0; i < pairs.size(); i++) {
            if (i > 0) {
                out.append('&');
            }
            out.append(pairs.get(i)[0]).append('=').append(pairs.get(i)[1]);
        }
        return out.toString();
    }

    /**
     * 规范化单个 query 分量(key 或 value)。
     *
     * @param component 原始分量
     * @return 严格解码后按 RFC 3986 unreserved 重编码的结果
     * @throws PlutusCanonicalizationException 分量不合规时抛出
     */
    public static String canonicalizeComponent(String component) {
        return percentEncode(percentDecodeStrict(component));
    }

    /**
     * 严格 percent 解码:只接受 unreserved 字面量与合法 {@code %XX},结果必须是合法 UTF-8。
     *
     * @param component 原始分量
     * @return 解码后的原始字节
     * @throws PlutusCanonicalizationException 分量不合规时抛出
     */
    public static byte[] percentDecodeStrict(String component) {
        int n = component.length();
        byte[] buffer = new byte[n];
        int len = 0;
        int i = 0;
        while (i < n) {
            char c = component.charAt(i);
            if (c == '%') {
                if (i + 2 >= n) {
                    throw new PlutusCanonicalizationException(
                            "query 分量存在截断的 percent 转义: " + component);
                }
                int hi = hexDigit(component.charAt(i + 1));
                int lo = hexDigit(component.charAt(i + 2));
                if (hi < 0 || lo < 0) {
                    throw new PlutusCanonicalizationException(
                            "query 分量存在非法的 percent 转义: " + component);
                }
                buffer[len++] = (byte) (hi * 16 + lo);
                i += 3;
            } else {
                if (c > 0x7F || !isUnreserved((byte) c)) {
                    throw new PlutusCanonicalizationException(
                            "query 分量存在必须 percent 编码的保留字符或非 ASCII 字符: " + component);
                }
                buffer[len++] = (byte) c;
                i++;
            }
        }
        byte[] decoded = new byte[len];
        System.arraycopy(buffer, 0, decoded, 0, len);
        requireValidUtf8(decoded, component);
        return decoded;
    }

    /**
     * 按 RFC 3986 unreserved 集合重编码。
     *
     * @param bytes 原始字节
     * @return ASCII 编码结果,percent 十六进制为大写
     */
    public static String percentEncode(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 3);
        for (byte b : bytes) {
            if (isUnreserved(b)) {
                out.append((char) (b & 0xFF));
            } else {
                out.append('%');
                out.append(Character.toUpperCase(Character.forDigit((b >> 4) & 0x0F, 16)));
                out.append(Character.toUpperCase(Character.forDigit(b & 0x0F, 16)));
            }
        }
        return out.toString();
    }

    private static void requireValidUtf8(byte[] decoded, String component) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            decoder.decode(ByteBuffer.wrap(decoded));
        } catch (CharacterCodingException e) {
            throw new PlutusCanonicalizationException(
                    "query 分量 percent 解码后不是合法 UTF-8: " + component);
        }
    }

    private static boolean isUnreserved(byte b) {
        int v = b & 0xFF;
        return (v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z') || (v >= '0' && v <= '9')
                || v == '-' || v == '.' || v == '_' || v == '~';
    }

    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }
}
