package com.slaunchx.plutus.sdk.signing;

import com.slaunchx.plutus.sdk.exception.PlutusCanonicalizationException;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;

/** Product form decoding, decoded UTF-16 sorting, Java form encoding with %20 spaces. */
public final class ProductCanonicalQuery {
    private ProductCanonicalQuery() {}

    public static String canonicalize(String query) {
        if (query == null || query.isBlank()) return "";
        var pairs = new ArrayList<Pair>();
        for (String part : query.split("&", -1)) {
            int index = part.indexOf('=');
            pairs.add(new Pair(decode(index < 0 ? part : part.substring(0, index)),
                    decode(index < 0 ? "" : part.substring(index + 1))));
        }
        pairs.sort(Comparator.comparing(Pair::key).thenComparing(Pair::value));
        var result = new ArrayList<String>();
        for (Pair pair : pairs) result.add(encode(pair.key()) + "=" + encode(pair.value()));
        return String.join("&", result);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String decode(String value) {
        // Reject malformed Unicode and percent bytes instead of silently replacing them.
        try {
            StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .encode(java.nio.CharBuffer.wrap(value));
            byte[] raw = value.getBytes(StandardCharsets.UTF_8);
            var bytes = new ByteArrayOutputStream();
            for (int i = 0; i < raw.length; i++) {
                int current = raw[i] & 255;
                if (current == '%') {
                    if (i + 2 >= raw.length) throw invalid();
                    int hi = hex(raw[++i]);
                    int lo = hex(raw[++i]);
                    if (hi < 0 || lo < 0) throw invalid();
                    bytes.write((hi << 4) | lo);
                } else {
                    bytes.write(current == '+' ? ' ' : current);
                }
            }
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes.toByteArray())).toString();
        } catch (CharacterCodingException exception) {
            throw invalid();
        }
    }

    private static int hex(byte value) {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    }
    private static PlutusCanonicalizationException invalid() {
        return new PlutusCanonicalizationException("Invalid product query encoding");
    }
    private record Pair(String key, String value) {}
}
