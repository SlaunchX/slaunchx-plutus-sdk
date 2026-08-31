package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.slaunchx.plutus.sdk.exception.PlutusCanonicalizationException;
import com.slaunchx.plutus.sdk.signing.CanonicalQuery;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 向量组 canonicalQuery:21 例,含 6 例必须拒绝。 */
class CanonicalQueryVectorTest {

    static List<JsonNode> vectors() {
        return TestVectors.group("canonicalQuery");
    }

    @Test
    @DisplayName("向量条数与 meta.counts 一致")
    void countMatchesMeta() {
        assertEquals(TestVectors.declaredCount("canonicalQuery"), vectors().size());
        assertEquals(21, vectors().size());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void matchesVector(String id, String input, String expected, boolean expectError) {
        if (expectError) {
            assertThrows(PlutusCanonicalizationException.class,
                    () -> CanonicalQuery.canonicalize(input), id + " 必须被拒绝");
        } else {
            assertEquals(expected, CanonicalQuery.canonicalize(input), id);
        }
    }

    static List<org.junit.jupiter.params.provider.Arguments> cases() {
        return vectors().stream()
                .map(v -> org.junit.jupiter.params.provider.Arguments.of(
                        v.get("id").asText(),
                        TestVectors.text(v, "input"),
                        TestVectors.text(v, "expected"),
                        v.path("expectError").asBoolean(false)))
                .toList();
    }

    @Test
    @DisplayName("拒绝用例覆盖 6 条")
    void rejectionCasesArePresent() {
        long rejections = vectors().stream().filter(v -> v.path("expectError").asBoolean(false)).count();
        assertEquals(6, rejections);
    }

    @Test
    @DisplayName("负向: 未编码的分隔符与非 ASCII 一律拒绝, 不做回退")
    void additionalRejections() {
        assertThrows(PlutusCanonicalizationException.class, () -> CanonicalQuery.canonicalize("q=a b"));
        assertThrows(PlutusCanonicalizationException.class, () -> CanonicalQuery.canonicalize("q=a/b"));
        assertThrows(PlutusCanonicalizationException.class, () -> CanonicalQuery.canonicalize("q=a#b"));
        assertThrows(PlutusCanonicalizationException.class, () -> CanonicalQuery.canonicalize("q=%C3"));
    }

    @Test
    @DisplayName("空片段保留, 无等号片段补等号")
    void emptySegmentsRetained() {
        assertEquals("=&a=1", CanonicalQuery.canonicalize("a=1&"));
        assertEquals("a=1&flag=", CanonicalQuery.canonicalize("flag&a=1"));
    }

    @Test
    @DisplayName("percent 编码输出为大写十六进制")
    void percentEncodeUppercase() {
        assertEquals("%20%2B%2F", CanonicalQuery.percentEncode(" +/".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }
}
