package com.slaunchx.plutus.sdk;

import com.slaunchx.plutus.sdk.crypto.EncryptedRoutes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link EncryptedRoutes} 常量表:恰好包含 SPEC 3 节列出的 6 条强制加密端点,逐字节比对。
 */
class EncryptedRoutesTest {

    /** SPEC 3 节「强制加密的请求体」表,routeTemplate 与方法逐字节抄录。 */
    private static final List<String[]> EXPECTED = List.of(
            new String[]{"/card-products/10010105/cards/create", "POST"},
            new String[]{"/card-products/10010106/shared/cards/create", "POST"},
            new String[]{"/card-products/10010106/prepaid/cards/create", "POST"},
            new String[]{"/card-products/10010107/prepaid/cards/create", "POST"},
            new String[]{"/card-products/10010107/prepaid/cards/recharge", "POST"},
            new String[]{"/card-products/10010107/prepaid/cards/withdraw", "POST"});

    @Test
    @DisplayName("all() 恰好包含且仅包含 SPEC 3 节的 6 条记录, routeTemplate 与 method 逐字节相等")
    void allMatchesSpecExactly() {
        List<EncryptedRoutes.Route> routes = EncryptedRoutes.all();
        assertEquals(EXPECTED.size(), routes.size(), "记录条数必须恰好为 6");
        for (int i = 0; i < EXPECTED.size(); i++) {
            assertEquals(EXPECTED.get(i)[0], routes.get(i).routeTemplate(),
                    "第 " + i + " 条 routeTemplate 必须逐字节相等");
            assertEquals(EXPECTED.get(i)[1], routes.get(i).method(),
                    "第 " + i + " 条 method 必须逐字节相等");
        }

        Set<String> actualPaths = new LinkedHashSet<>();
        for (EncryptedRoutes.Route route : routes) {
            actualPaths.add(route.routeTemplate());
        }
        Set<String> expectedPaths = new LinkedHashSet<>();
        for (String[] row : EXPECTED) {
            expectedPaths.add(row[0]);
        }
        assertEquals(expectedPaths, actualPaths, "路径集合不得包含多余或缺失的条目");
    }

    @Test
    @DisplayName("isKnown 对全部 6 条已知路径返回 true")
    void isKnownTrueForAllKnownPaths() {
        for (String[] row : EXPECTED) {
            assertTrue(EncryptedRoutes.isKnown(row[0]), row[0] + " 必须被判定为已知");
        }
    }

    @Test
    @DisplayName("isKnown 对未知路径、null、空串均返回 false")
    void isKnownFalseForUnknownPaths() {
        assertFalse(EncryptedRoutes.isKnown("/card-products/99999999/unknown/cards/create"));
        assertFalse(EncryptedRoutes.isKnown("/card-products/10010105/cards/create/"), "多余尾斜杠也不算命中");
        assertFalse(EncryptedRoutes.isKnown(""));
        assertFalse(EncryptedRoutes.isKnown(null));
    }
}
