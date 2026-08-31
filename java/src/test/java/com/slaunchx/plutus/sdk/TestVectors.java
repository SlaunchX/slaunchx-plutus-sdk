package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import com.slaunchx.plutus.sdk.crypto.PemKeys;

/**
 * 加载 shared/test-vectors.json,为全部向量测试提供统一入口。
 */
final class TestVectors {

    static final ObjectMapper MAPPER = new ObjectMapper();
    static final JsonNode ROOT = load();

    private TestVectors() {
    }

    private static JsonNode load() {
        Path path = locate();
        try {
            return MAPPER.readTree(Files.readString(path, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException("无法读取黄金测试向量: " + path, e);
        }
    }

    private static Path locate() {
        Path dir = Paths.get("").toAbsolutePath();
        for (int i = 0; i < 6 && dir != null; i++) {
            Path candidate = dir.resolve("shared").resolve("test-vectors.json");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("未找到 shared/test-vectors.json, 当前目录: "
                + Paths.get("").toAbsolutePath());
    }

    static List<JsonNode> group(String name) {
        JsonNode node = ROOT.path("vectors").path(name);
        if (!node.isArray() || node.isEmpty()) {
            throw new IllegalStateException("向量组为空: " + name);
        }
        List<JsonNode> out = new ArrayList<>();
        node.forEach(out::add);
        return out;
    }

    static int declaredCount(String group) {
        return ROOT.path("meta").path("counts").path(group).asInt(-1);
    }

    static String privateKeyPem(String name) {
        return keyField(name, "privateKeyPem");
    }

    static String publicKeyPem(String name) {
        return keyField(name, "publicKeyPem");
    }

    static String fingerprint(String name) {
        return keyField(name, "fingerprint");
    }

    static RSAPrivateKey privateKey(String name) {
        return PemKeys.parsePrivateKey(privateKeyPem(name));
    }

    static RSAPublicKey publicKey(String name) {
        return PemKeys.parsePublicKey(publicKeyPem(name));
    }

    private static String keyField(String name, String field) {
        JsonNode node = ROOT.path("keys").path(name).path(field);
        if (node.isMissingNode() || node.isNull()) {
            throw new IllegalStateException("向量缺少密钥字段: " + name + "." + field);
        }
        return node.asText();
    }

    /** 读取可为 JSON null 的文本字段。 */
    static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isMissingNode() || value.isNull() ? null : value.asText();
    }

    /** 读取可为 JSON null 的文本字段,转 UTF-8 字节。 */
    static byte[] bytes(JsonNode node, String field) {
        String value = text(node, field);
        return value == null ? null : value.getBytes(StandardCharsets.UTF_8);
    }
}
