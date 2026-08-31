package com.slaunchx.plutus.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.slaunchx.plutus.sdk.crypto.Digests;
import com.slaunchx.plutus.sdk.crypto.EncryptionAad;
import com.slaunchx.plutus.sdk.crypto.Envelope;
import com.slaunchx.plutus.sdk.crypto.EnvelopeCodec;
import com.slaunchx.plutus.sdk.crypto.RsaSignatures;
import com.slaunchx.plutus.sdk.exception.PlutusApiException;
import com.slaunchx.plutus.sdk.exception.PlutusException;
import com.slaunchx.plutus.sdk.exception.PlutusSignatureException;
import com.slaunchx.plutus.sdk.model.PublicErrorCode;
import com.slaunchx.plutus.sdk.signing.ResponseSignatureContext;
import com.slaunchx.plutus.sdk.signing.ResponseVerifier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 端到端联通性测试:用 JDK 内置 HTTP 服务器扮演平台侧,校验客户端组装的请求头与签名,
 * 并回以按协议签名的响应。覆盖明文调用、幂等键、加密端点、敏感响应解密与错误响应。
 */
class PlutusClientEndToEndTest {

    private static HttpServer server;
    private static String baseUrl;
    private static PlutusConfig config;
    private static PlutusConfig strictConfig;
    private static PlutusConfig strictRouteConfig;

    /** 不在 {@link com.slaunchx.plutus.sdk.crypto.EncryptedRoutes} 表中的加密端点外部路径。 */
    private static final String UNKNOWN_ENCRYPTED_PATH = "/card-products/99999999/unknown/cards/create";

    private static final AtomicReference<Map<String, String>> LAST_HEADERS = new AtomicReference<>();
    private static final AtomicReference<byte[]> LAST_REQUEST_BODY = new AtomicReference<>();
    private static final AtomicReference<String> LAST_DECRYPTED_REQUEST = new AtomicReference<>();

    /** 平台统一响应包络的 version 字段值。 */
    private static final String ENVELOPE_VERSION = "2.0.0";

    private static String envelope(boolean success, String code, String message, String dataJson) {
        return "{\"version\":\"" + ENVELOPE_VERSION + "\",\"timestamp\":1755600000123,"
                + "\"success\":" + success + ",\"code\":\"" + code + "\",\"message\":\"" + message + "\","
                + "\"data\":" + (dataJson == null ? "null" : dataJson) + "}";
    }

    @BeforeAll
    static void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", PlutusClientEndToEndTest::handle);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        config = baseConfig().build();
        strictConfig = baseConfig().requireSignatureOnErrorResponses(true).build();
        strictRouteConfig = baseConfig().strictEncryptedRouteValidation(true).build();
    }

    private static PlutusConfig.Builder baseConfig() {
        return PlutusConfig.builder()
                .baseUrl(baseUrl + "/")
                .apiKey("apk_vector_0001")
                .merchantAuthPrivateKeyPem(TestVectors.privateKeyPem("merchant_auth"))
                .platformAuthPublicKeyPem(TestVectors.publicKeyPem("platform_auth"))
                .merchantEncPrivateKeyPem(TestVectors.privateKeyPem("merchant_enc"))
                .platformEncPublicKeyPem(TestVectors.publicKeyPem("platform_enc"));
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("GET 带 query: 请求头齐备, 签名可被平台侧验证, 响应验签通过")
    void plainGet() {
        try (PlutusClient client = new PlutusClient(config)) {
            PlutusResponse response = client.request(PlutusRequest.get("/card-products/cards/page")
                    .queryParam("status", "IN_USE")
                    .queryParam("pageSize", "20")
                    .build());

            assertEquals(200, response.statusCode());
            assertTrue(response.signatureVerified(), "响应验签必须通过");

            Map<String, String> headers = LAST_HEADERS.get();
            assertEquals("apk_vector_0001", headers.get(PlutusHeaders.API_KEY));
            assertEquals("1", headers.get(PlutusHeaders.API_VERSION));
            assertEquals(RsaSignatures.ALGORITHM_HEADER_VALUE, headers.get(PlutusHeaders.SIGNATURE_ALGORITHM));
            assertNotNull(headers.get(PlutusHeaders.SIGNATURE));
            assertTrue(NonceGenerator.isValid(headers.get(PlutusHeaders.NONCE)), "nonce 必须满足协议字符集");
            assertEquals(13, headers.get(PlutusHeaders.TIMESTAMP).length(), "X-Timestamp 必须是毫秒");
            assertFalse(headers.containsKey(PlutusHeaders.IDEMPOTENCY_KEY), "未设置幂等键时不得发送该头");
            assertEquals("pageSize=20&status=IN_USE", headers.get("__query"), "线上 query 已规范化");

            com.slaunchx.plutus.sdk.model.ApiResponse parsed = response.requireSuccess();
            assertEquals("card_example_001", parsed.data().get("cardBizId").asText());
            assertEquals("2.0.0", parsed.version());
            assertEquals(1755600000123L, parsed.timestamp().orElseThrow());
            assertEquals("2000", parsed.rawCode());
            assertEquals(Boolean.TRUE, parsed.successFlag().orElseThrow());
        }
    }

    @Test
    @DisplayName("POST 带幂等键: 头存在且参与签名, 响应携带 X-Operation-Id 仍验签通过")
    void postWithIdempotencyKey() {
        try (PlutusClient client = new PlutusClient(config)) {
            PlutusResponse response = client.request(
                    PlutusRequest.post("/card-products/cards/freeze")
                            .jsonBody(Map.of("reasonCategory", "USER_REQUESTED"))
                            .idempotencyKey("idem-e2e-0000000001")
                            .build());

            assertEquals(201, response.statusCode());
            assertTrue(response.signatureVerified());
            assertEquals("idem-e2e-0000000001", LAST_HEADERS.get().get(PlutusHeaders.IDEMPOTENCY_KEY));
            assertEquals("application/json", LAST_HEADERS.get().get(PlutusHeaders.CONTENT_TYPE));
        }
    }

    @Test
    @DisplayName("加密端点: body 是信封 JSON, 平台侧可解出明文; 敏感响应可解密")
    void encryptedRoundTrip() {
        try (PlutusClient client = new PlutusClient(config)) {
            PlutusResponse response = client.request(
                    PlutusRequest.post("/card-products/10010106/shared/cards/create")
                            .jsonBody(Map.of("platformCardProductBizId", "pcp_example_001"))
                            .requestId("req_e2e_0000000001")
                            .encrypted(true)
                            .build());

            assertEquals(200, response.statusCode());
            assertTrue(response.signatureVerified());
            Map<String, String> headers = LAST_HEADERS.get();
            assertEquals("req_e2e_0000000001", headers.get(PlutusHeaders.REQUEST_ID));
            assertEquals(TestVectors.fingerprint("platform_enc"),
                    headers.get(PlutusHeaders.PLATFORM_ENCRYPTION_KEY_ID));
            assertEquals("{\"platformCardProductBizId\":\"pcp_example_001\"}", LAST_DECRYPTED_REQUEST.get());

            JsonNode envelopeNode = response.json().get("data").get("sensitive");
            String plaintext = client.decryptSensitivePayload(envelopeNode, "req_e2e_0000000001");
            assertEquals("{\"cardNumber\":\"4111111111111111\"}", plaintext);
        }
    }

    @Test
    @DisplayName("加密端点未提供 X-Request-Id 时由 SDK 生成非空值")
    void encryptedRequestIdAutoGenerated() {
        try (PlutusClient client = new PlutusClient(config)) {
            client.request(PlutusRequest.post("/card-products/10010106/shared/cards/create")
                    .jsonBody(Map.of("platformCardProductBizId", "pcp_example_001"))
                    .encrypted(true)
                    .build());
            assertNotNull(LAST_HEADERS.get().get(PlutusHeaders.REQUEST_ID));
            assertFalse(LAST_HEADERS.get().get(PlutusHeaders.REQUEST_ID).isBlank());
        }
    }

    @Test
    @DisplayName("加密端点 routeTemplate 不在 EncryptedRoutes 表中: 默认非严格模式不阻断, 请求正常完成")
    void unknownEncryptedRouteDefaultModeDoesNotBlock() {
        assertFalse(config.strictEncryptedRouteValidation(), "默认必须为 false");
        try (PlutusClient client = new PlutusClient(config)) {
            PlutusResponse response = client.request(
                    PlutusRequest.post(UNKNOWN_ENCRYPTED_PATH)
                            .jsonBody(Map.of("foo", "bar"))
                            .requestId("req_e2e_unknown_route_0001")
                            .encrypted(true)
                            .build());

            assertEquals(200, response.statusCode());
            assertTrue(response.signatureVerified());
            assertEquals("{\"foo\":\"bar\"}", LAST_DECRYPTED_REQUEST.get(),
                    "未知路由不阻断加密与发送");
        }
    }

    @Test
    @DisplayName("加密端点 routeTemplate 不在 EncryptedRoutes 表中: 严格模式下抛出 PlutusException, 且不发起网络请求")
    void unknownEncryptedRouteStrictModeThrows() {
        assertTrue(strictRouteConfig.strictEncryptedRouteValidation());
        try (PlutusClient client = new PlutusClient(strictRouteConfig)) {
            LAST_DECRYPTED_REQUEST.set(null);
            PlutusException error = assertThrows(PlutusException.class, () -> client.request(
                    PlutusRequest.post(UNKNOWN_ENCRYPTED_PATH)
                            .jsonBody(Map.of("foo", "bar"))
                            .requestId("req_e2e_unknown_route_0002")
                            .encrypted(true)
                            .build()));
            assertTrue(error.getMessage().contains(UNKNOWN_ENCRYPTED_PATH),
                    "异常信息应指出具体的未知路径, 便于排障");
            assertNull(LAST_DECRYPTED_REQUEST.get(), "严格模式下请求必须在发送前就被拒绝");
        }
    }

    @Test
    @DisplayName("严格模式对 EncryptedRoutes 已知路由不受影响")
    void strictModeDoesNotAffectKnownRoutes() {
        try (PlutusClient client = new PlutusClient(strictRouteConfig)) {
            PlutusResponse response = client.request(
                    PlutusRequest.post("/card-products/10010106/shared/cards/create")
                            .jsonBody(Map.of("platformCardProductBizId", "pcp_example_001"))
                            .requestId("req_e2e_known_route_strict_0001")
                            .encrypted(true)
                            .build());
            assertEquals(200, response.statusCode());
            assertTrue(response.signatureVerified());
        }
    }

    @Test
    @DisplayName("业务错误响应带签名, 解析为类型化异常")
    void businessErrorBecomesTypedException() {
        try (PlutusClient client = new PlutusClient(config)) {
            PlutusResponse response = client.request(PlutusRequest.get("/card-products/cards/conflict").build());
            assertEquals(409, response.statusCode());
            assertTrue(response.signatureVerified(), "业务错误响应同样应通过验签");
            PlutusApiException error = assertThrows(PlutusApiException.class, response::requireSuccess);
            assertEquals(PublicErrorCode.REQUEST_CONFLICT, error.errorCode().orElseThrow());
            assertEquals(409, error.httpStatus());
            assertFalse(error.retryable());
        }
    }

    @Test
    @DisplayName("平台伪造响应签名时抛出验签异常, 不把数据交给业务代码")
    void badResponseSignatureRejected() {
        try (PlutusClient client = new PlutusClient(config)) {
            assertThrows(PlutusSignatureException.class,
                    () -> client.request(PlutusRequest.get("/card-products/cards/badsig").build()));
        }
    }

    @Test
    @DisplayName("HTTP 200 但 success=false: requireSuccess 抛异常, 数字业务码原样保留")
    void businessFailureWithHttp200() {
        try (PlutusClient client = new PlutusClient(config)) {
            PlutusResponse response = client.request(
                    PlutusRequest.get("/card-products/cards/business-error").build());
            assertEquals(200, response.statusCode());
            assertTrue(response.signatureVerified());
            PlutusApiException error = assertThrows(PlutusApiException.class, response::requireSuccess);
            assertEquals("4022", error.response().rawCode());
            assertTrue(error.errorCode().isEmpty(), "数字业务码不在 PublicErrorCode 中登记");
            assertEquals("Validation Error", error.response().message());
        }
    }

    @Test
    @DisplayName("code=2101 账号待审批仍是成功")
    void pendingApprovalIsSuccess() {
        try (PlutusClient client = new PlutusClient(config)) {
            com.slaunchx.plutus.sdk.model.ApiResponse parsed = client.call(
                    PlutusRequest.get("/card-products/cards/pending-approval").build());
            assertEquals(com.slaunchx.plutus.sdk.model.ResultCodes.ACCOUNT_PENDING_APPROVAL,
                    parsed.rawCode());
            assertTrue(parsed.successful());
        }
    }

    @Test
    @DisplayName("缺签名头策略: 401 非 2xx 放行, signatureVerified=false, requireSuccess 抛 PlutusApiException")
    void unauthenticatedResponsePassesThrough() {
        try (PlutusClient client = new PlutusClient(config)) {
            PlutusResponse response = client.request(PlutusRequest.get("/card-products/cards/unauth").build());
            assertEquals(401, response.statusCode());
            assertFalse(response.signatureVerified());
            PlutusApiException error = assertThrows(PlutusApiException.class, response::requireSuccess);
            assertEquals(PublicErrorCode.API_KEY_INVALID, error.errorCode().orElseThrow());
        }
    }

    @Test
    @DisplayName("缺签名头策略: 500 非 2xx 同样放行, signatureVerified=false")
    void unsignedServerErrorPassesThrough() {
        try (PlutusClient client = new PlutusClient(config)) {
            PlutusResponse response = client.request(
                    PlutusRequest.get("/card-products/cards/unsigned-500").build());
            assertEquals(500, response.statusCode());
            assertFalse(response.signatureVerified(), "放行的响应必须让调用方看到未验签");
            PlutusApiException error = assertThrows(PlutusApiException.class, response::requireSuccess);
            assertEquals(PublicErrorCode.SYSTEM_INTERNAL_ERROR, error.errorCode().orElseThrow());
            assertTrue(error.retryable());
        }
    }

    @Test
    @DisplayName("缺签名头策略: HTTP 2xx 缺签名头一律抛验签异常")
    void unsignedSuccessResponseRejected() {
        try (PlutusClient client = new PlutusClient(config)) {
            assertThrows(PlutusSignatureException.class,
                    () -> client.request(PlutusRequest.get("/card-products/cards/unsigned-200").build()));
        }
    }

    @Test
    @DisplayName("缺签名头策略: 打开 requireSignatureOnErrorResponses 后非 2xx 缺签名头也抛验签异常")
    void strictModeRejectsUnsignedErrorResponse() {
        assertFalse(config.requireSignatureOnErrorResponses(), "默认必须为 false");
        assertTrue(strictConfig.requireSignatureOnErrorResponses());
        try (PlutusClient client = new PlutusClient(strictConfig)) {
            assertThrows(PlutusSignatureException.class,
                    () -> client.request(PlutusRequest.get("/card-products/cards/unauth").build()));
            assertThrows(PlutusSignatureException.class,
                    () -> client.request(PlutusRequest.get("/card-products/cards/unsigned-500").build()));
        }
    }

    @Test
    @DisplayName("不变量: 参与签名的 body 字节与实际发往传输层的 body 字节逐字节相等")
    void signedBytesEqualSentBytes() {
        try (PlutusClient client = new PlutusClient(config)) {
            PlutusResponse response = client.request(
                    PlutusRequest.post("/card-products/cards/freeze")
                            .jsonBody(Map.of("reasonCategory", "USER_REQUESTED"))
                            .build());

            byte[] sent = LAST_REQUEST_BODY.get();
            // 参与签名的字节: signedRequest().bodySha256Hex() 是 SDK 对序列化结果计算一次的摘要;
            // 服务端收到的字节复算后必须完全相同, 即 body 只序列化一次且签名与发送同源。
            assertEquals(response.signedRequest().bodySha256Hex(),
                    Digests.bodySha256Hex("POST", sent),
                    "签名字节与发送字节的 body 摘要必须一致");
            assertArrayEquals("{\"reasonCategory\":\"USER_REQUESTED\"}".getBytes(StandardCharsets.UTF_8),
                    sent, "服务端收到的必须是 SDK 唯一一次序列化的结果");
            // 规范串第 8 行即 body 摘要, 再核一次两者同源。
            String[] canonicalLines = response.signedRequest().canonicalString().split("\n", -1);
            assertEquals(8, canonicalLines.length);
            assertEquals(Digests.bodySha256Hex("POST", sent), canonicalLines[7]);
        }
    }

    @Test
    @DisplayName("不变量: 加密端点参与签名的是信封字节, 与实际发送的信封字节相同")
    void signedBytesEqualSentBytesForEncryptedRequest() {
        try (PlutusClient client = new PlutusClient(config)) {
            PlutusResponse response = client.request(
                    PlutusRequest.post("/card-products/10010106/shared/cards/create")
                            .jsonBody(Map.of("platformCardProductBizId", "pcp_example_001"))
                            .requestId("req_e2e_0000000002")
                            .encrypted(true)
                            .build());

            byte[] sent = LAST_REQUEST_BODY.get();
            assertEquals(response.signedRequest().bodySha256Hex(),
                    Digests.bodySha256Hex("POST", sent),
                    "加密请求同样必须签名信封的发送字节");
        }
    }

    // ------------------------------------------------------------------
    // 平台侧模拟
    // ------------------------------------------------------------------

    private static void handle(HttpExchange exchange) throws IOException {
        byte[] body;
        try (InputStream in = exchange.getRequestBody()) {
            body = in.readAllBytes();
        }
        // com.sun.net.httpserver 会把头名归一化为 Xxx-yyy 形式, 因此用大小写不敏感的映射。
        Map<String, String> headers = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        exchange.getRequestHeaders().forEach((k, v) -> headers.put(k, v.isEmpty() ? null : v.get(0)));
        String path = exchange.getRequestURI().getPath();
        String rawQuery = exchange.getRequestURI().getRawQuery();
        headers.put("__query", rawQuery);
        LAST_HEADERS.set(headers);
        LAST_REQUEST_BODY.set(body);

        // 平台侧验签: 用商户认证公钥校验 8 行规范串。
        String canonical = String.join("\n",
                exchange.getRequestMethod(),
                path,
                com.slaunchx.plutus.sdk.signing.CanonicalQuery.canonicalize(rawQuery),
                headers.get(PlutusHeaders.TIMESTAMP),
                headers.get(PlutusHeaders.NONCE),
                headers.get(PlutusHeaders.API_VERSION),
                headers.getOrDefault(PlutusHeaders.IDEMPOTENCY_KEY, ""),
                Digests.bodySha256Hex(exchange.getRequestMethod(), body));
        if (!RsaSignatures.verify(TestVectors.publicKey("merchant_auth"), canonical,
                headers.get(PlutusHeaders.SIGNATURE))) {
            respond(exchange, 401,
                    envelope(false, "API.SIGNATURE_INVALID", "signature is invalid", null),
                    null, null, null, canonical, false);
            return;
        }

        String requestId = headers.get(PlutusHeaders.REQUEST_ID);
        int status = 200;
        String operationId = null;
        String responseBody;

        switch (path) {
            case "/card-products/cards/page" -> responseBody = envelope(true, "2000", "Success",
                    "{\"cardBizId\":\"card_example_001\",\"status\":\"IN_USE\"}");
            case "/card-products/cards/freeze" -> {
                status = 201;
                operationId = "op_e2e_0000000001";
                responseBody = envelope(true, "2001", "Created", "{\"accepted\":true}");
            }
            case "/card-products/10010106/shared/cards/create" -> {
                Envelope envelope = Envelope.fromJson(TestVectors.MAPPER.readTree(body)).requireApiShape();
                EncryptionAad aad = EncryptionAad.forEncryptedRequest(requestId, path,
                        headers.get(PlutusHeaders.TIMESTAMP), TestVectors.fingerprint("platform_enc"));
                LAST_DECRYPTED_REQUEST.set(new EnvelopeCodec()
                        .openToString(envelope, TestVectors.privateKey("platform_enc"), aad));

                EncryptionAad responseAad = EncryptionAad.forSensitiveResponse(
                        requestId, headers.get(PlutusHeaders.TIMESTAMP), TestVectors.fingerprint("merchant_enc"));
                Envelope sensitive = new EnvelopeCodec().seal("{\"cardNumber\":\"4111111111111111\"}",
                        TestVectors.publicKey("merchant_enc"), TestVectors.fingerprint("merchant_enc"), responseAad);
                responseBody = envelope(true, "2000", "Success", "{\"sensitive\":"
                        + TestVectors.MAPPER.writeValueAsString(sensitive.toMap()) + "}");
            }
            case UNKNOWN_ENCRYPTED_PATH -> {
                // 不在 EncryptedRoutes 常量表中的加密端点: 平台侧照常按加密协议处理,
                // 用于验证 SDK 客户端侧「默认不阻断 / 严格模式拒绝」的行为均发生在发送之前。
                Envelope envelope = Envelope.fromJson(TestVectors.MAPPER.readTree(body)).requireApiShape();
                EncryptionAad aad = EncryptionAad.forEncryptedRequest(requestId, path,
                        headers.get(PlutusHeaders.TIMESTAMP), TestVectors.fingerprint("platform_enc"));
                LAST_DECRYPTED_REQUEST.set(new EnvelopeCodec()
                        .openToString(envelope, TestVectors.privateKey("platform_enc"), aad));
                responseBody = envelope(true, "2000", "Success", "{}");
            }
            case "/card-products/cards/conflict" -> {
                status = 409;
                responseBody = envelope(false, "REQUEST.CONFLICT", "幂等冲突", null);
            }
            case "/card-products/cards/business-error" -> {
                // HTTP 200 但 success=false: 业务层数字错误码。
                responseBody = envelope(false, "4022", "Validation Error", null);
            }
            case "/card-products/cards/pending-approval" -> {
                responseBody = envelope(true, "2101", "Account pending approval", null);
            }
            case "/card-products/cards/badsig" -> {
                respond(exchange, 200, envelope(true, "2000", "Success", null), requestId, null,
                        Long.toString(System.currentTimeMillis()), canonical, true);
                return;
            }
            case "/card-products/cards/unauth" -> {
                respond(exchange, 401, envelope(false, "API.KEY_INVALID", "api key invalid", null),
                        null, null, null, canonical, false);
                return;
            }
            case "/card-products/cards/unsigned-200" -> {
                // HTTP 2xx 且不带 X-Response-Signature: SDK 必须拒收。
                respond(exchange, 200, envelope(true, "2000", "Success", null),
                        null, null, null, canonical, false);
                return;
            }
            case "/card-products/cards/unsigned-500" -> {
                // 非 2xx 且不带 X-Response-Signature: 默认放行, signatureVerified=false。
                respond(exchange, 500, envelope(false, "SYSTEM.INTERNAL_ERROR", "boom", null),
                        null, null, null, canonical, false);
                return;
            }
            default -> {
                status = 404;
                responseBody = envelope(false, "RESOURCE.NOT_FOUND", "not found", null);
            }
        }
        respond(exchange, status, responseBody, requestId, operationId,
                Long.toString(System.currentTimeMillis()), canonical, false);
    }

    private static void respond(HttpExchange exchange, int status, String body, String requestId,
                                String operationId, String responseTimestamp, String requestCanonical,
                                boolean forgeSignature) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        String contentType = "application/json;charset=UTF-8";
        exchange.getResponseHeaders().set(PlutusHeaders.CONTENT_TYPE, contentType);
        if (requestId != null) {
            exchange.getResponseHeaders().set(PlutusHeaders.REQUEST_ID, requestId);
        }
        if (operationId != null) {
            exchange.getResponseHeaders().set(PlutusHeaders.OPERATION_ID, operationId);
        }
        if (responseTimestamp != null) {
            exchange.getResponseHeaders().set(PlutusHeaders.RESPONSE_TIMESTAMP, responseTimestamp);
            ResponseSignatureContext context = new ResponseSignatureContext(
                    Digests.sha256Hex(requestCanonical), "1", exchange.getRequestURI().getPath(),
                    operationId, requestId, status, contentType, responseTimestamp,
                    Digests.sha256Hex(payload));
            String signature = forgeSignature
                    ? RsaSignatures.sign(TestVectors.privateKey("merchant_auth"),
                            ResponseVerifier.canonicalString(context))
                    : RsaSignatures.sign(TestVectors.privateKey("platform_auth"),
                            ResponseVerifier.canonicalString(context));
            exchange.getResponseHeaders().set(PlutusHeaders.RESPONSE_SIGNATURE, signature);
            exchange.getResponseHeaders().set(PlutusHeaders.RESPONSE_SIGNATURE_ALGORITHM,
                    RsaSignatures.ALGORITHM_HEADER_VALUE);
            exchange.getResponseHeaders().set(PlutusHeaders.PLATFORM_SIGNING_KEY_ID,
                    TestVectors.fingerprint("platform_auth"));
        }
        exchange.sendResponseHeaders(status, payload.length);
        exchange.getResponseBody().write(payload);
        exchange.close();
    }
}
