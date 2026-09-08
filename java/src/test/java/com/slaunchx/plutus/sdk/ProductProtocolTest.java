package com.slaunchx.plutus.sdk;

import com.sun.net.httpserver.HttpServer;
import com.slaunchx.plutus.sdk.crypto.Digests;
import com.slaunchx.plutus.sdk.crypto.RsaSignatures;
import com.slaunchx.plutus.sdk.signing.*;
import com.slaunchx.plutus.sdk.exception.PlutusException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ProductProtocolTest {
    @Test void queries() throws Exception {
        var vectors = TestVectors.MAPPER.readTree(Files.readString(Path.of("../shared/product-query-vectors.json")));
        for (var pair : vectors.get("valid")) {
            assertEquals(pair.get(1).asText(), ProductCanonicalQuery.canonicalize(pair.get(0).isNull() ? null : pair.get(0).asText()));
        }
        for (var raw : vectors.get("invalid")) assertThrows(PlutusException.class, () -> ProductCanonicalQuery.canonicalize(raw.asText()));
    }

    private PlutusConfig.Builder config(String url) {
        return PlutusConfig.builder().baseUrl(url).apiKey("key")
                .merchantAuthPrivateKeyPem(TestVectors.privateKeyPem("merchant_auth"))
                .platformAuthPublicKeyPem(TestVectors.publicKeyPem("platform_auth"))
                .protocolProfile(ProtocolProfile.PRODUCT_V1);
    }

    @ParameterizedTest
    @ValueSource(strings={"missing","present","wrong","empty","tamper","other","alpha","unsigned"})
    void responseCompatibility(String mode) throws Exception {
        var ids = new ArrayList<String>();
        var failure = new java.util.concurrent.atomic.AtomicReference<Throwable>();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/", exchange -> {
            try {
                var h = exchange.getRequestHeaders();
                String id = h.getFirst("X-Request-Id"); ids.add(id);
                assertNotNull(id);
                assertEquals("operation-1",h.getFirst("X-Idempotency-Key"));
                assertEquals("q=a%20b&star=*&tilde=%7E",exchange.getRequestURI().getRawQuery());
                byte[] input = exchange.getRequestBody().readAllBytes();
                String canonical = String.join("\n", "POST","/test","q=a%20b&star=*&tilde=%7E",h.getFirst("X-Timestamp"),h.getFirst("X-Nonce"),"1",Digests.sha256Hex(input));
                assertTrue(RsaSignatures.verify(TestVectors.publicKey("merchant_auth"),canonical,h.getFirst("X-Signature")));
                String body = "{\"success\":true,\"data\":[]}";
                var lines = new ArrayList<>(List.of(mode.equals("other") ? "other-id" : id,"200","application/json","1788836400000",Digests.sha256Hex(body)));
                if (mode.equals("alpha")) lines.addAll(0,List.of("SLAUNCHX-API-RESPONSE-V1",Digests.sha256Hex(canonical),"1","/test",""));
                var responseHeaders = exchange.getResponseHeaders();
                responseHeaders.set("Content-Type","application/json");
                responseHeaders.set("X-Response-Timestamp","1788836400000");
                if (!mode.equals("unsigned")) responseHeaders.set("X-Response-Signature",RsaSignatures.sign(TestVectors.privateKey("platform_auth"),String.join("\n",lines)));
                if (mode.equals("present")) responseHeaders.set("X-Request-Id",id);
                if (mode.equals("wrong")) responseHeaders.set("X-Request-Id","wrong-id");
                if (mode.equals("empty")) responseHeaders.set("X-Request-Id","");
                byte[] bytes = (body + (mode.equals("tamper") ? " " : "")).getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200,bytes.length);
                exchange.getResponseBody().write(bytes);
            } catch (Throwable error) { failure.set(error); exchange.sendResponseHeaders(500,-1); }
            finally { exchange.close(); }
        });
        server.start();
        try {
            var client = new PlutusClient(config("http://127.0.0.1:" + server.getAddress().getPort()).build());
            var request = PlutusRequest.post("/test").query("q=a+b&tilde=~&star=%2A").idempotencyKey("operation-1").build();
            if (mode.equals("missing") || mode.equals("present")) {
                assertTrue(client.request(request).signatureVerified());
                assertTrue(client.request(request).signatureVerified());
                assertNotEquals(ids.get(0),ids.get(1));
            } else assertThrows(PlutusException.class, () -> client.request(request));
            if (failure.get() != null) throw new AssertionError(failure.get());
        } finally { server.stop(0); }
    }

    @Test void rejectsAmbiguousIdsBeforeSending() {
        var client = new PlutusClient(config("https://example.test").build());
        assertThrows(PlutusException.class, () -> client.request(PlutusRequest.get("/test").header("x-request-id","a").header("X-Request-Id","b").build()));
        assertThrows(PlutusException.class, () -> client.request(PlutusRequest.get("/test").requestId("a\nb").build()));
    }

    @Test void defaultDoesNotFallBack() {
        var input = new SigningInput("GET","/test",null,"1788836400000","0123456789abcdef","1",null,null);
        var signed = new RequestSigner(TestVectors.privateKey("merchant_auth")).sign(input);
        assertEquals(8,signed.canonicalString().split("\n",-1).length);
        var context = new ResponseSignatureContext(signed.requestCanonicalSha256(),"1","/test",null,"id",200,"application/json","1788836400000",Digests.sha256Hex("{}"));
        String canonical = String.join("\n","id","200","application/json","1788836400000",Digests.sha256Hex("{}"));
        assertFalse(new ResponseVerifier(TestVectors.publicKey("platform_auth")).verify(context,RsaSignatures.sign(TestVectors.privateKey("platform_auth"),canonical)));
    }
}
