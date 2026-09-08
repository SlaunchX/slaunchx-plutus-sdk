package plutus

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// mockPlatform 是一个最小的平台侧实现: 独立重建规范串验签, 并对响应签名。
type mockPlatform struct {
	t                 *testing.T
	merchantAuthPub   *rsa.PublicKey
	platformAuthPriv  *rsa.PrivateKey
	platformEncPriv   *rsa.PrivateKey
	merchantEncPub    *rsa.PublicKey
	tamperBody        bool
	omitSignature     bool
	lastRequestHeader http.Header
	lastRawQuery      string
	lastRequestBody   []byte
	lastPlaintext     string
}

func (m *mockPlatform) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	m.lastRequestHeader = r.Header.Clone()
	m.lastRawQuery = r.URL.RawQuery
	m.lastRequestBody = append([]byte(nil), body...)

	if got := r.Header.Get(HeaderSignatureAlgorithm); !strings.EqualFold(got, SignatureAlgorithm) {
		m.writeError(w, r, nil, http.StatusBadRequest, string(CodeSignatureAlgorithmInvalid), "bad algorithm")
		return
	}
	canonicalQuery, err := CanonicalizeQuery(r.URL.RawQuery)
	if err != nil {
		m.writeError(w, r, nil, http.StatusBadRequest, string(CodeSignatureInvalid), "bad query")
		return
	}
	bodyDigest := EmptyBodySHA256Hex
	if !ForcesEmptyBodyDigest(r.Method) && len(body) > 0 {
		bodyDigest = SHA256Hex(body)
	}
	canonical := strings.Join([]string{
		r.Method,
		r.URL.Path,
		canonicalQuery,
		r.Header.Get(HeaderTimestamp),
		r.Header.Get(HeaderNonce),
		r.Header.Get(HeaderAPIVersion),
		r.Header.Get(HeaderIdempotencyKey),
		bodyDigest,
	}, "\n")
	if err := VerifyCanonicalString(m.merchantAuthPub, canonical, r.Header.Get(HeaderSignature)); err != nil {
		m.writeError(w, r, nil, http.StatusUnauthorized, string(CodeSignatureInvalid), "signature is invalid")
		return
	}
	binding := SHA256Hex([]byte(canonical))

	switch {
	case r.URL.Path == "/card-products/10010106/shared/cards/create":
		env, err := ParseEnvelopeJSON(body)
		if err != nil {
			m.writeError(w, r, &binding, http.StatusBadRequest, string(CodeSecureChannelInvalid), "bad envelope")
			return
		}
		aad := AAD{
			RequestID:     r.Header.Get(HeaderRequestID),
			RouteTemplate: r.URL.Path,
			Timestamp:     r.Header.Get(HeaderTimestamp),
			KeyID:         r.Header.Get(HeaderPlatformEncryptionKeyID),
		}
		plaintext, err := Open(m.platformEncPriv, env, aad)
		if err != nil {
			m.writeError(w, r, &binding, http.StatusBadRequest, string(CodeSecureChannelInvalid), "decrypt failed")
			return
		}
		m.lastPlaintext = string(plaintext)
		w.Header().Set(HeaderOperationID, "op_mock_0001")
		m.writeSigned(w, r, binding, http.StatusCreated,
			[]byte(`{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2001","message":"Created","data":{"batchBizId":"ccb_mock_001"}}`))

	case r.URL.Path == "/card-products/cards/sensitive":
		// 敏感响应: routeTemplate 为空串, keyId 为商户加密公钥指纹。
		fingerprint, err := KeyFingerprint(m.merchantEncPub)
		if err != nil {
			http.Error(w, "fingerprint", http.StatusInternalServerError)
			return
		}
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		aad := AAD{RequestID: r.Header.Get(HeaderRequestID), RouteTemplate: "", Timestamp: timestamp, KeyID: fingerprint}
		env, err := Seal(m.merchantEncPub, fingerprint, aad, []byte(`{"cardNumber":"4111111111111111","cvv":"123"}`))
		if err != nil {
			http.Error(w, "seal", http.StatusInternalServerError)
			return
		}
		payload, _ := json.Marshal(map[string]any{
			"version":   "2.0.0",
			"timestamp": 1755600000123,
			"success":   true,
			"code":      "2000",
			"message":   "Success",
			"data":      map[string]any{"secure": env},
		})
		m.writeSigned(w, r, binding, http.StatusOK, payload)

	case r.URL.Path == "/card-products/cards/rate-limited":
		w.Header().Set(HeaderRetryAfter, "3")
		m.writeSigned(w, r, binding, http.StatusTooManyRequests,
			[]byte(`{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"REQUEST.RATE_LIMITED","message":"slow down"}`))

	case r.URL.Path == "/card-products/cards/business-rejected":
		// HTTP 200 但包络 success 为 false: 业务失败, 错误码是数字字符串。
		m.writeSigned(w, r, binding, http.StatusOK,
			[]byte(`{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"4022","message":"Validation Error"}`))

	case r.URL.Path == "/card-products/cards/unauthorized":
		// 未通过认证的响应不带签名头。
		w.Header().Set(HeaderRequestID, r.Header.Get(HeaderRequestID))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"API.KEY_DISABLED","message":"key disabled"}`))

	default:
		m.writeSigned(w, r, binding, http.StatusOK,
			[]byte(`{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{"cardBizId":"card_mock_001","status":"IN_USE"}}`))
	}
}

func (m *mockPlatform) writeError(w http.ResponseWriter, r *http.Request, binding *string, status int, code, message string) {
	body := []byte(`{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"` + code + `","message":"` + message + `"}`)
	if binding == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}
	m.writeSigned(w, r, *binding, status, body)
}

func (m *mockPlatform) writeSigned(w http.ResponseWriter, r *http.Request, binding string, status int, body []byte) {
	m.t.Helper()
	header := w.Header()
	header.Set("Content-Type", "application/json;charset=UTF-8")
	header.Set(HeaderRequestID, r.Header.Get(HeaderRequestID))
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	header.Set(HeaderResponseTimestamp, timestamp)
	header.Set(HeaderResponseSignatureAlgorithm, SignatureAlgorithm)

	canonical := strings.Join([]string{
		ResponseCanonicalPrefix,
		binding,
		r.Header.Get(HeaderAPIVersion),
		r.URL.Path,
		header.Get(HeaderOperationID),
		header.Get(HeaderRequestID),
		strconv.Itoa(status),
		header.Get("Content-Type"),
		timestamp,
		SHA256Hex(body),
	}, "\n")
	signature, err := SignCanonicalString(m.platformAuthPriv, canonical)
	if err != nil {
		m.t.Fatalf("sign response: %v", err)
	}
	if !m.omitSignature {
		header.Set(HeaderResponseSignature, signature)
	}
	if m.tamperBody {
		body = append(body, ' ')
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func newTestClient(t *testing.T, platform *mockPlatform, mutate func(*Config)) (*Client, *httptest.Server) {
	t.Helper()
	platform.t = t
	platform.merchantAuthPub = publicKey(t, "merchant_auth")
	platform.platformAuthPriv = privateKey(t, "platform_auth")
	platform.platformEncPriv = privateKey(t, "platform_enc")
	platform.merchantEncPub = publicKey(t, "merchant_enc")

	server := httptest.NewServer(platform)
	t.Cleanup(server.Close)

	cfg := Config{APIVersion: "1",
		BaseURL:                server.URL,
		APIKey:                 "apk_vector_0001",
		MerchantAuthPrivateKey: privateKey(t, "merchant_auth"),
		PlatformAuthPublicKey:  publicKey(t, "platform_auth"),
		PlatformEncPublicKey:   publicKey(t, "platform_enc"),
		MerchantEncPrivateKey:  privateKey(t, "merchant_enc"),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, server
}

func TestClientGetWithQuery(t *testing.T) {
	platform := &mockPlatform{}
	client, _ := newTestClient(t, platform, nil)

	var data struct {
		CardBizID string `json:"cardBizId"`
		Status    string `json:"status"`
	}
	resp, err := client.DoJSON(context.Background(), Request{
		Method: http.MethodGet,
		Path:   "/card-products/cards/page",
		Query:  url.Values{"status": {"IN_USE"}, "keyword": {"hello world"}, "pageSize": {"20"}},
	}, &data)
	if err != nil {
		t.Fatalf("DoJSON: %v", err)
	}
	if !resp.SignatureVerified {
		t.Error("response signature must be verified")
	}
	if data.CardBizID != "card_mock_001" {
		t.Errorf("data = %+v", data)
	}
	// 实际发出的 query 与签名的规范化结果一致: 空格是 %20, 不是 '+'。
	if want := "keyword=hello%20world&pageSize=20&status=IN_USE"; platform.lastRawQuery != want {
		t.Errorf("raw query on the wire = %q, want %q", platform.lastRawQuery, want)
	}
	if got := platform.lastRequestHeader.Get(HeaderNonce); got == "" {
		t.Error("nonce header is missing")
	}
	if _, ok := platform.lastRequestHeader["X-Api-Key"]; !ok {
		t.Error("X-Api-Key header is missing")
	}
}

func TestClientSendsLiteralAPIVersionHeader(t *testing.T) {
	platform := &mockPlatform{}
	client, _ := newTestClient(t, platform, nil)
	prepared, err := client.Prepare(context.Background(), Request{
		Method: http.MethodGet,
		Path:   "/card-products/cards/page",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	values, ok := prepared.HTTPRequest.Header["X-API-VERSION"]
	if !ok || len(values) != 1 || values[0] != DefaultAPIVersion {
		t.Fatalf("X-API-VERSION header = %v (present=%v), want [%s]", values, ok, DefaultAPIVersion)
	}
	if got := prepared.HTTPRequest.Header.Get(HeaderSignatureAlgorithm); got != SignatureAlgorithm {
		t.Errorf("X-Signature-Algorithm = %q, want %q", got, SignatureAlgorithm)
	}
	if prepared.Binding.RequestCanonicalSHA256 != SHA256Hex([]byte(prepared.Signed.CanonicalString)) {
		t.Error("binding digest must be the digest of the canonical string")
	}
}

func TestClientBodyIsSerializedOnce(t *testing.T) {
	platform := &mockPlatform{}
	client, _ := newTestClient(t, platform, nil)
	prepared, err := client.Prepare(context.Background(), Request{
		Method:         http.MethodPost,
		Path:           "/card-products/cards/freeze",
		JSONBody:       map[string]string{"reasonCategory": "USER_REQUESTED"},
		IdempotencyKey: "idem-client-0001",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if got := SHA256Hex(prepared.Body); got != prepared.Signed.BodyDigestHex {
		t.Fatalf("signed digest %s does not match the bytes to be sent %s", prepared.Signed.BodyDigestHex, got)
	}
	if !strings.HasSuffix(prepared.Signed.CanonicalString, prepared.Signed.BodyDigestHex) {
		t.Error("canonical string must end with the body digest")
	}
	if got := prepared.HTTPRequest.Header.Get(HeaderIdempotencyKey); got != "idem-client-0001" {
		t.Errorf("X-Idempotency-Key = %q", got)
	}
	if lines := strings.Split(prepared.Signed.CanonicalString, "\n"); lines[6] != "idem-client-0001" {
		t.Errorf("canonical line 7 = %q, want the idempotency key", lines[6])
	}
}

// TestClientSignedBytesEqualSentBytes 断言「签名字节 == 发送字节」不变量:
// 实际到达传输层的 body 与参与签名的 body 逐字节相等, 且 body 只序列化一次。
func TestClientSignedBytesEqualSentBytes(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		encrypt bool
	}{
		{name: "plain", path: "/card-products/cards/freeze"},
		{name: "encrypted", path: "/card-products/10010106/shared/cards/create", encrypt: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			platform := &mockPlatform{}
			client, _ := newTestClient(t, platform, nil)

			// JSONBody 里放一个 map: 若 SDK 序列化两次, key 顺序虽稳定但字节仍来自两次
			// 独立的 Marshal, 断言的是同一份字节被复用。
			prepared, err := client.Prepare(context.Background(), Request{
				Method:         http.MethodPost,
				Path:           tc.path,
				JSONBody:       map[string]any{"reasonCategory": "USER_REQUESTED", "quantity": 2, "note": "空格 与 中文"},
				Encrypt:        tc.encrypt,
				RequestID:      "req_invariant_0001",
				IdempotencyKey: "idem-invariant-0001",
			})
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}

			// 参与签名的 body 摘要必须就是待发送字节的摘要。
			if got := SHA256Hex(prepared.Body); got != prepared.Signed.BodyDigestHex {
				t.Fatalf("signed body digest %s != digest of bytes to send %s", prepared.Signed.BodyDigestHex, got)
			}

			// http.Request 持有的 body 必须与 prepared.Body 是同一份字节。
			readBack, err := prepared.HTTPRequest.GetBody()
			if err != nil {
				t.Fatalf("GetBody: %v", err)
			}
			onRequest, err := io.ReadAll(readBack)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			if !bytes.Equal(onRequest, prepared.Body) {
				t.Fatalf("http.Request body %q != signed body %q", onRequest, prepared.Body)
			}
			if prepared.HTTPRequest.ContentLength != int64(len(prepared.Body)) {
				t.Errorf("ContentLength = %d, want %d", prepared.HTTPRequest.ContentLength, len(prepared.Body))
			}

			// 真正发出去, 比对服务端收到的原始字节。
			resp, err := client.httpClient.Do(prepared.HTTPRequest)
			if err != nil {
				t.Fatalf("send: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if !bytes.Equal(platform.lastRequestBody, prepared.Body) {
				t.Fatalf("bytes on the wire %q != signed bytes %q", platform.lastRequestBody, prepared.Body)
			}
			if got := SHA256Hex(platform.lastRequestBody); got != prepared.Signed.BodyDigestHex {
				t.Fatalf("digest of bytes on the wire %s != signed digest %s", got, prepared.Signed.BodyDigestHex)
			}
			// 平台侧独立重建规范串验签通过 (否则 mock 会返回 401)。
			if resp.StatusCode == http.StatusUnauthorized {
				t.Fatal("platform rejected the signature: signed bytes differ from sent bytes")
			}
		})
	}
}

func TestClientEncryptedRequestAndSensitiveResponse(t *testing.T) {
	platform := &mockPlatform{}
	client, _ := newTestClient(t, platform, nil)

	resp, err := client.Do(context.Background(), Request{
		Method:         http.MethodPost,
		Path:           "/card-products/10010106/shared/cards/create",
		JSONBody:       map[string]any{"platformCardProductBizId": "pcp_example_001", "quantity": 2},
		Encrypt:        true,
		RequestID:      "req_client_0001",
		IdempotencyKey: "idem-client-0002",
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.SignatureVerified {
		t.Error("response signature must be verified")
	}
	if platform.lastPlaintext != `{"platformCardProductBizId":"pcp_example_001","quantity":2}` {
		t.Fatalf("platform decrypted %q", platform.lastPlaintext)
	}
	if got := platform.lastRequestHeader.Get(HeaderPlatformEncryptionKeyID); got != client.PlatformEncryptionKeyID() {
		t.Errorf("X-Platform-Encryption-Key-Id = %q, want %q", got, client.PlatformEncryptionKeyID())
	}
	if got := platform.lastRequestHeader.Get(HeaderRequestID); got != "req_client_0001" {
		t.Errorf("X-Request-Id = %q", got)
	}
	if resp.OperationID != "op_mock_0001" {
		t.Errorf("operation id = %q", resp.OperationID)
	}

	// 敏感响应解密。
	resp, err = client.Do(context.Background(), Request{
		Method:    http.MethodGet,
		Path:      "/card-products/cards/sensitive",
		RequestID: "req_client_0002",
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	var data struct {
		Secure Envelope `json:"secure"`
	}
	if err := resp.DecodeData(&data); err != nil {
		t.Fatalf("DecodeData: %v", err)
	}
	plaintext, err := client.DecryptSensitiveEnvelope(&data.Secure, resp.RequestID)
	if err != nil {
		t.Fatalf("DecryptSensitiveEnvelope: %v", err)
	}
	if string(plaintext) != `{"cardNumber":"4111111111111111","cvv":"123"}` {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if _, err := client.DecryptSensitiveEnvelope(&data.Secure, "req_other"); !errors.Is(err, ErrAADMismatch) {
		t.Errorf("wrong request id: got %v, want ErrAADMismatch", err)
	}
}

func TestClientAPIErrors(t *testing.T) {
	platform := &mockPlatform{}
	client, _ := newTestClient(t, platform, nil)

	_, err := client.Do(context.Background(), Request{Method: http.MethodGet, Path: "/card-products/cards/rate-limited"})
	if !IsCode(err, CodeRateLimited) {
		t.Fatalf("got %v, want REQUEST.RATE_LIMITED", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatal("errors.As failed")
	}
	if apiErr.RetryAfter != "3" || !apiErr.Retryable() || apiErr.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("api error = %+v", apiErr)
	}
	if !apiErr.Response.SignatureVerified {
		t.Error("signed error response must be verified")
	}

	// 401 不带签名头: 默认按类型化错误返回。
	_, err = client.Do(context.Background(), Request{Method: http.MethodGet, Path: "/card-products/cards/unauthorized"})
	if !IsCode(err, CodeKeyDisabled) {
		t.Fatalf("got %v, want API.KEY_DISABLED", err)
	}
	if errors.As(err, &apiErr) && apiErr.Response.SignatureVerified {
		t.Error("unsigned response must not be marked verified")
	}

	// 收紧配置后, 未签名的错误响应也要拒绝。
	strict, _ := newTestClient(t, platform, func(c *Config) { c.RequireSignatureOnErrorResponses = true })
	_, err = strict.Do(context.Background(), Request{Method: http.MethodGet, Path: "/card-products/cards/unauthorized"})
	if !errors.Is(err, ErrResponseSignatureMissing) {
		t.Fatalf("got %v, want ErrResponseSignatureMissing", err)
	}
}

// TestClientBusinessFailureOnHTTP200 覆盖 HTTP 200 + success:false: 必须按 *APIError 返回,
// 且数字形式的业务错误码不得被丢弃。
func TestClientBusinessFailureOnHTTP200(t *testing.T) {
	platform := &mockPlatform{}
	client, _ := newTestClient(t, platform, nil)

	resp, err := client.Do(context.Background(), Request{
		Method: http.MethodGet,
		Path:   "/card-products/cards/business-rejected",
	})
	if err == nil {
		t.Fatal("HTTP 200 with success:false must be reported as an error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T (%v), want *APIError", err, err)
	}
	if apiErr.Code != "4022" {
		t.Errorf("code = %q, want \"4022\"", apiErr.Code)
	}
	if apiErr.Message != "Validation Error" {
		t.Errorf("message = %q, want \"Validation Error\"", apiErr.Message)
	}
	if apiErr.HTTPStatus != http.StatusOK {
		t.Errorf("http status = %d, want 200", apiErr.HTTPStatus)
	}
	if resp == nil {
		t.Fatal("the parsed response must still be returned alongside the error")
	}
	if resp.IsSuccess() {
		t.Error("IsSuccess must follow the envelope success flag, not the HTTP status")
	}
	if !resp.SignatureVerified {
		t.Error("a signed 200 response must still be verified")
	}
}

func TestClientRejectsTamperedResponse(t *testing.T) {
	platform := &mockPlatform{tamperBody: true}
	client, _ := newTestClient(t, platform, nil)
	resp, err := client.Do(context.Background(), Request{Method: http.MethodGet, Path: "/card-products/cards/page"})
	if !errors.Is(err, ErrResponseSignatureInvalid) {
		t.Fatalf("got %v, want ErrResponseSignatureInvalid", err)
	}
	if resp != nil {
		t.Error("unverified response body must not be handed to the caller")
	}
}

func TestClientRequiresSignedSuccessResponse(t *testing.T) {
	platform := &mockPlatform{omitSignature: true}
	client, _ := newTestClient(t, platform, nil)
	if _, err := client.Do(context.Background(), Request{Method: http.MethodGet, Path: "/card-products/cards/page"}); !errors.Is(err, ErrResponseSignatureMissing) {
		t.Fatalf("got %v, want ErrResponseSignatureMissing", err)
	}

	relaxed, _ := newTestClient(t, platform, func(c *Config) {
		c.DisableResponseSignatureVerification = true
		c.PlatformAuthPublicKey = nil
	})
	resp, err := relaxed.Do(context.Background(), Request{Method: http.MethodGet, Path: "/card-products/cards/page"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.SignatureVerified {
		t.Error("verification is disabled, must not report verified")
	}
}

func TestClientConfigValidation(t *testing.T) {
	if _, err := New(Config{APIVersion: "1", APIKey: "apk", MerchantAuthPrivateKey: privateKey(t, "merchant_auth")}); !errors.Is(err, ErrInvalidConfig) {
		t.Error("missing base url must be rejected")
	}
	if _, err := New(Config{APIVersion: "1", BaseURL: "https://example.com", MerchantAuthPrivateKey: privateKey(t, "merchant_auth")}); !errors.Is(err, ErrInvalidConfig) {
		t.Error("missing api key must be rejected")
	}
	if _, err := New(Config{APIVersion: "1", BaseURL: "https://example.com", APIKey: "apk"}); !errors.Is(err, ErrInvalidConfig) {
		t.Error("missing merchant_auth key must be rejected")
	}
	if _, err := New(Config{APIVersion: "1",
		BaseURL:                "https://example.com",
		APIKey:                 "apk",
		MerchantAuthPrivateKey: privateKey(t, "merchant_auth"),
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Error("response verification enabled without platform_auth key must be rejected")
	}

	client, err := New(Config{APIVersion: "1",
		BaseURL:                "https://example.com",
		APIKey:                 "apk",
		MerchantAuthPrivateKey: privateKey(t, "merchant_auth"),
		PlatformAuthPublicKey:  publicKey(t, "platform_auth"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Prepare(context.Background(), Request{Method: http.MethodPost, Path: "cards/create"}); !errors.Is(err, ErrInvalidConfig) {
		t.Error("path without leading slash must be rejected")
	}
	if _, err := client.Prepare(context.Background(), Request{
		Method:   http.MethodPost,
		Path:     "/cards/create",
		Body:     []byte("{}"),
		JSONBody: map[string]string{},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Error("Body and JSONBody are mutually exclusive")
	}
	if _, err := client.Prepare(context.Background(), Request{
		Method:  http.MethodPost,
		Path:    "/card-products/10010106/shared/cards/create",
		Encrypt: true,
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Error("encrypted request without platform_enc key must be rejected")
	}
}

func TestEncodeQuery(t *testing.T) {
	got := EncodeQuery(url.Values{"q": {"hello world"}, "tag": {"中文"}, "a": {"2", "1"}})
	want := "a=1&a=2&q=hello%20world&tag=%E4%B8%AD%E6%96%87"
	if got != want {
		t.Fatalf("EncodeQuery = %q, want %q", got, want)
	}
	canonical, err := CanonicalizeQuery(got)
	if err != nil {
		t.Fatalf("CanonicalizeQuery: %v", err)
	}
	if canonical != want {
		t.Fatalf("canonicalized = %q, want %q", canonical, want)
	}
}
