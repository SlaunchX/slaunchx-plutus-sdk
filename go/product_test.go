package plutus

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestProductQuery(t *testing.T) {
	var vectors struct {
		Valid   [][]*string `json:"valid"`
		Invalid []string    `json:"invalid"`
	}
	raw, err := os.ReadFile("../shared/product-query-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, pair := range vectors.Valid {
		input := ""
		if pair[0] != nil {
			input = *pair[0]
		}
		got, err := CanonicalizeQueryForProfile(input, ProductV1)
		if err != nil || got != *pair[1] {
			t.Fatalf("query %q: got %q, error %v", input, got, err)
		}
	}
	for _, raw := range vectors.Invalid {
		if _, err := CanonicalizeQueryForProfile(raw, ProductV1); err == nil {
			t.Fatalf("accepted invalid query %q", raw)
		}
	}
}

func TestProductClientCompatibility(t *testing.T) {
	for _, mode := range []string{"missing", "present", "wrong", "empty", "tamper", "other", "alpha", "unsigned"} {
		t.Run(mode, func(t *testing.T) {
			ids := []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				id := r.Header.Get(HeaderRequestID)
				ids = append(ids, id)
				if id == "" {
					t.Error("request ID missing")
				}
				if r.URL.RawQuery != "q=a%20b&star=*&tilde=%7E" {
					t.Error("query mismatch")
				}
				if r.Header.Get(HeaderIdempotencyKey) != "operation-1" {
					t.Error("idempotency header missing")
				}
				canonical := strings.Join([]string{r.Method, "/test", "q=a%20b&star=*&tilde=%7E", r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderNonce), "1", SHA256Hex(raw)}, "\n")
				if err := VerifyCanonicalString(publicKey(t, "merchant_auth"), canonical, r.Header.Get(HeaderSignature)); err != nil {
					t.Error(err)
				}
				body := []byte(`{"success":true,"data":[]}`)
				if mode == "other" {
					id = "other-request"
				}
				lines := []string{id, "200", "application/json", "1788836400000", SHA256Hex(body)}
				if mode == "alpha" {
					lines = append([]string{ResponseCanonicalPrefix, SHA256Hex([]byte(canonical)), "1", "/test", ""}, lines...)
				}
				sig, err := SignCanonicalString(privateKey(t, "platform_auth"), strings.Join(lines, "\n"))
				if err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set(HeaderResponseTimestamp, "1788836400000")
				if mode != "unsigned" {
					w.Header().Set(HeaderResponseSignature, sig)
				}
				if mode == "present" {
					w.Header().Set(HeaderRequestID, id)
				}
				if mode == "wrong" {
					w.Header().Set(HeaderRequestID, "wrong-id")
				}
				if mode == "empty" {
					w.Header().Set(HeaderRequestID, "")
				}
				if mode == "tamper" {
					body = append(body, ' ')
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			client, err := New(Config{APIVersion: "1", BaseURL: server.URL, APIKey: "key", MerchantAuthPrivateKey: privateKey(t, "merchant_auth"), PlatformAuthPublicKey: publicKey(t, "platform_auth"), ProtocolProfile: ProductV1})
			if err != nil {
				t.Fatal(err)
			}
			req := Request{Method: "POST", Path: "/test", RawQuery: "q=a+b&tilde=~&star=%2A", Body: []byte(`{"ok":true}`), IdempotencyKey: "operation-1"}
			result, err := client.Do(context.Background(), req)
			if mode == "missing" || mode == "present" {
				if err != nil || !result.SignatureVerified {
					t.Fatalf("verification failed: %v", err)
				}
				if _, err = client.Do(context.Background(), req); err != nil {
					t.Fatal(err)
				}
				if ids[0] == ids[1] {
					t.Error("request IDs repeated")
				}
			} else if err == nil {
				t.Fatal("accepted invalid response")
			}
		})
	}
}

func TestProductRejectsAmbiguousIDs(t *testing.T) {
	client, err := New(Config{APIVersion: "1", BaseURL: "https://example.test", APIKey: "key", MerchantAuthPrivateKey: privateKey(t, "merchant_auth"), DisableResponseSignatureVerification: true, ProtocolProfile: ProductV1})
	if err != nil {
		t.Fatal(err)
	}
	for _, headers := range []http.Header{{"x-request-id": {"a"}, "X-Request-Id": {"b"}}, {"X-Request-Id": {"a\nb"}}} {
		if _, err := client.Prepare(context.Background(), Request{Method: "GET", Path: "/test", Header: headers}); err == nil {
			t.Fatal("accepted ambiguous ID")
		}
	}
	prepared, err := client.Prepare(context.Background(), Request{Method: "GET", Path: "/test", Header: http.Header{"x-request-id": {" custom "}}})
	if err != nil || prepared.Binding.SentRequestID != "custom" || prepared.HTTPRequest.Header.Get(HeaderRequestID) != "custom" {
		t.Fatalf("explicit ID not retained: %v", err)
	}
}

func TestProductNoProtocolFallback(t *testing.T) {
	req := CanonicalRequest{Method: "GET", ExternalPath: "/test", Timestamp: "1788836400000", Nonce: "0123456789abcdef", APIVersion: "1"}
	signed, err := NewSignerWithKey("key", privateKey(t, "merchant_auth")).Sign(req)
	if err != nil || len(strings.Split(signed.CanonicalString, "\n")) != 8 {
		t.Fatal("default changed")
	}
	req.ProtocolProfile = ProductV1
	product, err := NewSignerWithKey("key", privateKey(t, "merchant_auth")).Sign(req)
	if err != nil || len(strings.Split(product.CanonicalString, "\n")) != 7 {
		t.Fatal("product must sign seven lines")
	}
	body := []byte("{}")
	canonical := strings.Join([]string{"id", "200", "application/json", "1788836400000", SHA256Hex(body)}, "\n")
	sig, _ := SignCanonicalString(privateKey(t, "platform_auth"), canonical)
	header := http.Header{}
	header.Set(HeaderRequestID, "id")
	header.Set(HeaderResponseSignature, sig)
	header.Set("Content-Type", "application/json")
	header.Set(HeaderResponseTimestamp, "1788836400000")
	if err := NewResponseVerifierWithKey(publicKey(t, "platform_auth")).Verify(ResponseBinding{RequestCanonicalSHA256: signed.CanonicalDigestHex, APIVersion: "1", ExternalPath: "/test"}, 200, header, body); err == nil {
		t.Fatal("default accepted product response")
	}
	if _, err := CanonicalizeQueryForProfile("", ProtocolProfile("unknown")); err == nil {
		t.Fatal("accepted unknown profile")
	}
}

func TestRequiredAPIVersion(t *testing.T) {
	cfg := Config{BaseURL: "https://example.test", APIKey: "key", MerchantAuthPrivateKey: privateKey(t, "merchant_auth"), PlatformAuthPublicKey: publicKey(t, "platform_auth")}
	for _, version := range []string{"", " ", "\t\n"} {
		cfg.APIVersion = version
		if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "api version") {
			t.Fatalf("blank version %q: %v", version, err)
		}
	}
	for _, version := range []string{"1", "2"} {
		cfg.APIVersion = version
		client, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if client.apiVersion != version {
			t.Fatalf("configured version lost: %s", client.apiVersion)
		}
	}
}
