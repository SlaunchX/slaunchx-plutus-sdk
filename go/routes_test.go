package plutus

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"testing"
)

// TestEncryptedRouteTemplatesExactSet 断言常量表恰好包含且仅包含 SPEC 第 3 节列出的 6 条
// 已知加密端点, 逐字节匹配。
func TestEncryptedRouteTemplatesExactSet(t *testing.T) {
	want := []string{
		"/card-products/10010105/cards/create",
		"/card-products/10010106/shared/cards/create",
		"/card-products/10010106/prepaid/cards/create",
		"/card-products/10010107/prepaid/cards/create",
		"/card-products/10010107/prepaid/cards/recharge",
		"/card-products/10010107/prepaid/cards/withdraw",
	}
	got := append([]string(nil), EncryptedRouteTemplates...)
	sortedWant := append([]string(nil), want...)
	sortedGot := append([]string(nil), got...)
	sort.Strings(sortedWant)
	sort.Strings(sortedGot)
	if len(sortedGot) != len(sortedWant) {
		t.Fatalf("EncryptedRouteTemplates has %d entries, want %d: %v", len(sortedGot), len(sortedWant), got)
	}
	for i := range sortedWant {
		if sortedGot[i] != sortedWant[i] {
			t.Fatalf("EncryptedRouteTemplates[%d] = %q, want %q (full: %v)", i, sortedGot[i], sortedWant[i], got)
		}
	}
}

func TestIsKnownEncryptedRoute(t *testing.T) {
	for _, route := range EncryptedRouteTemplates {
		if !IsKnownEncryptedRoute(route) {
			t.Errorf("IsKnownEncryptedRoute(%q) = false, want true", route)
		}
	}
	unknown := []string{
		"",
		"/card-products/cards/page",
		"/card-products/10010105/cards/create/",
		"/card-products/10010999/cards/create",
		"/prometheus/api/v1/consumer/card-products/10010105/cards/create",
	}
	for _, route := range unknown {
		if IsKnownEncryptedRoute(route) {
			t.Errorf("IsKnownEncryptedRoute(%q) = true, want false", route)
		}
	}
}

// TestPrepareUnknownEncryptedRouteDefaultNonStrict 覆盖默认 (非严格) 模式:
// 未知 routeTemplate 不阻断请求, Prepare 不返回 error。
func TestPrepareUnknownEncryptedRouteDefaultNonStrict(t *testing.T) {
	client, err := New(Config{
		BaseURL:                "https://example.com",
		APIKey:                 "apk",
		MerchantAuthPrivateKey: privateKey(t, "merchant_auth"),
		PlatformAuthPublicKey:  publicKey(t, "platform_auth"),
		PlatformEncPublicKey:   publicKey(t, "platform_enc"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.strictEncryptedRoute {
		t.Fatal("StrictEncryptedRouteValidation must default to false")
	}
	prepared, err := client.Prepare(context.Background(), Request{
		Method:    http.MethodPost,
		Path:      "/card-products/unknown/cards/create",
		JSONBody:  map[string]string{"a": "b"},
		Encrypt:   true,
		RequestID: "req_unknown_route_0001",
	})
	if err != nil {
		t.Fatalf("Prepare must not fail on unknown route in non-strict mode: %v", err)
	}
	if prepared == nil || prepared.Envelope == nil {
		t.Fatal("expected an encrypted envelope to be prepared")
	}
}

// TestPrepareUnknownEncryptedRouteStrict 覆盖严格模式: 未知 routeTemplate 返回
// 满足 errors.Is(err, ErrUnknownEncryptedRoute) 的 error; 已知路由不受影响。
func TestPrepareUnknownEncryptedRouteStrict(t *testing.T) {
	client, err := New(Config{
		BaseURL:                        "https://example.com",
		APIKey:                         "apk",
		MerchantAuthPrivateKey:         privateKey(t, "merchant_auth"),
		PlatformAuthPublicKey:          publicKey(t, "platform_auth"),
		PlatformEncPublicKey:           publicKey(t, "platform_enc"),
		StrictEncryptedRouteValidation: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !client.strictEncryptedRoute {
		t.Fatal("StrictEncryptedRouteValidation must be true")
	}

	_, err = client.Prepare(context.Background(), Request{
		Method:    http.MethodPost,
		Path:      "/card-products/unknown/cards/create",
		JSONBody:  map[string]string{"a": "b"},
		Encrypt:   true,
		RequestID: "req_unknown_route_0002",
	})
	if !errors.Is(err, ErrUnknownEncryptedRoute) {
		t.Fatalf("got %v, want ErrUnknownEncryptedRoute", err)
	}

	prepared, err := client.Prepare(context.Background(), Request{
		Method:    http.MethodPost,
		Path:      "/card-products/10010106/shared/cards/create",
		JSONBody:  map[string]string{"a": "b"},
		Encrypt:   true,
		RequestID: "req_known_route_0001",
	})
	if err != nil {
		t.Fatalf("Prepare must succeed for a known encrypted route in strict mode: %v", err)
	}
	if prepared == nil || prepared.Envelope == nil {
		t.Fatal("expected an encrypted envelope to be prepared")
	}
}
