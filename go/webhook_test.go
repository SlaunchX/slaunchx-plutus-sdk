package plutus

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func webhookHTTPHeader(vec webhookVector) http.Header {
	header := http.Header{}
	for name, value := range vec.Headers {
		header.Set(name, value)
	}
	return header
}

func TestWebhookVectors(t *testing.T) {
	for _, vec := range vectors(t).Vectors.Webhook {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			body := []byte(vec.Body)
			headers := WebhookHeadersFromHTTP(webhookHTTPHeader(vec))
			if headers.DeliveryID != vec.AADComponents.RequestID {
				t.Fatalf("delivery id = %q, want %q", headers.DeliveryID, vec.AADComponents.RequestID)
			}

			// 摘要是 Base64, 不是 hex。
			if got := WebhookBodyDigestBase64(body); got != vec.BodyDigestBase64 {
				t.Fatalf("body digest = %q, want %q", got, vec.BodyDigestBase64)
			}
			if got := headers.CanonicalString(body); got != vec.SignatureCanonicalString {
				t.Fatalf("canonical string = %q, want %q", got, vec.SignatureCanonicalString)
			}
			if lines := strings.Split(vec.SignatureCanonicalString, "\n"); len(lines) != 4 {
				t.Fatalf("webhook canonical string must have 4 lines, got %d", len(lines))
			}

			// AAD: routeTemplate 固定为 "webhook", keyId 是 API Key 业务 ID。
			aad := headers.AAD()
			if aad.RouteTemplate != WebhookRouteTemplate {
				t.Fatalf("route template = %q, want %q", aad.RouteTemplate, WebhookRouteTemplate)
			}
			if aad.String() != vec.AADString || aad.Base64() != vec.AADBase64 {
				t.Fatalf("aad = %q / %q, want %q / %q", aad.String(), aad.Base64(), vec.AADString, vec.AADBase64)
			}

			// 信封形状: 有 envelopeVersion, 无 encryptedPayload。
			env, err := ParseWebhookEnvelope(body)
			if err != nil {
				t.Fatalf("ParseWebhookEnvelope: %v", err)
			}
			if env.EnvelopeVersion == nil || *env.EnvelopeVersion != 1 {
				t.Fatal("webhook envelope must carry envelopeVersion = 1")
			}
			if env.EncryptedPayload != "" {
				t.Fatal("webhook envelope must not carry encryptedPayload")
			}
			if env.AAD != vec.AADBase64 {
				t.Fatalf("envelope aad echo = %q, want %q", env.AAD, vec.AADBase64)
			}

			receiver, err := NewWebhookReceiver(WebhookConfig{
				APIKey:                vec.Headers[HeaderWebhookKeyID],
				PlatformAuthPublicKey: publicKey(t, vec.SignatureVerificationKey),
				MerchantEncPrivateKey: privateKey(t, vec.DecryptionKey),
			})
			if err != nil {
				t.Fatalf("NewWebhookReceiver: %v", err)
			}
			if err := receiver.Verify(headers, body); err != nil {
				t.Fatalf("Verify: %v", err)
			}

			notification, err := receiver.Handle(headers, body)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			if string(notification.Plaintext) != vec.ExpectedPlaintext {
				t.Fatalf("plaintext = %q, want %q", notification.Plaintext, vec.ExpectedPlaintext)
			}
			if notification.Payload.DeliveryBizID != headers.DeliveryID ||
				notification.Payload.EventType != headers.EventType ||
				notification.Payload.PayloadSchemaVersion != 1 {
				t.Fatalf("payload cross-check failed: %+v", notification.Payload)
			}
			if notification.Payload.EventID == "" || notification.Payload.Resource.BizID == "" {
				t.Fatalf("payload is incomplete: %+v", notification.Payload)
			}

			// 负向: body 被篡改 (哪怕是尾随空白) 验签必须失败, 且不进入解密。
			if _, err := receiver.Handle(headers, append(append([]byte(nil), body...), ' ')); !errors.Is(err, ErrWebhookSignatureInvalid) {
				t.Errorf("tampered body: got %v, want ErrWebhookSignatureInvalid", err)
			}
			// 负向: 传输头分量被篡改。
			for name, mutate := range map[string]func(WebhookHeaders) WebhookHeaders{
				"deliveryId": func(h WebhookHeaders) WebhookHeaders { h.DeliveryID += "x"; return h },
				"eventType":  func(h WebhookHeaders) WebhookHeaders { h.EventType += "x"; return h },
				"timestamp":  func(h WebhookHeaders) WebhookHeaders { h.Timestamp = "1788142396409"; return h },
			} {
				if err := receiver.Verify(mutate(headers), body); !errors.Is(err, ErrWebhookSignatureInvalid) {
					t.Errorf("tampered header %s: got %v, want ErrWebhookSignatureInvalid", name, err)
				}
			}
			// 负向: keyId 与本商户 API Key 不符。
			wrongKey := headers
			wrongKey.KeyID = "apk_other_0002"
			if _, err := receiver.Handle(wrongKey, body); !errors.Is(err, ErrWebhookPayloadMismatch) {
				t.Errorf("wrong key id: got %v, want ErrWebhookPayloadMismatch", err)
			}
			// 负向: AAD 的 keyId 位被篡改后解密失败 (绕过头比对, 直接用错误 AAD 解封)。
			tampered := aad
			tampered.KeyID = "apk_other_0002"
			if _, err := Open(privateKey(t, vec.DecryptionKey), env, tampered); !errors.Is(err, ErrAADMismatch) {
				t.Errorf("tampered aad keyId: got %v, want ErrAADMismatch", err)
			}
		})
	}
}

func TestWebhookEnvelopeRejectsAPIChainShape(t *testing.T) {
	vec := vectors(t).Vectors.Webhook[0]
	var raw map[string]any
	if err := json.Unmarshal([]byte(vec.Body), &raw); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}

	// 多出 encryptedPayload 字段 (additionalProperties: false)。
	withExtra := map[string]any{}
	for k, v := range raw {
		withExtra[k] = v
	}
	withExtra["encryptedPayload"] = raw["ciphertext"]
	encoded, _ := json.Marshal(withExtra)
	if _, err := ParseWebhookEnvelope(encoded); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Errorf("encryptedPayload must be rejected, got %v", err)
	}

	// 缺 envelopeVersion。
	withoutVersion := map[string]any{}
	for k, v := range raw {
		if k != "envelopeVersion" {
			withoutVersion[k] = v
		}
	}
	encoded, _ = json.Marshal(withoutVersion)
	if _, err := ParseWebhookEnvelope(encoded); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Errorf("missing envelopeVersion must be rejected, got %v", err)
	}

	// envelopeVersion 不为 1。
	raw["envelopeVersion"] = 2
	encoded, _ = json.Marshal(raw)
	if _, err := ParseWebhookEnvelope(encoded); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Errorf("envelopeVersion 2 must be rejected, got %v", err)
	}
}

func TestWebhookHandleRequest(t *testing.T) {
	vec := vectors(t).Vectors.Webhook[0]
	receiver, err := NewWebhookReceiver(WebhookConfig{
		APIKey:                vec.Headers[HeaderWebhookKeyID],
		PlatformAuthPublicKey: publicKey(t, vec.SignatureVerificationKey),
		MerchantEncPrivateKey: privateKey(t, vec.DecryptionKey),
	})
	if err != nil {
		t.Fatalf("NewWebhookReceiver: %v", err)
	}

	var captured *WebhookNotification
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notification, err := receiver.HandleRequest(r)
		if err != nil {
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		captured = notification
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/webhooks/slaunchx", bytes.NewReader([]byte(vec.Body)))
	for name, value := range vec.Headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if captured == nil || string(captured.Plaintext) != vec.ExpectedPlaintext {
		t.Fatal("handler did not decrypt the notification")
	}

	// 篡改的投递必须被拒绝。
	req = httptest.NewRequest(http.MethodPost, "/webhooks/slaunchx", strings.NewReader(vec.Body+" "))
	for name, value := range vec.Headers {
		req.Header.Set(name, value)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestWebhookTimestampTolerance(t *testing.T) {
	vec := vectors(t).Vectors.Webhook[0]
	deliveredAt := time.UnixMilli(1788142396408)
	receiver, err := NewWebhookReceiver(WebhookConfig{
		APIKey:                vec.Headers[HeaderWebhookKeyID],
		PlatformAuthPublicKey: publicKey(t, vec.SignatureVerificationKey),
		MerchantEncPrivateKey: privateKey(t, vec.DecryptionKey),
		TimestampTolerance:    5 * time.Minute,
		Now:                   func() time.Time { return deliveredAt.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("NewWebhookReceiver: %v", err)
	}
	headers := WebhookHeadersFromHTTP(webhookHTTPHeader(vec))
	if _, err := receiver.Handle(headers, []byte(vec.Body)); err != nil {
		t.Fatalf("within tolerance: %v", err)
	}

	receiver, err = NewWebhookReceiver(WebhookConfig{
		APIKey:                vec.Headers[HeaderWebhookKeyID],
		PlatformAuthPublicKey: publicKey(t, vec.SignatureVerificationKey),
		MerchantEncPrivateKey: privateKey(t, vec.DecryptionKey),
		TimestampTolerance:    5 * time.Minute,
		Now:                   func() time.Time { return deliveredAt.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("NewWebhookReceiver: %v", err)
	}
	if _, err := receiver.Handle(headers, []byte(vec.Body)); !errors.Is(err, ErrWebhookTimestampOutOfRange) {
		t.Fatalf("outside tolerance: got %v, want ErrWebhookTimestampOutOfRange", err)
	}
}

func TestMandatoryWebhookRecipient(t *testing.T) {
	cfg := WebhookConfig{PlatformAuthPublicKey: publicKey(t, "platform_auth"), MerchantEncPrivateKey: privateKey(t, "merchant_enc")}
	for _, id := range []string{"", " ", "\t\n"} {
		cfg.APIKey = id
		if _, err := NewWebhookReceiver(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("missing local recipient accepted: %v", err)
		}
	}
	vec := vectors(t).Vectors.Webhook[0]
	headers := WebhookHeadersFromHTTP(webhookHTTPHeader(vec))
	body := []byte(vec.Body)
	cfg.APIKey = vec.Headers[HeaderWebhookKeyID]
	correct, err := NewWebhookReceiver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = correct.Handle(headers, body); err != nil {
		t.Fatal(err)
	}
	// Identical platform and encryption keys; only local API Key changes.
	cfg.APIKey = "apk_other_recipient"
	other, err := NewWebhookReceiver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = other.Verify(headers, body); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Handle(headers, body); !errors.Is(err, ErrWebhookPayloadMismatch) {
		t.Fatalf("wrong recipient: %v", err)
	}
	if _, err = other.Handle(headers, append(append([]byte{}, body...), ' ')); !errors.Is(err, ErrWebhookSignatureInvalid) {
		t.Fatalf("signature must be checked first: %v", err)
	}
	headers.KeyID = cfg.APIKey
	if _, err = other.Handle(headers, body); err == nil {
		t.Fatal("rewriting header bypassed AAD")
	}
}
