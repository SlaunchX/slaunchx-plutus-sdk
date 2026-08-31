package plutus

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestEncryptedEnvelopeVectors(t *testing.T) {
	for _, vec := range vectors(t).Vectors.EncryptedEnvelope {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			aad := AAD{
				RequestID:     vec.AADComponents.RequestID,
				RouteTemplate: vec.AADComponents.RouteTemplate,
				Timestamp:     vec.AADComponents.Timestamp,
				KeyID:         vec.AADComponents.KeyID,
			}
			if aad.String() != vec.AADString {
				t.Fatalf("aad string = %q, want %q", aad.String(), vec.AADString)
			}
			if aad.Base64() != vec.AADBase64 {
				t.Fatalf("aad base64 = %q, want %q", aad.Base64(), vec.AADBase64)
			}
			// 信封里的 aad 只是回显, 必须与本地重建值一致。
			if vec.Envelope.AAD != vec.AADBase64 {
				t.Fatalf("envelope aad echo = %q, want %q", vec.Envelope.AAD, vec.AADBase64)
			}
			if vec.Envelope.Algorithm != EnvelopeAlgorithm {
				t.Fatalf("algorithm = %q, want %q", vec.Envelope.Algorithm, EnvelopeAlgorithm)
			}
			if vec.Envelope.EncryptedPayload != vec.Envelope.Ciphertext {
				t.Fatalf("encryptedPayload must equal ciphertext on the API chain")
			}
			if vec.Envelope.EnvelopeVersion != nil {
				t.Fatalf("API chain envelope must not carry envelopeVersion")
			}
			if got, err := vec.Envelope.DecodedAAD(); err != nil || got != aad {
				t.Fatalf("DecodedAAD = %+v (%v), want %+v", got, err, aad)
			}

			priv := privateKey(t, vec.DecryptionKey)
			if fp, err := KeyFingerprint(&priv.PublicKey); err != nil || fp != vec.Envelope.KeyFingerprint {
				t.Fatalf("keyFingerprint = %q, want decryption key fingerprint %q (%v)", vec.Envelope.KeyFingerprint, fp, err)
			}

			envelope := vec.Envelope
			plaintext, err := Open(priv, &envelope, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if string(plaintext) != vec.ExpectedPlaintext {
				t.Fatalf("plaintext = %q, want %q", plaintext, vec.ExpectedPlaintext)
			}

			// 敏感响应方向: 高层入口从回显 aad 取 timestamp 并重建其余分量。
			if vec.Direction == "sensitive_response" {
				got, err := OpenSensitiveResponse(priv, &envelope, aad.RequestID)
				if err != nil {
					t.Fatalf("OpenSensitiveResponse: %v", err)
				}
				if string(got) != vec.ExpectedPlaintext {
					t.Fatalf("sensitive plaintext = %q, want %q", got, vec.ExpectedPlaintext)
				}
				// 关联 ID 不一致时 AAD 重建失败。
				if _, err := OpenSensitiveResponse(priv, &envelope, aad.RequestID+"x"); !errors.Is(err, ErrAADMismatch) {
					t.Errorf("wrong request id: got %v, want ErrAADMismatch", err)
				}
			}

			// 负向: AAD 任一分量被篡改都必须失败。
			for name, tampered := range map[string]AAD{
				"requestId":     {RequestID: aad.RequestID + "x", RouteTemplate: aad.RouteTemplate, Timestamp: aad.Timestamp, KeyID: aad.KeyID},
				"routeTemplate": {RequestID: aad.RequestID, RouteTemplate: aad.RouteTemplate + "/x", Timestamp: aad.Timestamp, KeyID: aad.KeyID},
				"timestamp":     {RequestID: aad.RequestID, RouteTemplate: aad.RouteTemplate, Timestamp: "1755600099000", KeyID: aad.KeyID},
				"keyId":         {RequestID: aad.RequestID, RouteTemplate: aad.RouteTemplate, Timestamp: aad.Timestamp, KeyID: "SHA256:" + strings.Repeat("0", 64)},
			} {
				if _, err := Open(priv, &envelope, tampered); !errors.Is(err, ErrAADMismatch) {
					t.Errorf("tampered aad component %s: got %v, want ErrAADMismatch", name, err)
				}
			}

			// 负向: 篡改密文时 GCM 认证必须失败。
			blob, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
			if err != nil {
				t.Fatalf("decode ciphertext: %v", err)
			}
			blob[len(blob)-1] ^= 0x01
			corrupted := envelope
			corrupted.Ciphertext = base64.StdEncoding.EncodeToString(blob)
			if _, err := Open(priv, &corrupted, aad); !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("tampered ciphertext: got %v, want ErrDecryptFailed", err)
			}

			// 负向: 用另一把私钥解包必须失败。
			other := privateKey(t, "platform_auth")
			if _, err := Open(other, &envelope, aad); !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("wrong private key: got %v, want ErrDecryptFailed", err)
			}
		})
	}
}

func TestSealRequestRoundTrip(t *testing.T) {
	pub := publicKey(t, "platform_enc")
	priv := privateKey(t, "platform_enc")
	fingerprint, err := KeyFingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	const (
		requestID     = "req_roundtrip_0001"
		routeTemplate = "/card-products/10010106/shared/cards/create"
		timestamp     = "1755600010000"
	)
	plaintext := []byte(`{"platformCardProductBizId":"pcp_example_001","quantity":2}`)

	env, err := SealRequest(pub, requestID, routeTemplate, timestamp, plaintext)
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}
	if env.KeyFingerprint != fingerprint {
		t.Errorf("keyFingerprint = %q, want %q", env.KeyFingerprint, fingerprint)
	}
	if env.EncryptedPayload != env.Ciphertext {
		t.Error("encryptedPayload must equal ciphertext")
	}
	if env.EnvelopeVersion != nil {
		t.Error("API chain envelope must not carry envelopeVersion")
	}
	aad := AAD{RequestID: requestID, RouteTemplate: routeTemplate, Timestamp: timestamp, KeyID: fingerprint}
	if env.AAD != aad.Base64() {
		t.Errorf("aad echo = %q, want %q", env.AAD, aad.Base64())
	}

	blob, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	if want := GCMNonceSize + len(plaintext) + GCMTagSize; len(blob) != want {
		t.Errorf("ciphertext blob = %d bytes, want %d (iv||ct||tag)", len(blob), want)
	}

	got, err := Open(priv, env, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round-trip plaintext = %q, want %q", got, plaintext)
	}

	// 每次加密使用新的一次性密钥与 IV。
	again, err := SealRequest(pub, requestID, routeTemplate, timestamp, plaintext)
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}
	if again.Ciphertext == env.Ciphertext || again.EncryptedKey == env.EncryptedKey {
		t.Error("envelope must use a fresh AES key and IV on every seal")
	}

	if _, err := SealRequest(pub, "", routeTemplate, timestamp, plaintext); !errors.Is(err, ErrInvalidConfig) {
		t.Error("empty request id must be rejected")
	}
	if _, err := SealRequest(pub, requestID, routeTemplate, "1755600010", plaintext); !errors.Is(err, ErrInvalidTimestamp) {
		t.Error("second-precision timestamp must be rejected")
	}
}

func TestSensitiveResponseRoundTrip(t *testing.T) {
	pub := publicKey(t, "merchant_enc")
	priv := privateKey(t, "merchant_enc")
	fingerprint, err := KeyFingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	aad := AAD{RequestID: "req_sensitive_0001", RouteTemplate: "", Timestamp: "1755600011000", KeyID: fingerprint}
	env, err := Seal(pub, fingerprint, aad, []byte(`{"cardNumber":"4111111111111111"}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	plaintext, err := OpenSensitiveResponse(priv, env, aad.RequestID)
	if err != nil {
		t.Fatalf("OpenSensitiveResponse: %v", err)
	}
	if string(plaintext) != `{"cardNumber":"4111111111111111"}` {
		t.Fatalf("plaintext = %q", plaintext)
	}

	// 指纹不符 (平台用了另一把商户公钥) 必须拒绝。
	wrong := *env
	wrong.KeyFingerprint = "SHA256:" + strings.Repeat("a", 64)
	if _, err := OpenSensitiveResponse(priv, &wrong, aad.RequestID); !errors.Is(err, ErrKeyFingerprintMismatch) {
		t.Errorf("fingerprint mismatch: got %v, want ErrKeyFingerprintMismatch", err)
	}
}

func TestEnvelopeValidation(t *testing.T) {
	if _, err := ParseEnvelopeJSON([]byte(`{"algorithm":"RSA-OAEP-AES-128-GCM","encryptedKey":"a","ciphertext":"b","aad":"c"}`)); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Error("unknown algorithm must be rejected")
	}
	if _, err := ParseEnvelopeJSON([]byte(`{"algorithm":"RSA-OAEP-AES-256-GCM","ciphertext":"b","aad":"c"}`)); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Error("missing encryptedKey must be rejected")
	}
	if _, err := ParseAAD("a|b|c"); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Error("aad with 3 components must be rejected")
	}
	aad, err := ParseAAD("req_1||1755600011000|SHA256:ff")
	if err != nil {
		t.Fatalf("ParseAAD: %v", err)
	}
	if aad.RouteTemplate != "" || aad.Timestamp != "1755600011000" {
		t.Fatalf("ParseAAD = %+v", aad)
	}
}
