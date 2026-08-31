package plutus

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestRequestSignatureVectors(t *testing.T) {
	for _, vec := range vectors(t).Vectors.RequestSignature {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			req := CanonicalRequest{
				Method:         vec.Request.Method,
				ExternalPath:   vec.Request.ExternalPath,
				RawQuery:       str(vec.Request.QueryString),
				Timestamp:      vec.Request.Timestamp,
				Nonce:          vec.Request.Nonce,
				APIVersion:     vec.Request.APIVersion,
				IdempotencyKey: str(vec.Request.IdempotencyKey),
				Body:           bodyBytes(vec.Request.Body),
			}

			canonicalQuery, err := CanonicalizeQuery(req.RawQuery)
			if err != nil {
				t.Fatalf("canonicalize query: %v", err)
			}
			if canonicalQuery != vec.CanonicalQuery {
				t.Errorf("canonical query = %q, want %q", canonicalQuery, vec.CanonicalQuery)
			}
			if got := ForcesEmptyBodyDigest(req.Method); got != vec.ForcedEmptyBody {
				t.Errorf("forced empty body = %v, want %v", got, vec.ForcedEmptyBody)
			}
			if got := BodyDigestHex(req.Method, req.Body); got != vec.BodyHash {
				t.Errorf("body digest = %s, want %s", got, vec.BodyHash)
			}

			canonical, err := req.CanonicalString()
			if err != nil {
				t.Fatalf("canonical string: %v", err)
			}
			lines := strings.Split(canonical, "\n")
			if len(lines) != len(vec.CanonicalStringLines) {
				t.Fatalf("canonical string has %d lines, want %d", len(lines), len(vec.CanonicalStringLines))
			}
			for i, want := range vec.CanonicalStringLines {
				if lines[i] != want {
					t.Errorf("canonical line %d = %q, want %q", i+1, lines[i], want)
				}
			}
			if canonical != vec.CanonicalString {
				t.Fatalf("canonical string mismatch:\n got %q\nwant %q", canonical, vec.CanonicalString)
			}
			if got := SHA256Hex([]byte(canonical)); got != vec.RequestCanonicalSHA256 {
				t.Errorf("request canonical digest = %s, want %s", got, vec.RequestCanonicalSHA256)
			}

			// 用 merchant_auth 公钥验证向量签名。
			if err := VerifyCanonicalString(publicKey(t, vec.SigningKey), canonical, vec.Signature); err != nil {
				t.Fatalf("verify vector signature: %v", err)
			}

			// PKCS#1 v1.5 是确定性的: 重新签名必须与向量逐字节相等。
			signer := NewSignerWithKey(vec.Headers[HeaderAPIKey], privateKey(t, vec.SigningKey))
			signed, err := signer.Sign(req)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if signed.Signature != vec.Signature {
				t.Fatalf("signature mismatch:\n got %s\nwant %s", signed.Signature, vec.Signature)
			}
			if signed.CanonicalDigestHex != vec.RequestCanonicalSHA256 {
				t.Errorf("canonical digest = %s, want %s", signed.CanonicalDigestHex, vec.RequestCanonicalSHA256)
			}
			for name, want := range vec.Headers {
				if got := signed.Headers[name]; got != want {
					t.Errorf("header %s = %q, want %q", name, got, want)
				}
			}
			if len(signed.Headers) != len(vec.Headers) {
				t.Errorf("produced %d headers, vector has %d: %v", len(signed.Headers), len(vec.Headers), signed.Headers)
			}
		})
	}
}

func TestRequestSignatureRejectsTamperedCanonical(t *testing.T) {
	vec := vectors(t).Vectors.RequestSignature[3]
	pub := publicKey(t, vec.SigningKey)
	tampered := strings.Replace(vec.CanonicalString, "POST", "PUT", 1)
	if err := VerifyCanonicalString(pub, tampered, vec.Signature); err == nil {
		t.Fatal("tampered canonical string must fail verification")
	}
	// 幂等键行被清空后同样必须失败。
	withoutIdem := strings.Replace(vec.CanonicalString, "idem-vector-0000000004", "", 1)
	if err := VerifyCanonicalString(pub, withoutIdem, vec.Signature); err == nil {
		t.Fatal("canonical string without idempotency key must fail verification")
	}
}

func TestSignerValidatesNonceAndTimestamp(t *testing.T) {
	signer := NewSignerWithKey("apk_test", privateKey(t, "merchant_auth"))
	base := CanonicalRequest{
		Method:       "GET",
		ExternalPath: "/card-products/cards/page",
		Timestamp:    "1755600000000",
		Nonce:        "nonce-vector-0000000001",
		APIVersion:   DefaultAPIVersion,
	}

	bad := base
	bad.Nonce = "c2hvcnQ="
	if _, err := signer.Sign(bad); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("base64 nonce must be rejected, got %v", err)
	}

	bad = base
	bad.Nonce = "short"
	if _, err := signer.Sign(bad); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("short nonce must be rejected, got %v", err)
	}

	bad = base
	bad.Timestamp = "1755600000"
	if _, err := signer.Sign(bad); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("second-precision timestamp must be rejected, got %v", err)
	}

	bad = base
	bad.RawQuery = "q=a+b"
	if _, err := signer.Sign(bad); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("raw '+' in query must be rejected, got %v", err)
	}
}

func TestNewNonceIsValid(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce, err := NewNonce()
		if err != nil {
			t.Fatalf("NewNonce: %v", err)
		}
		if err := ValidateNonce(nonce); err != nil {
			t.Fatalf("generated nonce %q is invalid: %v", nonce, err)
		}
		if seen[nonce] {
			t.Fatalf("duplicate nonce %q", nonce)
		}
		seen[nonce] = true
	}
	if err := ValidateNonce("f81d4fae-7dec-11d0-a765-00a0c91e6bf6"); err != nil {
		t.Fatalf("hyphenated UUID must be a valid nonce: %v", err)
	}
}

func responseHeader(vec responseSignatureVector) http.Header {
	header := http.Header{}
	for name, value := range vec.Headers {
		header.Set(name, value)
	}
	header.Set("Content-Type", vec.ContentType)
	return header
}

func TestResponseSignatureVectors(t *testing.T) {
	requestByID := map[string]requestSignatureVector{}
	for _, req := range vectors(t).Vectors.RequestSignature {
		requestByID[req.ID] = req
	}

	for _, vec := range vectors(t).Vectors.ResponseSignature {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			// 绑定摘要必须来自本地重算的请求规范串, 不从响应头读取。
			reqVec, ok := requestByID[vec.RequestVectorID]
			if !ok {
				t.Fatalf("unknown request vector %q", vec.RequestVectorID)
			}
			if got := SHA256Hex([]byte(reqVec.CanonicalString)); got != vec.RequestCanonicalSHA256 {
				t.Fatalf("locally computed binding digest = %s, want %s", got, vec.RequestCanonicalSHA256)
			}

			body := []byte(vec.ResponseBody)
			if got := SHA256Hex(body); got != vec.ResponseBodyHash {
				t.Errorf("response body digest = %s, want %s", got, vec.ResponseBodyHash)
			}

			canonical := CanonicalResponse{
				RequestCanonicalSHA256: vec.RequestCanonicalSHA256,
				APIVersion:             vec.APIVersion,
				ExternalPath:           vec.ExternalPath,
				OperationID:            str(vec.OperationID),
				RequestID:              str(vec.RequestID),
				HTTPStatus:             vec.HTTPStatus,
				ContentType:            vec.ContentType,
				ResponseTimestamp:      vec.ResponseTimestamp,
				Body:                   body,
			}.CanonicalString()
			lines := strings.Split(canonical, "\n")
			if len(lines) != len(vec.CanonicalStringLines) {
				t.Fatalf("canonical string has %d lines, want %d", len(lines), len(vec.CanonicalStringLines))
			}
			for i, want := range vec.CanonicalStringLines {
				if lines[i] != want {
					t.Errorf("canonical line %d = %q, want %q", i+1, lines[i], want)
				}
			}
			if canonical != vec.CanonicalString {
				t.Fatalf("canonical string mismatch:\n got %q\nwant %q", canonical, vec.CanonicalString)
			}
			if err := VerifyCanonicalString(publicKey(t, vec.SigningKey), canonical, vec.Signature); err != nil {
				t.Fatalf("verify vector signature: %v", err)
			}

			verifier := NewResponseVerifierWithKey(publicKey(t, vec.SigningKey))
			binding := ResponseBinding{
				RequestCanonicalSHA256: vec.RequestCanonicalSHA256,
				APIVersion:             vec.APIVersion,
				ExternalPath:           vec.ExternalPath,
			}
			header := responseHeader(vec)
			if err := verifier.Verify(binding, vec.HTTPStatus, header, body); err != nil {
				t.Fatalf("ResponseVerifier.Verify: %v", err)
			}

			// 负向: 篡改响应体、Content-Type 归一化、绑定摘要错误都必须失败。
			if err := verifier.Verify(binding, vec.HTTPStatus, header, append(body, ' ')); !errors.Is(err, ErrResponseSignatureInvalid) {
				t.Errorf("tampered body: got %v, want ErrResponseSignatureInvalid", err)
			}
			normalized := responseHeader(vec)
			normalized.Set("Content-Type", strings.ToLower(strings.ReplaceAll(vec.ContentType, ";charset=UTF-8", "")))
			if vec.ContentType != normalized.Get("Content-Type") {
				if err := verifier.Verify(binding, vec.HTTPStatus, normalized, body); !errors.Is(err, ErrResponseSignatureInvalid) {
					t.Errorf("normalized content-type: got %v, want ErrResponseSignatureInvalid", err)
				}
			}
			wrongBinding := binding
			wrongBinding.RequestCanonicalSHA256 = strings.Repeat("0", 64)
			if err := verifier.Verify(wrongBinding, vec.HTTPStatus, header, body); !errors.Is(err, ErrResponseSignatureInvalid) {
				t.Errorf("wrong binding digest: got %v, want ErrResponseSignatureInvalid", err)
			}
			missing := responseHeader(vec)
			missing.Del(HeaderResponseSignature)
			if err := verifier.Verify(binding, vec.HTTPStatus, missing, body); !errors.Is(err, ErrResponseSignatureMissing) {
				t.Errorf("missing signature: got %v, want ErrResponseSignatureMissing", err)
			}
		})
	}
}

// TestParseAPIResponseFromVectors 只覆盖响应头到 APIResponse 的解析与原始字节保留。
//
// 向量文件的 body 是为签名字节固定下来的历史形态, 不代表当前的统一响应包络,
// 因此这里不做成功/失败判定断言 —— 成功判定用本地 fixture 覆盖,
// 见 envelope_success_test.go 的 TestEnvelopeSuccessDecision。
func TestParseAPIResponseFromVectors(t *testing.T) {
	for _, vec := range vectors(t).Vectors.ResponseSignature {
		resp := ParseAPIResponse(vec.HTTPStatus, responseHeader(vec), []byte(vec.ResponseBody))
		if resp.RequestID != str(vec.RequestID) {
			t.Errorf("%s: request id = %q, want %q", vec.ID, resp.RequestID, str(vec.RequestID))
		}
		if resp.OperationID != str(vec.OperationID) {
			t.Errorf("%s: operation id = %q, want %q", vec.ID, resp.OperationID, str(vec.OperationID))
		}
		if resp.HTTPStatus != vec.HTTPStatus {
			t.Errorf("%s: http status = %d, want %d", vec.ID, resp.HTTPStatus, vec.HTTPStatus)
		}
		if string(resp.Body) != vec.ResponseBody {
			t.Errorf("%s: raw body was not preserved verbatim", vec.ID)
		}
	}
}
