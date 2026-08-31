package plutus

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

const vectorsPath = "../shared/test-vectors.json"

type vectorKey struct {
	Purpose        string `json:"purpose"`
	Algorithm      string `json:"algorithm"`
	ModulusBits    int    `json:"modulusBits"`
	PublicExponent int    `json:"publicExponent"`
	Fingerprint    string `json:"fingerprint"`
	PublicKeyPEM   string `json:"publicKeyPem"`
	PrivateKeyPEM  string `json:"privateKeyPem"`
}

type canonicalQueryVector struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Input       *string `json:"input"`
	Expected    *string `json:"expected"`
	ExpectError bool    `json:"expectError"`
	ErrorReason string  `json:"errorReason"`
}

type bodyHashVector struct {
	ID              string  `json:"id"`
	Description     string  `json:"description"`
	Method          *string `json:"method"`
	Body            *string `json:"body"`
	ForcedEmptyBody bool    `json:"forcedEmptyBody"`
	Expected        string  `json:"expected"`
}

type requestSignatureVector struct {
	ID         string `json:"id"`
	SigningKey string `json:"signingKey"`
	Request    struct {
		Method         string  `json:"method"`
		ExternalPath   string  `json:"externalPath"`
		QueryString    *string `json:"queryString"`
		Timestamp      string  `json:"timestamp"`
		Nonce          string  `json:"nonce"`
		APIVersion     string  `json:"apiVersion"`
		IdempotencyKey *string `json:"idempotencyKey"`
		Body           *string `json:"body"`
	} `json:"request"`
	CanonicalQuery         string            `json:"canonicalQuery"`
	ForcedEmptyBody        bool              `json:"forcedEmptyBody"`
	BodyHash               string            `json:"bodyHash"`
	CanonicalString        string            `json:"canonicalString"`
	CanonicalStringLines   []string          `json:"canonicalStringLines"`
	RequestCanonicalSHA256 string            `json:"requestCanonicalSha256"`
	Signature              string            `json:"signature"`
	Headers                map[string]string `json:"headers"`
}

type responseSignatureVector struct {
	ID                     string            `json:"id"`
	SigningKey             string            `json:"signingKey"`
	RequestVectorID        string            `json:"requestVectorId"`
	RequestCanonicalSHA256 string            `json:"requestCanonicalSha256"`
	APIVersion             string            `json:"apiVersion"`
	ExternalPath           string            `json:"externalPath"`
	OperationID            *string           `json:"operationId"`
	RequestID              *string           `json:"requestId"`
	HTTPStatus             int               `json:"httpStatus"`
	ContentType            string            `json:"contentType"`
	ResponseTimestamp      string            `json:"responseTimestamp"`
	ResponseBody           string            `json:"responseBody"`
	ResponseBodyHash       string            `json:"responseBodyHash"`
	CanonicalString        string            `json:"canonicalString"`
	CanonicalStringLines   []string          `json:"canonicalStringLines"`
	Signature              string            `json:"signature"`
	Headers                map[string]string `json:"headers"`
}

type aadComponents struct {
	RequestID     string `json:"requestId"`
	RouteTemplate string `json:"routeTemplate"`
	Timestamp     string `json:"timestamp"`
	KeyID         string `json:"keyId"`
}

type envelopeVector struct {
	ID                string            `json:"id"`
	Direction         string            `json:"direction"`
	DecryptionKey     string            `json:"decryptionKey"`
	AADComponents     aadComponents     `json:"aadComponents"`
	AADString         string            `json:"aadString"`
	AADBase64         string            `json:"aadBase64"`
	Envelope          Envelope          `json:"envelope"`
	ExpectedPlaintext string            `json:"expectedPlaintext"`
	RequestHeaders    map[string]string `json:"requestHeaders"`
}

type webhookVector struct {
	ID                       string            `json:"id"`
	DecryptionKey            string            `json:"decryptionKey"`
	SignatureVerificationKey string            `json:"signatureVerificationKey"`
	Headers                  map[string]string `json:"headers"`
	Body                     string            `json:"body"`
	BodyDigestBase64         string            `json:"bodyDigestBase64"`
	SignatureCanonicalString string            `json:"signatureCanonicalString"`
	AADComponents            aadComponents     `json:"aadComponents"`
	AADString                string            `json:"aadString"`
	AADBase64                string            `json:"aadBase64"`
	ExpectedPlaintext        string            `json:"expectedPlaintext"`
}

type vectorFile struct {
	Meta struct {
		Protocol string         `json:"protocol"`
		Counts   map[string]int `json:"counts"`
	} `json:"meta"`
	Keys    map[string]vectorKey `json:"keys"`
	Vectors struct {
		CanonicalQuery    []canonicalQueryVector    `json:"canonicalQuery"`
		BodyHash          []bodyHashVector          `json:"bodyHash"`
		RequestSignature  []requestSignatureVector  `json:"requestSignature"`
		ResponseSignature []responseSignatureVector `json:"responseSignature"`
		EncryptedEnvelope []envelopeVector          `json:"encryptedEnvelope"`
		Webhook           []webhookVector           `json:"webhook"`
	} `json:"vectors"`
}

var loadedVectors *vectorFile

func vectors(t *testing.T) *vectorFile {
	t.Helper()
	if loadedVectors != nil {
		return loadedVectors
	}
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", vectorsPath, err)
	}
	var file vectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse %s: %v", vectorsPath, err)
	}
	loadedVectors = &file
	return loadedVectors
}

func privateKey(t *testing.T, name string) *rsa.PrivateKey {
	t.Helper()
	key, ok := vectors(t).Keys[name]
	if !ok {
		t.Fatalf("unknown vector key %q", name)
	}
	parsed, err := ParseRSAPrivateKeyPEM([]byte(key.PrivateKeyPEM))
	if err != nil {
		t.Fatalf("parse %s private key: %v", name, err)
	}
	return parsed
}

func publicKey(t *testing.T, name string) *rsa.PublicKey {
	t.Helper()
	key, ok := vectors(t).Keys[name]
	if !ok {
		t.Fatalf("unknown vector key %q", name)
	}
	parsed, err := ParseRSAPublicKeyPEM([]byte(key.PublicKeyPEM))
	if err != nil {
		t.Fatalf("parse %s public key: %v", name, err)
	}
	return parsed
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func bodyBytes(p *string) []byte {
	if p == nil {
		return nil
	}
	return []byte(*p)
}

func TestVectorFileCounts(t *testing.T) {
	v := vectors(t)
	if v.Meta.Protocol != Protocol {
		t.Fatalf("protocol = %q, want %q", v.Meta.Protocol, Protocol)
	}
	actual := map[string]int{
		"canonicalQuery":    len(v.Vectors.CanonicalQuery),
		"bodyHash":          len(v.Vectors.BodyHash),
		"requestSignature":  len(v.Vectors.RequestSignature),
		"responseSignature": len(v.Vectors.ResponseSignature),
		"encryptedEnvelope": len(v.Vectors.EncryptedEnvelope),
		"webhook":           len(v.Vectors.Webhook),
	}
	for group, want := range v.Meta.Counts {
		if actual[group] != want {
			t.Errorf("group %s: loaded %d vectors, meta says %d", group, actual[group], want)
		}
	}
}

func TestVectorKeys(t *testing.T) {
	for name, key := range vectors(t).Keys {
		pub := publicKey(t, name)
		priv := privateKey(t, name)
		if pub.N.Cmp(priv.N) != 0 {
			t.Errorf("%s: public/private key pair mismatch", name)
		}
		if pub.N.BitLen() != key.ModulusBits {
			t.Errorf("%s: modulus %d bits, want %d", name, pub.N.BitLen(), key.ModulusBits)
		}
		if pub.E != key.PublicExponent {
			t.Errorf("%s: exponent %d, want %d", name, pub.E, key.PublicExponent)
		}
		fingerprint, err := KeyFingerprint(pub)
		if err != nil {
			t.Fatalf("%s: fingerprint: %v", name, err)
		}
		if fingerprint != key.Fingerprint {
			t.Errorf("%s: fingerprint = %s, want %s", name, fingerprint, key.Fingerprint)
		}
	}
}

func TestCanonicalQueryVectors(t *testing.T) {
	for _, vec := range vectors(t).Vectors.CanonicalQuery {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			got, err := CanonicalizeQuery(str(vec.Input))
			if vec.ExpectError {
				if err == nil {
					t.Fatalf("expected rejection (%s), got %q", vec.ErrorReason, got)
				}
				var queryErr *QueryError
				if !errors.As(err, &queryErr) {
					t.Fatalf("error %v is not a *QueryError", err)
				}
				if !errors.Is(err, ErrInvalidQuery) {
					t.Fatalf("error %v does not unwrap to ErrInvalidQuery", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != str(vec.Expected) {
				t.Fatalf("canonical query = %q, want %q", got, str(vec.Expected))
			}
			// 规范化必须幂等。
			again, err := CanonicalizeQuery(got)
			if err != nil {
				t.Fatalf("re-canonicalize %q: %v", got, err)
			}
			if again != got {
				t.Fatalf("canonicalization is not idempotent: %q -> %q", got, again)
			}
		})
	}
}

func TestBodyHashVectors(t *testing.T) {
	for _, vec := range vectors(t).Vectors.BodyHash {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			method := str(vec.Method)
			if ForcesEmptyBodyDigest(method) != vec.ForcedEmptyBody {
				t.Fatalf("ForcesEmptyBodyDigest(%q) = %v, want %v", method, !vec.ForcedEmptyBody, vec.ForcedEmptyBody)
			}
			got := BodyDigestHex(method, bodyBytes(vec.Body))
			if got != vec.Expected {
				t.Fatalf("body digest = %s, want %s", got, vec.Expected)
			}
		})
	}
}

func TestEmptyBodyDigestConstant(t *testing.T) {
	if got := SHA256Hex(nil); got != EmptyBodySHA256Hex {
		t.Fatalf("empty digest = %s, want %s", got, EmptyBodySHA256Hex)
	}
}
