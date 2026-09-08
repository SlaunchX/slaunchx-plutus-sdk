package plutus

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ProtocolProfile selects a wire contract explicitly. Zero value preserves Alpha.
type ProtocolProfile string

const (
	RequestBoundV1 ProtocolProfile = "request-bound-v1"
	ProductV1      ProtocolProfile = "product-v1"
)

func (p ProtocolProfile) validate() error {
	if p != "" && p != RequestBoundV1 && p != ProductV1 {
		return fmt.Errorf("%w: unknown protocol profile", ErrInvalidConfig)
	}
	return nil
}

// CanonicalizeQueryForProfile uses the selected protocol without fallback.
func CanonicalizeQueryForProfile(raw string, profile ProtocolProfile) (string, error) {
	if err := profile.validate(); err != nil {
		return "", err
	}
	if profile != ProductV1 {
		return CanonicalizeQuery(raw)
	}
	if strings.TrimFunc(raw, javaWhitespace) == "" {
		return "", nil
	}
	pairs := make([][2]string, 0)
	for _, part := range strings.Split(raw, "&") {
		key, value, _ := strings.Cut(part, "=")
		k, err := url.QueryUnescape(key)
		if err != nil || !utf8.ValidString(k) {
			return "", fmt.Errorf("%w: invalid product query key", ErrInvalidConfig)
		}
		v, err := url.QueryUnescape(value)
		if err != nil || !utf8.ValidString(v) {
			return "", fmt.Errorf("%w: invalid product query value", ErrInvalidConfig)
		}
		pairs = append(pairs, [2]string{k, v})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return utf16Less(pairs[i][0], pairs[j][0])
		}
		return utf16Less(pairs[i][1], pairs[j][1])
	})
	out := make([]string, len(pairs))
	encode := func(value string) string {
		return strings.NewReplacer("+", "%20", "%2A", "*", "~", "%7E").Replace(url.QueryEscape(value))
	}
	for i, pair := range pairs {
		out[i] = encode(pair[0]) + "=" + encode(pair[1])
	}
	return strings.Join(out, "&"), nil
}

func javaWhitespace(r rune) bool {
	return r >= 9 && r <= 13 || r >= 0x1c && r <= 0x20 || r == 0x1680 || r >= 0x2000 && r <= 0x2006 || r >= 0x2008 && r <= 0x200a || r == 0x2028 || r == 0x2029 || r == 0x205f || r == 0x3000
}
func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}
func productRequestID(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("%w: request ID must not contain newlines", ErrInvalidConfig)
	}
	if id := strings.TrimSpace(value); id != "" {
		return id, nil
	}
	nonce, err := NewNonce()
	if err != nil {
		return "", err
	}
	return "req_" + nonce, nil
}
