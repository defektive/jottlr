package jwt

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// makeJWT builds a compact JWS from a header and claims map. The signature is a
// fixed non-empty base64url token; jottlr never verifies it. Header maps are
// JSON-encoded with sorted keys, so any header containing "alg" begins with
// `{"alg"` and therefore base64url-encodes to the "eyJ" anchor the finder uses.
func makeJWT(header, claims map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	return enc.EncodeToString(h) + "." + enc.EncodeToString(c) + ".c2ln"
}

func defaultHeader() map[string]any { return map[string]any{"alg": "HS256", "typ": "JWT"} }

func TestParseRoundTrip(t *testing.T) {
	raw := makeJWT(defaultHeader(), map[string]any{
		"iss": "https://issuer.example",
		"sub": "user-42",
		"exp": 4102444800,
	})
	tok, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tok.Raw != raw {
		t.Errorf("Raw = %q, want %q", tok.Raw, raw)
	}
	if tok.Alg() != "HS256" {
		t.Errorf("Alg = %q, want HS256", tok.Alg())
	}
	if tok.Typ() != "JWT" {
		t.Errorf("Typ = %q, want JWT", tok.Typ())
	}
	if iss, ok := tok.Issuer(); !ok || iss != "https://issuer.example" {
		t.Errorf("Issuer = %q,%v", iss, ok)
	}
	if sub, ok := tok.Subject(); !ok || sub != "user-42" {
		t.Errorf("Subject = %q,%v", sub, ok)
	}
}

func TestParseRejectsNonJWT(t *testing.T) {
	cases := map[string]string{
		"two segments":     "eyJhbGci.eyJpc3Mi",
		"not base64url":    "eyJhbGci.@@@@.sig",
		"header not json":  base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".e30.sig",
		"payload is array": makeArrayPayload(),
		"empty":            "",
		"random base64url": "eyJabc.def.ghi", // decodes but not to a JSON object
	}
	for name, raw := range cases {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: expected error for %q", name, raw)
		}
	}
}

func makeArrayPayload() string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(defaultHeader())
	return enc.EncodeToString(h) + "." + enc.EncodeToString([]byte("[1,2,3]")) + ".sig"
}

func TestParseTolaratesPadding(t *testing.T) {
	// Re-add '=' padding to each segment; Parse should still decode it.
	enc := base64.URLEncoding // with padding
	h, _ := json.Marshal(defaultHeader())
	c, _ := json.Marshal(map[string]any{"sub": "x"})
	raw := enc.EncodeToString(h) + "." + enc.EncodeToString(c) + ".sig"
	if _, err := Parse(raw); err != nil {
		t.Errorf("padded token should parse: %v", err)
	}
}

func TestNumericDateAndExpiry(t *testing.T) {
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour).Unix()
	future := now.Add(time.Hour).Unix()

	expiredTok, _ := Parse(makeJWT(defaultHeader(), map[string]any{"exp": past}))
	if !expiredTok.IsExpired(now) {
		t.Error("token with past exp should be expired")
	}
	if expiredTok.TimeValid(now) {
		t.Error("expired token should not be time-valid")
	}

	liveTok, _ := Parse(makeJWT(defaultHeader(), map[string]any{"exp": future, "nbf": past}))
	if liveTok.IsExpired(now) {
		t.Error("token with future exp should not be expired")
	}
	if !liveTok.TimeValid(now) {
		t.Error("token within [nbf,exp) should be time-valid")
	}

	notYet, _ := Parse(makeJWT(defaultHeader(), map[string]any{"nbf": future}))
	if !notYet.NotYetValid(now) {
		t.Error("token with future nbf should be not-yet-valid")
	}

	// A token with no exp is never expired.
	noExp, _ := Parse(makeJWT(defaultHeader(), map[string]any{"sub": "x"}))
	if noExp.IsExpired(now) {
		t.Error("token without exp should not be expired")
	}
	if _, ok := noExp.ExpiresAt(); ok {
		t.Error("ExpiresAt should report absent")
	}
}

func TestAudienceStringAndArray(t *testing.T) {
	single, _ := Parse(makeJWT(defaultHeader(), map[string]any{"aud": "api"}))
	if got := single.Audience(); len(got) != 1 || got[0] != "api" {
		t.Errorf("single aud = %v", got)
	}
	multi, _ := Parse(makeJWT(defaultHeader(), map[string]any{"aud": []any{"api", "web"}}))
	if got := multi.Audience(); len(got) != 2 || got[0] != "api" || got[1] != "web" {
		t.Errorf("multi aud = %v", got)
	}
	none, _ := Parse(makeJWT(defaultHeader(), map[string]any{"sub": "x"}))
	if got := none.Audience(); got != nil {
		t.Errorf("absent aud = %v, want nil", got)
	}
}

func TestNoneAlgEmptySignature(t *testing.T) {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]any{"alg": "none"})
	c, _ := json.Marshal(map[string]any{"sub": "x"})
	raw := enc.EncodeToString(h) + "." + enc.EncodeToString(c) + "." // empty signature
	tok, err := Parse(raw)
	if err != nil {
		t.Fatalf("alg=none token should parse: %v", err)
	}
	if tok.Alg() != "none" || tok.Signature != "" {
		t.Errorf("alg=%q sig=%q", tok.Alg(), tok.Signature)
	}
}
