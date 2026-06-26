package jwt

import (
	"reflect"
	"regexp"
	"testing"
	"time"
)

var refNow = time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)

func mustParse(t *testing.T, raw string) *Token {
	t.Helper()
	tok, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return tok
}

func TestFilterZeroMatchesAll(t *testing.T) {
	tok := mustParse(t, makeJWT(defaultHeader(), map[string]any{"sub": "x"}))
	if !(Filter{Now: refNow}).Match(tok) {
		t.Error("zero filter should match any token")
	}
}

func TestFilterIssuerAndAlg(t *testing.T) {
	tok := mustParse(t, makeJWT(defaultHeader(), map[string]any{"iss": "https://accounts.example.com"}))

	if !(Filter{Now: refNow, Issuer: regexp.MustCompile(`accounts\.example`)}).Match(tok) {
		t.Error("issuer pattern should match")
	}
	if (Filter{Now: refNow, Issuer: regexp.MustCompile(`evil\.com`)}).Match(tok) {
		t.Error("non-matching issuer should fail")
	}
	if !(Filter{Now: refNow, Alg: "hs256"}).Match(tok) {
		t.Error("alg match should be case-insensitive")
	}
	if (Filter{Now: refNow, Alg: "RS256"}).Match(tok) {
		t.Error("wrong alg should fail")
	}
}

func TestFilterExpiry(t *testing.T) {
	past := refNow.Add(-time.Hour).Unix()
	future := refNow.Add(time.Hour).Unix()
	expired := mustParse(t, makeJWT(defaultHeader(), map[string]any{"exp": past}))
	live := mustParse(t, makeJWT(defaultHeader(), map[string]any{"exp": future}))
	noExp := mustParse(t, makeJWT(defaultHeader(), map[string]any{"sub": "x"}))

	if !(Filter{Now: refNow, NotExpired: true}).Match(live) {
		t.Error("live token should pass not-expired")
	}
	if (Filter{Now: refNow, NotExpired: true}).Match(expired) {
		t.Error("expired token should fail not-expired")
	}
	if (Filter{Now: refNow, NotExpired: true}).Match(noExp) {
		t.Error("token without exp should fail not-expired (no exp to prove freshness)")
	}
	if !(Filter{Now: refNow, Expired: true}).Match(expired) {
		t.Error("expired token should pass -expired")
	}
	if (Filter{Now: refNow, Expired: true}).Match(live) {
		t.Error("live token should fail -expired")
	}
}

func TestFilterTimeValid(t *testing.T) {
	past := refNow.Add(-time.Hour).Unix()
	future := refNow.Add(time.Hour).Unix()
	live := mustParse(t, makeJWT(defaultHeader(), map[string]any{"nbf": past, "exp": future}))
	notYet := mustParse(t, makeJWT(defaultHeader(), map[string]any{"nbf": future, "exp": future}))

	if !(Filter{Now: refNow, TimeValid: true}).Match(live) {
		t.Error("token in window should be valid")
	}
	if (Filter{Now: refNow, TimeValid: true}).Match(notYet) {
		t.Error("not-yet-valid token should fail -valid")
	}
}

func TestFilterClaims(t *testing.T) {
	tok := mustParse(t, makeJWT(defaultHeader(), map[string]any{
		"sub":   "x",
		"admin": true,
		"ver":   2,
	}))

	if !(Filter{Now: refNow, HasClaims: []string{"admin", "sub"}}).Match(tok) {
		t.Error("present claims should pass -has")
	}
	if (Filter{Now: refNow, HasClaims: []string{"missing"}}).Match(tok) {
		t.Error("absent claim should fail -has")
	}
	if !(Filter{Now: refNow, ClaimEq: map[string]string{"admin": "true"}}).Match(tok) {
		t.Error("bool claim equality should match")
	}
	if !(Filter{Now: refNow, ClaimEq: map[string]string{"ver": "2"}}).Match(tok) {
		t.Error("numeric claim equality should match")
	}
	if (Filter{Now: refNow, ClaimEq: map[string]string{"ver": "3"}}).Match(tok) {
		t.Error("wrong numeric value should fail")
	}
}

func TestFilterAudience(t *testing.T) {
	tok := mustParse(t, makeJWT(defaultHeader(), map[string]any{"aud": []any{"api", "web"}}))
	if !(Filter{Now: refNow, Audience: regexp.MustCompile(`^web$`)}).Match(tok) {
		t.Error("matching aud entry should pass")
	}
	if (Filter{Now: refNow, Audience: regexp.MustCompile(`mobile`)}).Match(tok) {
		t.Error("non-matching aud should fail")
	}
}

func TestExtract(t *testing.T) {
	tok := mustParse(t, makeJWT(defaultHeader(), map[string]any{
		"iss": "acme",
		"realm_access": map[string]any{
			"roles": []any{"admin", "user"},
		},
	}))

	if v, ok := Extract(tok, "iss"); !ok || v != "acme" {
		t.Errorf("Extract iss = %v,%v", v, ok)
	}
	if v, ok := Extract(tok, "header.alg"); !ok || v != "HS256" {
		t.Errorf("Extract header.alg = %v,%v", v, ok)
	}
	if v, ok := Extract(tok, "payload.iss"); !ok || v != "acme" {
		t.Errorf("Extract payload.iss = %v,%v", v, ok)
	}
	if v, ok := Extract(tok, "realm_access.roles"); !ok || !reflect.DeepEqual(v, []any{"admin", "user"}) {
		t.Errorf("Extract nested roles = %v,%v", v, ok)
	}
	if _, ok := Extract(tok, "does.not.exist"); ok {
		t.Error("missing path should report not-found")
	}
}
