package jwt

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Filter is a conjunction of predicates over a Token: a token matches only if it
// satisfies every field that is set. The zero Filter matches every token, so a
// bare `jottlr` finds all JWTs. Time-based predicates are evaluated against Now
// (defaulting to the wall clock when zero).
type Filter struct {
	// Now is the reference time for exp/nbf predicates; zero means time.Now().
	Now time.Time

	// Alg, when non-empty, requires the header "alg" to equal it (case-insensitive).
	Alg string
	// Issuer/Subject, when set, require the matching claim to match the regexp.
	Issuer  *regexp.Regexp
	Subject *regexp.Regexp
	// Audience, when set, requires at least one "aud" entry to match the regexp.
	Audience *regexp.Regexp

	// NotExpired requires an "exp" claim that is strictly in the future.
	NotExpired bool
	// Expired requires an "exp" claim at or before Now.
	Expired bool
	// TimeValid requires Now to fall within [nbf, exp).
	TimeValid bool

	// HasClaims requires each named claim key to be present (any value).
	HasClaims []string
	// ClaimEq requires each named claim to equal the given value (compared as
	// text; numbers and booleans are stringified).
	ClaimEq map[string]string
}

// now resolves the reference time, defaulting to the wall clock.
func (f Filter) now() time.Time {
	if f.Now.IsZero() {
		return time.Now()
	}
	return f.Now
}

// Match reports whether t satisfies every set predicate.
func (f Filter) Match(t *Token) bool {
	now := f.now()

	if f.Alg != "" && !strings.EqualFold(f.Alg, t.Alg()) {
		return false
	}
	if f.Issuer != nil {
		iss, _ := t.Issuer()
		if !f.Issuer.MatchString(iss) {
			return false
		}
	}
	if f.Subject != nil {
		sub, _ := t.Subject()
		if !f.Subject.MatchString(sub) {
			return false
		}
	}
	if f.Audience != nil && !matchAny(f.Audience, t.Audience()) {
		return false
	}

	if f.NotExpired {
		exp, ok := t.ExpiresAt()
		if !ok || !now.Before(exp) {
			return false
		}
	}
	if f.Expired && !t.IsExpired(now) {
		return false
	}
	if f.TimeValid && !t.TimeValid(now) {
		return false
	}

	for _, k := range f.HasClaims {
		if _, ok := t.Claims[k]; !ok {
			return false
		}
	}
	for k, want := range f.ClaimEq {
		got, ok := t.Claims[k]
		if !ok || !valueEquals(got, want) {
			return false
		}
	}
	return true
}

// matchAny reports whether re matches any string in vals.
func matchAny(re *regexp.Regexp, vals []string) bool {
	for _, v := range vals {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// valueEquals compares a decoded claim value against the textual want. Strings
// compare directly; numbers and booleans are stringified so `-claim admin=true`
// or `-claim ver=2` work as a user would expect.
func valueEquals(got any, want string) bool {
	switch v := got.(type) {
	case string:
		return v == want
	case json.Number:
		return v.String() == want
	case bool:
		return fmt.Sprintf("%t", v) == want
	default:
		return fmt.Sprintf("%v", v) == want
	}
}

// Extract resolves a dotted path against a token, jq-style, returning the value
// and whether it was found. The first segment may be "header", "payload" or
// "claims" to choose a section; otherwise the path is resolved against the
// claims (the common case, e.g. "iss" or "realm_access.roles"). Remaining
// segments descend through nested JSON objects.
func Extract(t *Token, path string) (any, bool) {
	segs := strings.Split(path, ".")
	var cur any
	switch segs[0] {
	case "header":
		cur, segs = t.Header, segs[1:]
	case "payload", "claims":
		cur, segs = t.Claims, segs[1:]
	default:
		cur = t.Claims
	}
	for _, s := range segs {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[s]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
