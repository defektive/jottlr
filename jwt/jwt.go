// Package jwt parses, decodes and inspects JSON Web Tokens (the JWS compact
// serialization: header.payload.signature). It is deliberately a *reader*: it
// never verifies signatures — jottlr is "jq for JWTs", a tool for finding and
// filtering tokens by their contents, not a validating auth library. Treat any
// claim it surfaces as untrusted until verified elsewhere.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ErrNotJWT is returned when a string is not a well-formed compact JWS: it must
// have three dot-separated segments whose header and payload base64url-decode to
// JSON objects.
var ErrNotJWT = errors.New("not a JWT")

// Token is a decoded (but unverified) JWT.
type Token struct {
	// Raw is the original token text exactly as it appeared in the input.
	Raw string `json:"raw"`
	// Header is the decoded JOSE header (e.g. alg, typ, kid).
	Header map[string]any `json:"header"`
	// Claims is the decoded payload (registered + private claims).
	Claims map[string]any `json:"claims"`
	// Signature is the third segment, left as the raw base64url text. jottlr
	// does not verify it.
	Signature string `json:"signature"`
}

// Parse decodes a compact JWS string into a Token. It validates structure and
// JSON but not the signature. A non-JWT input yields ErrNotJWT.
func Parse(raw string) (*Token, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrNotJWT
	}
	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return nil, ErrNotJWT
	}
	payloadJSON, err := decodeSegment(parts[1])
	if err != nil {
		return nil, ErrNotJWT
	}

	header, err := decodeObject(headerJSON)
	if err != nil {
		return nil, ErrNotJWT
	}
	claims, err := decodeObject(payloadJSON)
	if err != nil {
		return nil, ErrNotJWT
	}

	return &Token{
		Raw:       raw,
		Header:    header,
		Claims:    claims,
		Signature: parts[2],
	}, nil
}

// decodeSegment base64url-decodes a JWT segment. Per RFC 7515 segments carry no
// padding, but we tolerate any stray '=' so pasted tokens still parse.
func decodeSegment(seg string) ([]byte, error) {
	seg = strings.TrimRight(seg, "=")
	return base64.RawURLEncoding.DecodeString(seg)
}

// decodeObject unmarshals data as a JSON object, keeping numbers as json.Number
// so large NumericDate values survive without float rounding. A JSON value that
// is not an object (array, string, ...) is rejected — a real JWT header and
// payload are always objects, and this is what filters out base64url noise that
// merely looks token-shaped.
func decodeObject(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, ErrNotJWT
	}
	return obj, nil
}

// Alg returns the "alg" header value (e.g. "HS256", "none"), or "" if absent.
func (t *Token) Alg() string {
	s, _ := t.Header["alg"].(string)
	return s
}

// Typ returns the "typ" header value, or "" if absent.
func (t *Token) Typ() string {
	s, _ := t.Header["typ"].(string)
	return s
}

// Issuer returns the "iss" claim and whether it was present as a string.
func (t *Token) Issuer() (string, bool) {
	s, ok := t.Claims["iss"].(string)
	return s, ok
}

// Subject returns the "sub" claim and whether it was present as a string.
func (t *Token) Subject() (string, bool) {
	s, ok := t.Claims["sub"].(string)
	return s, ok
}

// Audience returns the "aud" claim normalised to a slice. JWT allows aud to be
// either a single string or an array of strings; both are flattened here.
func (t *Token) Audience() []string {
	switch v := t.Claims["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// ExpiresAt returns the "exp" claim as a time and whether it was present.
func (t *Token) ExpiresAt() (time.Time, bool) { return t.numericDate("exp") }

// NotBefore returns the "nbf" claim as a time and whether it was present.
func (t *Token) NotBefore() (time.Time, bool) { return t.numericDate("nbf") }

// IssuedAt returns the "iat" claim as a time and whether it was present.
func (t *Token) IssuedAt() (time.Time, bool) { return t.numericDate("iat") }

// numericDate reads a NumericDate claim (seconds since the Unix epoch, possibly
// fractional) into a time.Time.
func (t *Token) numericDate(key string) (time.Time, bool) {
	v, ok := t.Claims[key]
	if !ok {
		return time.Time{}, false
	}
	var secs float64
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return time.Time{}, false
		}
		secs = f
	case float64:
		secs = n
	default:
		return time.Time{}, false
	}
	whole := int64(secs)
	frac := int64((secs - float64(whole)) * 1e9)
	return time.Unix(whole, frac), true
}

// IsExpired reports whether the token has an "exp" claim at or before now. A
// token with no "exp" is never considered expired.
func (t *Token) IsExpired(now time.Time) bool {
	exp, ok := t.ExpiresAt()
	return ok && !now.Before(exp)
}

// NotYetValid reports whether the token has an "nbf" claim strictly after now. A
// token with no "nbf" is never considered not-yet-valid.
func (t *Token) NotYetValid(now time.Time) bool {
	nbf, ok := t.NotBefore()
	return ok && now.Before(nbf)
}

// TimeValid reports whether now falls within the token's [nbf, exp) window:
// not expired and not before its not-before time. Absent bounds are treated as
// open (a token with neither exp nor nbf is always time-valid).
func (t *Token) TimeValid(now time.Time) bool {
	return !t.IsExpired(now) && !t.NotYetValid(now)
}
