package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/defektive/base-grep/scan"
	"github.com/defektive/jottlr/jwt"
)

func TestRenderLineHighlight(t *testing.T) {
	tok := &jwt.Token{Raw: "eyJ.a.b"}
	loc := jwt.Located{Token: tok, Line: "Bearer eyJ.a.b end", Col: 7}

	plain := renderLine(loc, false, 0)
	if plain != "Bearer eyJ.a.b end" {
		t.Errorf("plain = %q", plain)
	}
	if strings.Contains(plain, "\x1b[") {
		t.Error("plain render should have no ANSI escapes")
	}

	colored := renderLine(loc, true, 0)
	if colored != "Bearer "+scan.HiOn+"eyJ.a.b"+scan.HiOff+" end" {
		t.Errorf("colored = %q", colored)
	}
}

func TestRenderLineMaxColumns(t *testing.T) {
	tok := &jwt.Token{Raw: "eyJ.a.b"}
	long := strings.Repeat("A", 80) + "eyJ.a.b" + strings.Repeat("B", 80)
	loc := jwt.Located{Token: tok, Line: long, Col: 80}

	out := renderLine(loc, false, 20)
	if !strings.Contains(out, "eyJ.a.b") {
		t.Errorf("truncation dropped the token: %q", out)
	}
	if !strings.HasPrefix(out, "…") || !strings.HasSuffix(out, "…") {
		t.Errorf("expected ellipses both sides: %q", out)
	}
}

func TestFormatValue(t *testing.T) {
	if got := formatValue("acme"); got != "acme" {
		t.Errorf("string = %q, want bare acme", got)
	}
	if got := formatValue(json.Number("42")); got != "42" {
		t.Errorf("number = %q, want 42", got)
	}
	if got := formatValue([]any{"a", "b"}); got != `["a","b"]` {
		t.Errorf("array = %q", got)
	}
	if got := formatValue(true); got != "true" {
		t.Errorf("bool = %q", got)
	}
}

func TestParseTime(t *testing.T) {
	got, err := parseTime("2026-06-26T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("RFC3339 parse = %v", got)
	}
	got, err = parseTime("1700000000")
	if err != nil {
		t.Fatal(err)
	}
	if got.Unix() != 1700000000 {
		t.Errorf("epoch parse = %v", got.Unix())
	}
	if _, err := parseTime("not-a-time"); err == nil {
		t.Error("expected error for garbage time")
	}
}

func TestBuildFilter(t *testing.T) {
	f, err := buildFilter("HS256", `acme`, "", "", true, false, false,
		stringList{"exp"}, stringList{"admin=true"}, "1700000000")
	if err != nil {
		t.Fatalf("buildFilter: %v", err)
	}
	if f.Alg != "HS256" || !f.NotExpired || f.Issuer == nil {
		t.Errorf("filter fields not set: %+v", f)
	}
	if f.ClaimEq["admin"] != "true" {
		t.Errorf("ClaimEq = %v", f.ClaimEq)
	}
	if f.Now.Unix() != 1700000000 {
		t.Errorf("Now = %v", f.Now.Unix())
	}

	if _, err := buildFilter("", "(", "", "", false, false, false, nil, nil, ""); err == nil {
		t.Error("expected error for bad regexp")
	}
	if _, err := buildFilter("", "", "", "", false, false, false, nil, stringList{"noequals"}, ""); err == nil {
		t.Error("expected error for malformed -claim")
	}
}
