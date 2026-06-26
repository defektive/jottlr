package jwt

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestFindInStream(t *testing.T) {
	tok := makeJWT(defaultHeader(), map[string]any{"iss": "acme", "sub": "u1"})
	blob := "Authorization: Bearer " + tok + "\nsome other line"
	found := Find("<stdin>", []byte(blob))
	if len(found) != 1 {
		t.Fatalf("found %d tokens, want 1", len(found))
	}
	loc := found[0]
	if loc.Token.Raw != tok {
		t.Errorf("Raw = %q, want %q", loc.Token.Raw, tok)
	}
	// Offset and Col must point at the token.
	if got := blob[loc.Offset : loc.Offset+len(tok)]; got != tok {
		t.Errorf("Offset %d points at %q", loc.Offset, got)
	}
	if !strings.HasPrefix(loc.Line, "Authorization: Bearer ") {
		t.Errorf("Line = %q, want the Authorization line", loc.Line)
	}
	if got := loc.Line[loc.Col : loc.Col+len(tok)]; got != tok {
		t.Errorf("Col %d points at %q", loc.Col, got)
	}
}

func TestFindMultiple(t *testing.T) {
	a := makeJWT(defaultHeader(), map[string]any{"sub": "a"})
	b := makeJWT(defaultHeader(), map[string]any{"sub": "b"})
	found := Find("x", []byte(a+" and "+b))
	if len(found) != 2 {
		t.Fatalf("found %d, want 2", len(found))
	}
	if found[0].Token.Raw != a || found[1].Token.Raw != b {
		t.Errorf("tokens out of order: %q then %q", found[0].Token.Raw, found[1].Token.Raw)
	}
	if found[0].Offset >= found[1].Offset {
		t.Error("offsets should be increasing")
	}
}

func TestFindRejectsLookalikes(t *testing.T) {
	// "eyJ"-prefixed three-segment strings that are not real JWTs must be
	// dropped because their segments do not decode to JSON objects.
	noise := "eyJunk.notbase64@@.sig eyJabc.def.ghi eyJ.x.y"
	if found := Find("x", []byte(noise)); len(found) != 0 {
		t.Errorf("found %d false positives: %+v", len(found), found)
	}
}

func TestFindNone(t *testing.T) {
	if found := Find("x", []byte("nothing token-shaped here at all")); found != nil {
		t.Errorf("expected nil, got %+v", found)
	}
}

func TestFindRelaxedIsSupersetOfFind(t *testing.T) {
	// A well-formed JWT must be reported once, identically to strict Find — not
	// split into its header and payload segments.
	tok := makeJWT(defaultHeader(), map[string]any{"iss": "acme", "sub": "u1"})
	blob := "Bearer " + tok + " end"

	relaxed := FindRelaxed("x", []byte(blob))
	if len(relaxed) != 1 {
		t.Fatalf("relaxed found %d, want 1 (the whole JWT)", len(relaxed))
	}
	if relaxed[0].Token.Raw != tok {
		t.Errorf("relaxed token = %q, want the full JWT", relaxed[0].Token.Raw)
	}
	if iss, _ := relaxed[0].Token.Issuer(); iss != "acme" {
		t.Errorf("relaxed JWT lost its claims: iss=%q", iss)
	}
}

func TestFindRelaxedBarePayload(t *testing.T) {
	// A lone base64url JSON object (no JWT envelope) is found only in relaxed mode.
	enc := base64.RawURLEncoding
	payload := enc.EncodeToString([]byte(`{"iss":"acme","sub":"solo"}`))
	blob := "cookie=" + payload + ";"

	if strict := Find("x", []byte(blob)); len(strict) != 0 {
		t.Errorf("strict Find should not match a bare payload, got %d", len(strict))
	}

	relaxed := FindRelaxed("x", []byte(blob))
	if len(relaxed) != 1 {
		t.Fatalf("relaxed found %d, want 1", len(relaxed))
	}
	tok := relaxed[0].Token
	if tok.Raw != payload {
		t.Errorf("Raw = %q, want %q", tok.Raw, payload)
	}
	if tok.Header != nil {
		t.Errorf("bare object should have no header, got %v", tok.Header)
	}
	if iss, ok := tok.Issuer(); !ok || iss != "acme" {
		t.Errorf("bare object claims wrong: iss=%q,%v", iss, ok)
	}
	// Offset must point at the payload within the blob.
	if blob[relaxed[0].Offset:relaxed[0].Offset+len(payload)] != payload {
		t.Errorf("offset %d does not point at the payload", relaxed[0].Offset)
	}
}

func TestFindRelaxedSignatureless(t *testing.T) {
	// A two-segment header.payload (no signature) is not a valid JWT, so relaxed
	// mode decodes each segment; the payload object must surface.
	enc := base64.RawURLEncoding
	h := enc.EncodeToString([]byte(`{"alg":"HS256"}`))
	p := enc.EncodeToString([]byte(`{"sub":"halfbaked"}`))
	blob := h + "." + p

	if strict := Find("x", []byte(blob)); len(strict) != 0 {
		t.Errorf("strict Find should skip a 2-segment token, got %d", len(strict))
	}
	relaxed := FindRelaxed("x", []byte(blob))
	var subs []string
	for _, loc := range relaxed {
		if sub, ok := loc.Token.Subject(); ok {
			subs = append(subs, sub)
		}
	}
	if len(subs) != 1 || subs[0] != "halfbaked" {
		t.Errorf("relaxed subjects = %v, want [halfbaked]", subs)
	}
}

func TestFindRelaxedRejectsNonJSON(t *testing.T) {
	// "eyJ"-prefixed runs that do not base64url-decode to JSON objects are still
	// dropped, even in relaxed mode.
	if found := FindRelaxed("x", []byte("eyJabc eyJ.x.y notatoken")); len(found) != 0 {
		t.Errorf("relaxed found %d false positives: %+v", len(found), found)
	}
}

func TestFindStreamMatchesFind(t *testing.T) {
	// FindStream over a reader must report the same tokens and the same global
	// offsets as Find over the whole buffer.
	a := makeJWT(defaultHeader(), map[string]any{"sub": "a"})
	b := makeJWT(defaultHeader(), map[string]any{"sub": "b"})
	c := makeJWT(defaultHeader(), map[string]any{"sub": "c"})
	blob := "log line one " + a + "\nnoise\nBearer " + b + " trailer\n" + c

	want := Find("<stream>", []byte(blob))

	var got []Located
	if err := FindStream("<stream>", strings.NewReader(blob), Find, func(l Located) {
		got = append(got, l)
	}); err != nil {
		t.Fatalf("FindStream: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("stream found %d tokens, whole-buffer found %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Token.Raw != want[i].Token.Raw {
			t.Errorf("token %d: stream %q, buffer %q", i, got[i].Token.Raw, want[i].Token.Raw)
		}
		if got[i].Offset != want[i].Offset {
			t.Errorf("token %d offset: stream %d, buffer %d", i, got[i].Offset, want[i].Offset)
		}
		// The global offset must point at the token in the original blob.
		if blob[got[i].Offset:got[i].Offset+len(got[i].Token.Raw)] != got[i].Token.Raw {
			t.Errorf("token %d: offset %d does not point at the token", i, got[i].Offset)
		}
	}
}

func TestFindStreamIsIncremental(t *testing.T) {
	// Prove the stream is consumed line by line: a reader that blocks forever
	// after the first newline must still yield the token on the first line. If
	// FindStream buffered the whole input it would block here.
	tok := makeJWT(defaultHeader(), map[string]any{"sub": "first"})
	r := &blockAfterFirstLine{first: tok + "\n"}

	done := make(chan Located, 1)
	go func() {
		_ = FindStream("x", r, Find, func(l Located) {
			select {
			case done <- l:
			default:
			}
		})
	}()

	select {
	case got := <-done:
		if got.Token.Raw != tok {
			t.Errorf("got %q, want %q", got.Token.Raw, tok)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FindStream did not emit the first line's token before reading the rest")
	}
}

// blockAfterFirstLine yields one line, then blocks indefinitely, modelling an
// open pipe that has produced some data but not closed.
type blockAfterFirstLine struct {
	first string
	done  bool
}

func (b *blockAfterFirstLine) Read(p []byte) (int, error) {
	if !b.done {
		n := copy(p, b.first)
		b.done = true
		return n, nil
	}
	select {} // block forever, as an unclosed pipe would
}
