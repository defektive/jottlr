package jwt

import (
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

func TestFindStreamMatchesFind(t *testing.T) {
	// FindStream over a reader must report the same tokens and the same global
	// offsets as Find over the whole buffer.
	a := makeJWT(defaultHeader(), map[string]any{"sub": "a"})
	b := makeJWT(defaultHeader(), map[string]any{"sub": "b"})
	c := makeJWT(defaultHeader(), map[string]any{"sub": "c"})
	blob := "log line one " + a + "\nnoise\nBearer " + b + " trailer\n" + c

	want := Find("<stream>", []byte(blob))

	var got []Located
	if err := FindStream("<stream>", strings.NewReader(blob), func(l Located) {
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
		_ = FindStream("x", r, func(l Located) {
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
