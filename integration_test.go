package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// binPath is the compiled jottlr binary, built once for the whole suite.
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "jottlr-it")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "jottlr")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("build failed: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func mkJWT(header, claims map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	return enc.EncodeToString(h) + "." + enc.EncodeToString(c) + ".c2ln"
}

func hdr() map[string]any { return map[string]any{"alg": "HS256", "typ": "JWT"} }

// jottlr runs the binary with stdin and returns stdout, stderr and the exit code.
func jottlr(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errOut.String(), code
}

func TestStdinRawMatch(t *testing.T) {
	tok := mkJWT(hdr(), map[string]any{"iss": "acme", "sub": "u1"})
	out, _, code := jottlr(t, "Bearer "+tok+"\n")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, tok) {
		t.Errorf("output missing token: %q", out)
	}
	if !strings.HasPrefix(out, "<stdin>:") {
		t.Errorf("output missing grep-style prefix: %q", out)
	}
}

func TestStdinNoMatchExit1(t *testing.T) {
	out, _, code := jottlr(t, "no tokens here\n")
	if code != 1 {
		t.Errorf("exit = %d, want 1 for no matches", code)
	}
	if out != "" {
		t.Errorf("expected no output, got %q", out)
	}
}

func TestExpiryFiltering(t *testing.T) {
	live := mkJWT(hdr(), map[string]any{"sub": "live", "exp": 4102444800})   // year 2100
	expired := mkJWT(hdr(), map[string]any{"sub": "old", "exp": 1000000000}) // 2001
	stdin := live + "\n" + expired + "\n"

	// -not-expired keeps only the live token.
	out, _, code := jottlr(t, stdin, "-not-expired", "-get", "sub")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	got := strings.Fields(out)
	if len(got) != 1 || got[0] != "live" {
		t.Errorf("not-expired -> %v, want [live]", got)
	}

	// -expired keeps only the old token.
	out, _, _ = jottlr(t, stdin, "-expired", "-get", "sub")
	if strings.TrimSpace(out) != "old" {
		t.Errorf("expired -> %q, want old", out)
	}
}

func TestIssuerAndClaimFilter(t *testing.T) {
	good := mkJWT(hdr(), map[string]any{"iss": "https://accounts.example.com", "admin": true, "sub": "a"})
	bad := mkJWT(hdr(), map[string]any{"iss": "https://evil.test", "admin": false, "sub": "b"})
	stdin := good + "\n" + bad + "\n"

	out, _, code := jottlr(t, stdin, "-iss", `accounts\.example`, "-claim", "admin=true", "-get", "sub")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.TrimSpace(out) != "a" {
		t.Errorf("filtered -get sub = %q, want a", out)
	}
}

func TestDecodeOutput(t *testing.T) {
	tok := mkJWT(hdr(), map[string]any{"iss": "acme", "sub": "u1"})
	out, _, code := jottlr(t, tok+"\n", "-decode")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	var v decodeView
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("decode output not valid JSON: %v\n%s", err, out)
	}
	if v.Header["alg"] != "HS256" || v.Claims["iss"] != "acme" {
		t.Errorf("decoded values wrong: %+v", v)
	}
	// HTML-escaping is disabled, so the source label appears as the literal
	// "<stdin>"; if it had been escaped it would read as a <... sequence
	// and this substring would be absent.
	if !strings.Contains(out, "<stdin>") {
		t.Errorf("decode output should label the source literally as <stdin>: %q", out)
	}
}

func TestJSONOutput(t *testing.T) {
	tok := mkJWT(hdr(), map[string]any{"sub": "u1"})
	out, _, _ := jottlr(t, tok+"\n", "-json")
	var arr []jsonToken
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		t.Fatalf("-json output invalid: %v\n%s", err, out)
	}
	if len(arr) != 1 || arr[0].Raw != tok {
		t.Errorf("json array = %+v", arr)
	}
}

func TestDirectorySearchRecursive(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "nested")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	topTok := mkJWT(hdr(), map[string]any{"sub": "top"})
	deepTok := mkJWT(hdr(), map[string]any{"sub": "deep"})
	if err := os.WriteFile(filepath.Join(dir, "top.txt"), []byte("x "+topTok), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "deep.txt"), []byte(deepTok), 0o644); err != nil {
		t.Fatal(err)
	}

	// Non-recursive: only the top-level file is scanned.
	out, _, code := jottlr(t, "", "-get", "sub", dir)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if got := strings.Fields(out); len(got) != 1 || got[0] != "top" {
		t.Errorf("flat dir scan = %v, want [top]", got)
	}

	// Recursive: both files are scanned, output sorted by path.
	out, _, _ = jottlr(t, "", "-r", "-get", "sub", dir)
	got := strings.Fields(out)
	if len(got) != 2 {
		t.Fatalf("recursive scan = %v, want 2 results", got)
	}
	// Results are ordered by full path: dir/nested/deep.txt sorts before
	// dir/top.txt ('n' < 't').
	if got[0] != "deep" || got[1] != "top" {
		t.Errorf("recursive order = %v, want [deep top]", got)
	}
}

func TestFileGrepOutput(t *testing.T) {
	dir := t.TempDir()
	tok := mkJWT(hdr(), map[string]any{"sub": "u1"})
	f := filepath.Join(dir, "creds.log")
	if err := os.WriteFile(f, []byte("token="+tok+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, code := jottlr(t, "", f)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.HasPrefix(out, f+":") {
		t.Errorf("expected path-prefixed grep output, got %q", out)
	}
	if !strings.Contains(out, tok) {
		t.Errorf("output missing token: %q", out)
	}
}

func TestStreamManyLines(t *testing.T) {
	// A large, multi-line stream with tokens scattered among noise lines must be
	// fully scanned line by line, preserving encounter order.
	var b strings.Builder
	var wantSubs []string
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "noise line %d with no token\n", i)
		if i%50 == 0 {
			sub := fmt.Sprintf("user-%d", i)
			wantSubs = append(wantSubs, sub)
			fmt.Fprintf(&b, "Authorization: Bearer %s\n", mkJWT(hdr(), map[string]any{"sub": sub}))
		}
	}
	out, _, code := jottlr(t, b.String(), "-get", "sub")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	got := strings.Fields(out)
	if len(got) != len(wantSubs) {
		t.Fatalf("got %d tokens, want %d", len(got), len(wantSubs))
	}
	for i := range wantSubs {
		if got[i] != wantSubs[i] {
			t.Errorf("token %d = %q, want %q (order not preserved)", i, got[i], wantSubs[i])
		}
	}
}

func TestOnlyMatching(t *testing.T) {
	a := mkJWT(hdr(), map[string]any{"sub": "a"})
	b := mkJWT(hdr(), map[string]any{"sub": "b"})
	stdin := "Authorization: Bearer " + a + " trailing junk\nnoise\nx=" + b + "\n"

	out, _, code := jottlr(t, stdin, "-o")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	// Output must be exactly the two bare tokens, one per line — no surrounding
	// text, no source:offset prefix.
	want := a + "\n" + b + "\n"
	if out != want {
		t.Errorf("-o output = %q, want %q", out, want)
	}
}

func TestStreamEmptyJSONArray(t *testing.T) {
	// -json with no matches must still emit a valid empty array.
	out, _, code := jottlr(t, "no tokens here\n", "-json")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	var arr []jsonToken
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		t.Fatalf("empty -json not valid JSON: %v (%q)", err, out)
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array, got %d", len(arr))
	}
}

func TestInvalidFlagExit2(t *testing.T) {
	_, _, code := jottlr(t, "", "-iss", "(")
	if code != 2 {
		t.Errorf("exit = %d, want 2 for bad regexp", code)
	}
}
