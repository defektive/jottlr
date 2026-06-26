package jwt

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/defektive/base-grep/scan"
)

// candidate matches JWT-shaped runs: three dot-separated base64url segments
// whose first segment begins with "eyJ". A JOSE header is a JSON object, so it
// starts with '{' and a key — '{"' base64url-encodes to the literal prefix
// "eyJ", which makes a cheap, highly selective anchor. The signature segment may
// be empty (alg=none tokens are header.payload.), hence the trailing '*'.
var candidate = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

// relaxedCandidate matches one or more base64url segments beginning with the
// "eyJ" JSON-object anchor, without requiring the three segments of a JWS. It
// therefore also catches a bare base64url JSON object — a lone payload, a
// signature-less token, a two-segment near-JWT — anything that decodes to JSON.
var relaxedCandidate = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*`)

// Located is a JWT (or, in relaxed mode, a base64url JSON object) found at a
// position in some input, with the surrounding line captured for grep-like
// output.
type Located struct {
	// Token is the decoded JWT (or header-less object in relaxed mode).
	Token *Token
	// Source labels where it was found (a file path, or e.g. "<stdin>").
	Source string
	// Offset is the byte offset of the token within the source.
	Offset int
	// Line is the full line containing the token (no trailing newline); Col is
	// the token's byte offset within Line.
	Line string
	Col  int
}

// Finder locates tokens within a buffer. Find and FindRelaxed both satisfy it,
// letting callers (e.g. FindStream) select a mode without branching.
type Finder func(source string, data []byte) []Located

// locate builds a Located for tok at byte offset start, capturing the line
// around it for grep-like rendering.
func locate(source string, data []byte, start int, tok *Token) Located {
	ls, le := scan.LineBounds(data, start)
	return Located{
		Token:  tok,
		Source: source,
		Offset: start,
		Line:   string(data[ls:le]),
		Col:    start - ls,
	}
}

// Find scans data for JWT-shaped candidates and returns those that actually
// decode to valid tokens, in order of appearance. The regexp anchor cheaply
// narrows the search; Parse then rejects anything whose header/payload are not
// real base64url JSON objects, eliminating false positives. Overlapping
// candidates are not pursued — JWT matches do not nest.
func Find(source string, data []byte) []Located {
	var found []Located
	for _, loc := range candidate.FindAllIndex(data, -1) {
		start, end := loc[0], loc[1]
		tok, err := Parse(string(data[start:end]))
		if err != nil {
			continue
		}
		found = append(found, locate(source, data, start, tok))
	}
	return found
}

// FindRelaxed scans data for base64url-encoded JSON objects, not just
// well-formed JWTs. It is a strict superset of Find: a run that parses as a
// three-segment JWT is reported once as that JWT (Header, Claims, Signature all
// populated, identical to Find). Any other run has each of its dot-separated
// segments decoded independently, and every segment that is a base64url JSON
// object is reported as a header-less, signature-less Token with the decoded
// object in Claims. This surfaces signature-less tokens, lone payloads pasted on
// their own, and other near-JWTs that strict mode would skip.
func FindRelaxed(source string, data []byte) []Located {
	var found []Located
	for _, loc := range relaxedCandidate.FindAllIndex(data, -1) {
		start, end := loc[0], loc[1]
		run := string(data[start:end])
		if tok, err := Parse(run); err == nil {
			found = append(found, locate(source, data, start, tok))
			continue
		}
		segOff := start
		for _, seg := range strings.Split(run, ".") {
			if obj, err := parseObjectSegment(seg); err == nil {
				found = append(found, locate(source, data, segOff, &Token{Raw: seg, Claims: obj}))
			}
			segOff += len(seg) + 1 // +1 for the '.' separator
		}
	}
	return found
}

// FindStream scans r line by line with the given finder (Find or FindRelaxed)
// and calls emit for every token as soon as it is found, returning any read
// error. Because a JWT — and a base64url JSON object — contains no newline, a
// single line always holds a whole token, so line-buffered scanning finds every
// token while keeping memory bounded by the longest line, making it suitable for
// unbounded streams. Located offsets are global: byte positions relative to the
// start of r, matching what the finder would report over the whole input.
//
// The one pathological case is a stream with no newline at all (one enormous
// line); like any line-oriented tool, that line is buffered whole.
func FindStream(source string, r io.Reader, find Finder, emit func(Located)) error {
	br := bufio.NewReader(r)
	base := 0 // byte offset of the current line within the stream
	for {
		line, readErr := br.ReadString('\n')
		if len(line) > 0 {
			// Match against the line without its trailing newline; the newline
			// still counts toward the running offset of later lines.
			content := strings.TrimRight(line, "\n")
			for _, loc := range find(source, []byte(content)) {
				loc.Offset += base
				emit(loc)
			}
			base += len(line)
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}
