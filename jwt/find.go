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

// Located is a JWT found at a position in some input, with the surrounding line
// captured for grep-like output.
type Located struct {
	// Token is the decoded JWT.
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
		ls, le := scan.LineBounds(data, start)
		found = append(found, Located{
			Token:  tok,
			Source: source,
			Offset: start,
			Line:   string(data[ls:le]),
			Col:    start - ls,
		})
	}
	return found
}

// FindStream scans r line by line and calls emit for every JWT as soon as it is
// found, returning any read error. Because a JWT contains no newline (its
// segments are base64url joined by dots), a single line always holds a whole
// token — so line-buffered scanning finds every token while keeping memory
// bounded by the longest line, making it suitable for unbounded streams. Located
// offsets are global: byte positions relative to the start of r, matching what
// Find would report over the whole input.
//
// The one pathological case is a stream with no newline at all (one enormous
// line); like any line-oriented tool, that line is buffered whole.
func FindStream(source string, r io.Reader, emit func(Located)) error {
	br := bufio.NewReader(r)
	base := 0 // byte offset of the current line within the stream
	for {
		line, readErr := br.ReadString('\n')
		if len(line) > 0 {
			// Match against the line without its trailing newline; the newline
			// still counts toward the running offset of later lines.
			content := strings.TrimRight(line, "\n")
			for _, loc := range Find(source, []byte(content)) {
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
