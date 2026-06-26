package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/defektive/base-grep/scan"
	"github.com/defektive/jottlr/jwt"
)

// marshalIndent is json.MarshalIndent without HTML escaping, so '<', '>' and '&'
// (common in URLs and the "<stdin>" source label) print literally.
func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// outputMode selects how matching tokens are printed. At most one of get, json,
// decode or only applies (in that precedence); otherwise the default grep-like
// raw line is used.
type outputMode struct {
	only   bool
	decode bool
	json   bool
	get    string
}

// jsonToken is the structured representation emitted by -json. Header is omitted
// for relaxed-mode bare objects, which have no JOSE header.
type jsonToken struct {
	Source string         `json:"source"`
	Offset int            `json:"offset"`
	Raw    string         `json:"raw"`
	Header map[string]any `json:"header,omitempty"`
	Claims map[string]any `json:"claims"`
}

// decodeView is the per-token object printed by -decode: the decoded values,
// tagged with where the token was found. Header is omitted for relaxed-mode bare
// objects.
type decodeView struct {
	Source string         `json:"source"`
	Offset int            `json:"offset"`
	Header map[string]any `json:"header,omitempty"`
	Claims map[string]any `json:"claims"`
}

// sink renders matching tokens one at a time, so jottlr never has to hold the
// whole input (or the whole match set) in memory — essential for unbounded
// streams. Emit writes each token immediately; Close finishes any output that
// needs a footer (the closing bracket of a -json array).
type sink struct {
	w        io.Writer
	mode     outputMode
	color    bool
	maxCols  int
	count    int  // tokens emitted (drives the process exit code)
	jsonOpen bool // whether the -json array has been opened
}

func newSink(w io.Writer, mode outputMode, color bool, maxCols int) *sink {
	return &sink{w: w, mode: mode, color: color, maxCols: maxCols}
}

// Emit renders one matching token according to the active output mode.
func (s *sink) Emit(loc jwt.Located) error {
	s.count++
	switch {
	case s.mode.get != "":
		if v, ok := jwt.Extract(loc.Token, s.mode.get); ok {
			fmt.Fprintln(s.w, formatValue(v))
		}
	case s.mode.json:
		elem, err := marshalArrayElem(jsonToken{
			Source: loc.Source,
			Offset: loc.Offset,
			Raw:    loc.Token.Raw,
			Header: loc.Token.Header,
			Claims: loc.Token.Claims,
		})
		if err != nil {
			return err
		}
		sep := ",\n  "
		if !s.jsonOpen {
			sep = "[\n  "
			s.jsonOpen = true
		}
		if _, err := io.WriteString(s.w, sep); err != nil {
			return err
		}
		_, err = s.w.Write(elem)
		return err
	case s.mode.decode:
		b, err := marshalIndent(decodeView{
			Source: loc.Source,
			Offset: loc.Offset,
			Header: loc.Token.Header,
			Claims: loc.Token.Claims,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(s.w, "%s\n", b)
	case s.mode.only:
		tok := loc.Token.Raw
		if s.color {
			tok = scan.HiOn + tok + scan.HiOff
		}
		fmt.Fprintln(s.w, tok)
	default:
		fmt.Fprintf(s.w, "%s:%d: %s\n", loc.Source, loc.Offset, renderLine(loc, s.color, s.maxCols))
	}
	return nil
}

// Close writes any trailing output. For -json it closes the array (or writes an
// empty array when nothing matched); other modes need no footer.
func (s *sink) Close() error {
	if !s.mode.json {
		return nil
	}
	if !s.jsonOpen {
		_, err := io.WriteString(s.w, "[]\n")
		return err
	}
	_, err := io.WriteString(s.w, "\n]\n")
	return err
}

// marshalArrayElem renders one -json array element: indented two spaces deeper
// than the array, with HTML escaping disabled. The leading "  " for the opening
// brace is supplied by the caller's separator.
func marshalArrayElem(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("  ", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// formatValue renders an extracted claim value for -get: strings and numbers
// print bare (shell-friendly), everything else as compact JSON.
func formatValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	default:
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(bytes.TrimRight(buf.Bytes(), "\n"))
	}
}

// renderLine returns the token's line with the token span highlighted (when
// color is enabled). When maxCols > 0 and the line is longer, it is truncated to
// a window of about maxCols columns centred on the token, with an ellipsis on
// each trimmed side. Mirrors base-grep's grep-like rendering.
func renderLine(loc jwt.Located, color bool, maxCols int) string {
	line := loc.Line
	start, end := loc.Col, loc.Col+len(loc.Token.Raw)
	if start < 0 || end > len(line) { // safety; should not happen
		return line
	}
	prefix, matched, suffix := line[:start], line[start:end], line[end:]

	if maxCols > 0 && len(line) > maxCols {
		budget := maxCols - len(matched)
		if budget < 0 {
			budget = 0
		}
		left := budget / 2
		right := budget - left
		if len(prefix) > left {
			prefix = "…" + prefix[len(prefix)-left:]
		}
		if len(suffix) > right {
			suffix = suffix[:right] + "…"
		}
	}

	if color {
		matched = scan.HiOn + matched + scan.HiOff
	}
	return prefix + matched + suffix
}
