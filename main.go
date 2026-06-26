// Command jottlr finds JSON Web Tokens in input streams, files or directories
// and filters them by their decoded contents — "jq for JWTs". It can print the
// decoded header/claims, extract a single field, or print the raw token grep
// style when its claims match a set of predicates (issuer pattern, not expired,
// algorithm, arbitrary claim equality, ...).
//
// jottlr never verifies signatures; it is an inspection/triage tool. Exit codes
// follow grep: 0 = at least one token matched, 1 = none, 2 = usage/IO error.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/defektive/base-grep/scan"
	"github.com/defektive/jottlr/jwt"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// stringList is a repeatable string flag (e.g. -has exp -has iss).
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func run(args []string, stdin *os.File, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("jottlr", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		// Filtering.
		alg        = fs.String("alg", "", "require the header alg to equal this (case-insensitive)")
		issRe      = fs.String("iss", "", "require the iss claim to match this regexp")
		subRe      = fs.String("sub", "", "require the sub claim to match this regexp")
		audRe      = fs.String("aud", "", "require an aud entry to match this regexp")
		notExpired = fs.Bool("not-expired", false, "require an exp claim strictly in the future")
		expired    = fs.Bool("expired", false, "require an exp claim at or before now")
		timeValid  = fs.Bool("valid", false, "require now to fall within [nbf, exp)")
		has        stringList
		claimEq    stringList

		// Output.
		decode = fs.Bool("decode", false, "print the decoded header and claims instead of the raw token")
		jsonO  = fs.Bool("json", false, "emit matching tokens as a JSON array (source, offset, header, claims)")
		get    = fs.String("get", "", "print only this dotted field (jq-style), e.g. iss, header.alg, realm_access.roles")

		// Search / rendering.
		recursive = fs.Bool("r", false, "recurse into subdirectories when a path is a directory")
		jobs      = fs.Int("jobs", 0, "files to scan in parallel during a directory walk (0 = number of CPUs)")
		colorWhen = fs.String("color", "auto", "highlight the token in raw output: always, never, or auto (terminal only)")
		maxCols   = fs.Int("max-columns", 0, "truncate raw lines to this many columns around the token (0 = whole line)")
		now       = fs.String("now", "", "reference time for exp/nbf as RFC3339 or a Unix epoch (default: current time)")
	)
	fs.Var(&has, "has", "require this claim to be present (repeatable)")
	fs.Var(&claimEq, "claim", "require claim=value (repeatable), e.g. -claim admin=true")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: jottlr [flags] [path ...]\n\n")
		fmt.Fprintf(stderr, "Finds JWTs and filters them by their claims. With no path, reads stdin.\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	filter, err := buildFilter(*alg, *issRe, *subRe, *audRe, *notExpired, *expired, *timeValid, has, claimEq, *now)
	if err != nil {
		fmt.Fprintln(stderr, "jottlr:", err)
		return 2
	}

	useColor, err := scan.ResolveColor(*colorWhen, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "jottlr:", err)
		return 2
	}

	paths := fs.Args()

	out := newSink(stdout, outputMode{decode: *decode, json: *jsonO, get: *get}, useColor, *maxCols)

	// emit applies the filter and renders matching tokens incrementally, so the
	// whole input never has to be buffered. A write error aborts the run.
	var emitErr error
	emit := func(loc jwt.Located) {
		if emitErr != nil || !filter.Match(loc.Token) {
			return
		}
		emitErr = out.Emit(loc)
	}

	if len(paths) == 0 {
		// No paths: stream stdin so jottlr works on unbounded pipes.
		if err := jwt.FindStream("<stdin>", stdin, emit); err != nil && emitErr == nil {
			fmt.Fprintln(stderr, "jottlr:", err)
			return 2
		}
	}
	for _, p := range paths {
		located, errs := scan.WalkFiles(p, *jobs, *recursive, func(path string, data []byte) ([]jwt.Located, error) {
			return jwt.Find(path, data), nil
		})
		for _, e := range errs {
			fmt.Fprintln(stderr, "jottlr:", e)
		}
		for _, loc := range located {
			emit(loc)
		}
	}

	if emitErr != nil {
		fmt.Fprintln(stderr, "jottlr:", emitErr)
		return 2
	}
	if err := out.Close(); err != nil {
		fmt.Fprintln(stderr, "jottlr:", err)
		return 2
	}
	if out.count == 0 {
		return 1 // grep convention: 1 means "no matches"
	}
	return 0
}

// buildFilter assembles a jwt.Filter from the parsed flags, compiling regexps
// and parsing the -now reference time.
func buildFilter(alg, issRe, subRe, audRe string, notExpired, expired, timeValid bool, has, claimEq stringList, nowStr string) (jwt.Filter, error) {
	f := jwt.Filter{Alg: alg, NotExpired: notExpired, Expired: expired, TimeValid: timeValid, HasClaims: has}

	for name, src := range map[string]string{"iss": issRe, "sub": subRe, "aud": audRe} {
		if src == "" {
			continue
		}
		re, err := regexp.Compile(src)
		if err != nil {
			return f, fmt.Errorf("invalid -%s regexp: %w", name, err)
		}
		switch name {
		case "iss":
			f.Issuer = re
		case "sub":
			f.Subject = re
		case "aud":
			f.Audience = re
		}
	}

	if len(claimEq) > 0 {
		f.ClaimEq = make(map[string]string, len(claimEq))
		for _, kv := range claimEq {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return f, fmt.Errorf("invalid -claim %q (want key=value)", kv)
			}
			f.ClaimEq[k] = v
		}
	}

	if nowStr != "" {
		t, err := parseTime(nowStr)
		if err != nil {
			return f, err
		}
		f.Now = t
	}
	return f, nil
}

// parseTime accepts an RFC3339 timestamp or a bare Unix epoch (seconds).
func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	var secs int64
	if _, err := fmt.Sscanf(s, "%d", &secs); err == nil {
		return time.Unix(secs, 0), nil
	}
	return time.Time{}, fmt.Errorf("invalid -now %q (want RFC3339 or a Unix epoch)", s)
}
