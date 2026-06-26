# CLAUDE.md

Guidance for working in this repo. Read this first.

## What this is

`jottlr` (soft *j*, "yaat-ler") is a Go CLI — **jq for JWTs**. It finds JSON Web
Tokens in input streams, files or directories and filters them by their decoded
contents (issuer pattern, not-expired, alg, arbitrary claim equality, ...). It
can print the raw token grep-style, the decoded header/claims, a JSON dump, or a
single jq-style field.

Module path: `github.com/defektive/jottlr`. Go 1.26. **Reader, not validator:**
jottlr decodes but **never verifies signatures**. Every claim it surfaces is
untrusted. Do not add signature verification or call it "valid" in a crypto
sense — `-valid` means *time*-valid (within `[nbf, exp)`), nothing more.

## The core idea (don't lose this)

A JOSE header is a JSON object → starts with `{"` → base64url-encodes to the
literal prefix **`eyJ`**. That is the anchor (`jwt/find.go`): a regexp matches
three dot-separated base64url segments around `eyJ`, then every candidate is
**actually decoded** (`jwt.Parse`) and dropped unless its header and payload are
real base64url JSON objects. Anchor = speed; decode = near-zero false positives.
The signature segment may be empty (`alg=none` → `header.payload.`).

## Reuse from base-grep (important architectural decision)

The content-agnostic grep machinery — bounded-parallel file/dir walk, line
capture, color/terminal handling — is **shared with the sibling `base-grep`
repo**, not duplicated. It was lifted out of `base-grep/internal/` into the
importable `github.com/defektive/base-grep/scan` package, which base-grep now
publishes; jottlr depends on it as an ordinary module (no `replace`):

```
require github.com/defektive/base-grep <pseudo-version>
```

- `scan.WalkFiles[T](root, jobs, recursive, fn)` — generic worker-pool walker;
  jottlr passes a `func(path, data) ([]jwt.Located, error)`. Deterministic,
  path-sorted output regardless of scheduling.
- `scan.LineBounds`, `scan.ResolveColor`, `scan.IsTerminal`, `scan.HiOn/HiOff`.

To pick up local changes to the `scan` package, bump the dependency with
`go get github.com/defektive/base-grep@latest` after base-grep is pushed (or add
a temporary `replace` pointing at `../base-grep` while iterating across both).

## Layout

```
main.go              CLI: flags, buildFilter, parseTime, orchestration
render.go            output modes (raw / -decode / -json / -get) + renderLine
jwt/                 the JWT library (public, reusable, no CLI deps)
  jwt.go             Token, Parse, claim accessors, expiry/time helpers
  find.go            Find(source, data) []Located + FindStream (line-buffered)
  filter.go          Filter (predicate conjunction) + jq-style Extract
integration_test.go  builds the real binary, drives it over stdin/files/dirs
render_test.go       unit tests for renderLine / formatValue / buildFilter
```

## Behavior decisions already made (don't regress these)

- **Filters are ANDed**; the zero `jwt.Filter` matches everything (bare `jottlr`
  = find all tokens). `-not-expired` requires an `exp` to *exist* and be future
  (a token with no `exp` fails it — there's nothing proving freshness), whereas
  `IsExpired`/`NotYetValid` treat absent bounds as "not expired"/"not too early".
- **Numbers stay `json.Number`** (decoder uses `UseNumber`) so big NumericDate
  values and `-claim ver=2` comparisons don't suffer float rounding.
- **`aud` is normalised** to `[]string` (JWT allows string *or* array).
- **JSON output disables HTML escaping** so `<stdin>` and URLs print literally.
- **Exit codes follow grep**: 0 = match, 1 = no match, 2 = usage/IO error.
- **Output ordering** is deterministic: stream matches in encounter order, file/
  dir matches sorted by path then offset (via `scan.WalkFiles`).
- **stdin is streamed** via `jwt.FindStream` (line-buffered) and rendered
  incrementally through `sink` — jottlr never buffers the whole input, so it
  works on unbounded pipes (`tail -f`, `logs -f`). JWTs contain no newline, so a
  line is the correct unit and nothing is missed. The `sink` opens/closes the
  `-json` array as elements arrive; don't reintroduce a "collect then render"
  step that would defeat streaming. (The one unavoidable buffer is a stream with
  no newline at all — one giant line.) Files still go through `scan.WalkFiles`,
  which reads each file whole.

## Conventions

- Standard library only in `jottlr` itself; the one dependency is the local
  `base-grep/scan`. Keep it that way.
- Run `gofmt -w .` and keep `go vet ./...` clean before finishing.
- Tests must pass under `go test -race ./...`.
- Tests build tokens with a `makeJWT`/`mkJWT` helper — keep headers containing
  `alg` (sorted JSON keys put `alg` first → the `eyJ` anchor holds).
- `Match`/`Located`/JSON output are a public-ish contract; change deliberately.

## Commands

```sh
go build -o jottlr .
go test ./...            # unit + integration
go test -race ./...      # must stay clean
echo "$TOKEN" | go run . -decode
go run . -r -not-expired -iss 'example\.com' ./dir
```

## Likely next steps (not yet done)

- JWE (5-segment) detection — currently only compact JWS is recognised.
- `-count` / `-l` (files-with-matches) grep-style summary flags.
- Reuse base-grep's `-max-filesize` idea as a skip guard for huge files.
