# jottlr

`jottlr` (a soft *j* — "yaat-ler") is **jq for JWTs**: a Go CLI that finds JSON
Web Tokens in input streams, files, or directories and filters them by their
decoded contents. Print the decoded header and claims, pull out a single field,
or print the raw token grep-style when its claims match — *not expired*, *issuer
matches a pattern*, *alg is none*, *has this claim*, and so on.

It is a **reader / triage tool**, not an auth library: jottlr decodes but never
verifies signatures. Treat anything it surfaces as untrusted.

Module path: `github.com/defektive/jottlr`. Go 1.26. Standard library only,
except the shared scanning engine reused from its sibling
[`base-grep`](../base-grep) (see *Reuse* below).

## Install / build

```sh
go build -o jottlr .
```

## Usage

```
jottlr [flags] [path ...]
```

With no path, jottlr reads **stdin**, scanning it line by line and printing each
match as soon as it is found — so it works on unbounded pipes (`kubectl logs -f`,
`tail -f`, a long capture) without buffering the whole stream. Given a file it
scans that file; given a directory it scans the immediate files, or the whole
tree with `-r`. Exit codes follow grep: **0** = at least one token matched,
**1** = none, **2** = usage/IO error.

### Finding tokens

```sh
# Pull every JWT out of a log stream (grep-style: source:offset: line).
kubectl logs pod | jottlr

# Recursively scan a directory of captured traffic / configs for tokens.
jottlr -r ./captures
```

### Filtering

| Flag | Keeps tokens where… |
|------|---------------------|
| `-iss <regexp>` | the `iss` claim matches the pattern |
| `-sub <regexp>` | the `sub` claim matches |
| `-aud <regexp>` | some `aud` entry matches |
| `-alg <name>` | the header `alg` equals `<name>` (case-insensitive) |
| `-not-expired` | there is an `exp` claim strictly in the future |
| `-expired` | there is an `exp` claim at or before now |
| `-valid` | now falls within `[nbf, exp)` |
| `-has <claim>` | the claim is present (repeatable) |
| `-claim k=v` | claim `k` equals `v` (repeatable; numbers/bools stringified) |
| `-now <t>` | reference time for the above (RFC3339 or Unix epoch) |

Filters are ANDed together. A bare `jottlr` (no filters) matches every token.

```sh
# Live tokens issued by our accounts service — print the subject of each.
jottlr -not-expired -iss 'accounts\.example\.com$' -get sub < tokens.txt

# Hunt for forgeable alg=none tokens in a tree.
jottlr -r -alg none ./loot

# Admin tokens only.
jottlr -claim admin=true -has exp access.log
```

### Output modes

- **(default)** raw token, grep-style: `source:offset: <line>` with the token
  highlighted (`-color auto|always|never`, `-max-columns N`).
- `-decode` — pretty-print the decoded `header` and `claims` (tagged with where
  the token was found).
- `-json` — emit all matching tokens as a JSON array (`source`, `offset`,
  `raw`, `header`, `claims`).
- `-get <path>` — print one field, jq-style. The path resolves against the
  claims by default; prefix with `header.`, `payload.`/`claims.` to choose a
  section, and dot into nested objects:

  ```sh
  jottlr -get iss                  # the issuer
  jottlr -get header.alg           # the algorithm
  jottlr -get realm_access.roles   # nested claim -> JSON array
  ```

## How JWTs are found

A JOSE header is a JSON object, so it begins with `{"` — which base64url-encodes
to the literal prefix **`eyJ`**. jottlr uses that as a cheap, highly selective
anchor, matches three dot-separated base64url segments around it, then *actually
decodes* each candidate: anything whose header/payload are not real base64url
JSON objects is discarded. This keeps false positives near zero while staying
fast. The signature segment may be empty (`alg=none` tokens are
`header.payload.`).

## Reuse: the shared `scan` engine

The directory walk, line capture, and color handling are not JWT-specific, so
they live in `base-grep`'s `scan` package (lifted out of its `internal/` tree so
sibling tools can import it). jottlr depends on the published module directly:

```
require github.com/defektive/base-grep <version>
```

`scan.WalkFiles[T]` is a generic, bounded-parallel file/dir walker; each tool
plugs in its own per-file matcher (literal-pattern search in base-grep, JWT
extraction here) and reuses the concurrency, error collection and deterministic
ordering. `scan.LineBounds`, `scan.ResolveColor` and `scan.IsTerminal` round out
the shared grep-like behaviour.

## Layout

```
main.go              CLI: flags, filter assembly, orchestration
render.go            output rendering (raw / decode / json / get) + color
jwt/                 the JWT library (public, reusable)
  jwt.go             Token, Parse, claim accessors, expiry helpers
  find.go            Find JWTs in a buffer or stream (regexp anchor + decode)
  filter.go          Filter predicates and the jq-style Extract
integration_test.go  builds the real binary and drives it
render_test.go       unit tests for rendering / flag plumbing
```

## Development

```sh
go build -o jottlr .
go test ./...           # unit + integration
go test -race ./...     # must stay clean
gofmt -w . && go vet ./...
```

## Security note

jottlr is intended for authorized security testing, CTF, and defensive triage:
spotting and sorting tokens you are entitled to inspect. It does not verify
signatures and makes no claim a token is genuine — only that it *decodes* and
its claims match your filter.
