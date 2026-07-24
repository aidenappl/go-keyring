# AGENTS.md — go-keyring

> `go-keyring` is the **Go SDK for the Keyring secrets platform**. A consuming service holds a
> Keyring **service token** (`KEYRING_ACCESS_KEY_ID` + `KEYRING_SECRET_ACCESS_KEY`) and uses this
> module to fetch — at process startup — only the secrets it has been granted, over a single
> `GET /secrets` call to `keys.appleby.cloud` authenticated with HTTP Basic. Its headline calls
> are `keyring.MustGet("SECRET_NAME")` (fetch-or-panic) and the newer `keyring.MustResolve(...)`
> family (Keyring **or** environment, tolerant of an unconfigured Keyring). This file orients any
> agent/worker before touching code in this repo.
>
> **⚠️ Golden rule — keep this file current:** any change to the exported surface (functions,
> types, `Option`s, sentinel errors), the resolution order, the env-var names, the wire format,
> or the release process MUST update this AGENTS.md — and `README.md` — in the SAME change. This
> module is consumed by tag across many services; stale context here misleads every future agent
> and every downstream service that upgrades.
>
> **⚠️ Blast radius:** this is a **shared library pinned by version in each consumer's `go.mod`**,
> so a change is opt-in — nothing moves until a service runs `go get -u`. But a bad tagged release
> that services then upgrade to can break **startup for every service that fetches its config
> here**. Keyring failures do not degrade gracefully: `MustGet`/`MustLoad` panic, which is the
> intended fail-fast at boot.

---

## What this repo is

A small, dependency-free Go module (`module github.com/aidenappl/go-keyring`, `go 1.24.10`)
published by git tag and consumed via the Go module proxy. It is **not a service** — there is no
`main`, no Docker image, no deployment, no server. It is the client half of the Keyring platform;
the server is [`keyring-api`](https://github.com/aidenappl/keyring-api).

Its single job: let a Go service resolve its configuration from Keyring instead of shipping a
`.env` file. Two usage shapes:

1. **Fetch-or-fail (`Get`/`MustGet`/`Load`/`MustLoad`/`InjectEnv`)** — talk to the Keyring API,
   treat an unreachable/unconfigured Keyring as an error (or a panic).
2. **Resolve (`Lookup`/`Resolve`/`MustResolve`/`ResolveOr`)** — try the process **environment
   first**, then Keyring, and treat an unconfigured/unreachable Keyring as *not an error*. This is
   the family that works cleanly in tests and CI where Keyring is deliberately absent.

The entire module is **one package, `keyring`**, at the repo root — three `.go` files plus two
test files.

## Stack & dependencies

- **Go 1.24.10**, **standard library only**. `go.sum` is empty; there are **zero external
  dependencies**. Keep it that way unless there is a strong reason — a secrets SDK with no
  transitive deps is a security feature.
- Transport is `net/http` with HTTP Basic Auth and a JSON body. No router, no SQL, no framework.
- Response bodies are capped at **32 MiB** (`maxResponseBytes`) to bound memory from an
  unexpectedly large or malicious payload, and drained before close so the TCP connection is
  reusable.

## Project structure

Flat, single-package, package-per-file-by-concern. No `cmd/`, `internal/`, or `pkg/`.

| Path | Role |
|------|------|
| `keyring.go` | The core client. `Client`, the `Option` functional options (`WithURL`, `WithCredentials`, `WithTimeout`), `New`, the wire types (`secret`, `secretsResponse`), `Load`/`MustLoad`, `InjectEnv`, `Get`/`MustGet`/`GetOr` (methods **and** package-level convenience functions). Also `maxResponseBytes`. |
| `resolve.go` | The **Resolve family** (env-first, Keyring-second). `SourceEnvVar` (`KEYRING_SOURCE`), `EnvOnly`, `Lookup`, `Resolve`, `MustResolve`, `ResolveOr`. Added in commit `7e77249` "Add Resolve helpers: Keyring or environment". |
| `errors.go` | The three sentinel errors: `ErrUnauthorized`, `ErrUnavailable`, `ErrMalformedResponse`. |
| `resolve_test.go` | Unit tests for the Resolve family (standard `testing`, `t.Setenv`, no testify). |
| `keyring_test.go` | Unit tests for the core client — `Load`/`New`/`InjectEnv` exercised against an `httptest.Server`: happy path, HTTP Basic header, 401/403 → `ErrUnauthorized`, network/timeout → `ErrUnavailable`, non-2xx / unparseable body → `ErrMalformedResponse`, and `New` field validation. Standard `testing`, no testify. |
| `go.mod` / `go.sum` | Module definition (Go 1.24.10); `go.sum` is empty (no deps). |
| `Devfile.yaml` | The `dev` CLI command map (see below). |
| `.github/workflows/pr.yml` | PR gate: gofmt check, `go mod verify` + tidy diff, `go build`, `go test -race`. |
| `.github/workflows/ci.yml` | `Release` workflow on `main` / `v*` tags: gofmt, golangci-lint, `go test -race` + coverage → Codecov, `govulncheck`, and a tag-triggered GitHub Release with generated changelog. |
| `README.md` | The consumer-facing usage guide. Keep in sync with this file. |

## Running, building & testing

This repo uses the standard `dev` CLI via `Devfile.yaml`:

```bash
dev build    # go build ./...          (compiles the library)
dev run      # go test ./...            (library has no main; runs the tests instead)
dev test     # go test ./...
dev fmt      # gofmt -w -s .
dev vet      # go vet ./...
dev check    # gofmt -w -s . && go vet ./... && go test ./...
dev tidy     # go mod tidy
```

> Note: this is a **library** with no `main` package. `dev build` compiles the whole module
> (`go build ./...`) and `dev run` runs the tests (`go test ./...`) since there is nothing to
> execute. `dev check` / `dev test` are the ones that matter.

There is **no** Docker, no `docker-compose`, no `.env` required to build or test — the tests
deliberately run with `KEYRING_URL` unset.

## How code is written here

- **Package-level convenience over a client.** Every core operation exists twice: as a method on
  `*Client` (for services that build and hold a client) and as a package-level function that
  builds a client from environment variables on each call (`keyring.Get`, `keyring.MustGet`,
  `keyring.GetOr`). The package-level forms are the ergonomic 90%-case; the `*Client` forms are
  for when you want explicit options or to reuse one client.
- **Functional options.** `New(opts ...Option)` seeds from env vars, then applies options, then
  validates that `url`, `accessKeyID`, and `secretAccessKey` are all non-empty (returns a
  descriptive error naming the missing piece and how to supply it). Options are `WithURL` (strips
  trailing slash), `WithCredentials`, `WithTimeout`.
- **Sentinel errors, wrapped.** `Load` maps transport failures to `ErrUnavailable`, 401/403 to
  `ErrUnauthorized`, and any other status or unparseable body to `ErrMalformedResponse`, using
  `fmt.Errorf("%w: ...", ErrX, ...)` so consumers can `errors.Is`. Preserve this — the README
  documents `errors.Is` handling as part of the contract.
- **Environment-first precedence for single-key reads.** `Client.Get` (and therefore
  `keyring.Get`/`MustGet`) checks `os.Getenv(key)` **first**; if the key is already in the
  process environment it returns that value and prints a notice (`keyring: using local env var
  ... (keyring lookup skipped)`) instead of calling the API. This is why `InjectEnv`-then-`Get`
  never double-fetches, and why local `.env`/shell overrides win.
- **Never log values, only names.** `InjectEnv` prints a boxed, sorted table of injected **key
  names** to stdout, marking `(override)` where it replaced a differing existing env var. It never
  prints a value. Keep every log/print path value-free — this is a hard rule for a secrets SDK.
- **Empty string means "not set".** Throughout (`Get`, `Lookup`), an empty value is treated as
  absent so a fallback still applies. A test (`TestLookup_EmptyEnvValueIsNotFound`) locks this in.
- **Tests use `testing` + `t.Setenv` only.** No testify, no mocking framework. Because the Resolve
  tests leave `KEYRING_URL` unset, `New()` fails and resolution falls through to env — which is
  exactly the CI/test situation being verified.

## Domain & architecture

### The one endpoint: `GET /secrets`

`Client.Load` is the only network call in the module. It does:

1. `GET {url}/secrets` where `url` is `KEYRING_URL` (default nothing — required).
2. `req.SetBasicAuth(accessKeyID, secretAccessKey)` — **HTTP Basic**, username = access key ID,
   password = secret access key.
3. Reads the JSON envelope `{ "data": [ { "key": ..., "value": ... }, ... ] }` (capped at 32 MiB,
   body drained then closed) into a `map[string]string`.

The API returns **decrypted** values on this path — that is the whole point of the service path
(contrast `keyring-api`'s `/admin/*` endpoints, which deal in ciphertext). The token only ever
receives the secrets it has been **granted**; `go-keyring` does no filtering of its own.

### Resolution helpers — env first, Keyring second

`resolve.go` exists because `Get`/`MustGet`/`GetOr` build a client first and therefore **fail
when Keyring is unconfigured, even if the value is right there in the environment** — awkward in
tests and CI, where services had started hand-rolling "try Keyring, then fall back to env"
wrappers. `Resolve` centralises that:

- **`Lookup(ctx, key) (string, bool)`** — resolution order: (1) `os.LookupEnv(key)` when non-empty;
  (2) if `EnvOnly()` is false, build a client and call `Get`. An unconfigured or unreachable
  Keyring is **not an error** — it just reports "not found". Never returns an error.
- **`Resolve(ctx, key) (string, error)`** — `Lookup`, else an error **naming the key** and whether
  it was env-only.
- **`MustResolve(key) string`** — `Resolve` with `context.Background()`, panics if absent
  everywhere. **Prefer this over `MustGet` for service startup**: it succeeds from the environment
  even when Keyring is unavailable (the normal situation in tests/CI).
- **`ResolveOr(ctx, key, fallback) string`** — `Lookup`, else `fallback`. Never contacts Keyring
  when the value is already in the environment.

### `KEYRING_SOURCE=env` — the CI/test escape hatch

`SourceEnvVar` is the constant `"KEYRING_SOURCE"`. When it equals `env` (case-insensitive),
`EnvOnly()` returns true and the Resolve family **skips the Keyring API entirely**, reading only
the process environment. Services set this in tests and CI so a test process can **never** pick up
production secrets from a developer's configured Keyring. `EnvOnly()` defaults to false when the
var is unset.

### Precedence summary

| Call | Order | Keyring unreachable is… | On absent |
|------|-------|-------------------------|-----------|
| `Get` / `MustGet` / `GetOr` | env first, then Keyring (builds a client) | **an error** (client build or fetch fails) | error / panic / fallback |
| `Lookup` / `Resolve` / `MustResolve` / `ResolveOr` | env first, then Keyring (unless `KEYRING_SOURCE=env`) | **not an error** | not-found / error / panic / fallback |
| `Load` / `MustLoad` | Keyring only (no env fallback) | error / panic | n/a (returns whole map) |
| `InjectEnv` | Keyring only, writes results into env | error | n/a |

### The lazy-`Init()` consumer implication

The global CLAUDE.md DB pattern uses an IIFE (`var DB = func() *sql.DB { ... }()`) that connects
at package-init time. **Services that fetch their DSN from Keyring cannot do that** — at package
init, `InjectEnv`/`MustResolve` may not have run yet, so the DSN env var is empty and the IIFE
would connect to nothing (or panic). Such services use a **lazy `Init()`** for the DB connection
instead, called from `main()` **after** Keyring has resolved config. If you are wiring a new
Keyring consumer, the correct boot order is:

```go
func main() {
    // 1. Pull config from Keyring into the environment FIRST.
    client, err := keyring.New()
    if err != nil { log.Fatal(err) }
    if err := client.InjectEnv(context.Background()); err != nil { log.Fatal(err) }

    // 2. NOW initialise things that read that config.
    db.Init()          // lazy Init(), not a package-level IIFE
    // ... start server
}
```

This is called out in the global standards ("If the service loads secrets from Keyring at
startup, use a lazy `Init()` function instead of an IIFE"). Getting it wrong manifests as a
service that connects to an empty/default DSN despite Keyring being healthy.

## Ecosystem & related repos

Keyring is one of the five `appleby.cloud` infrastructure platforms. This module is the Go
consumer SDK; the other pieces:

| Repo | Relationship |
|------|--------------|
| [`keyring-api`](https://github.com/aidenappl/keyring-api) | **The server.** Serves `GET /secrets` (this SDK's only endpoint) on `keys.appleby.cloud`, plus the Forta-authed `/admin/*` surface. Owns storage, the grant graph, tokens, groups, audit. |
| [`keyring-web`](https://github.com/aidenappl/keyring-web) | Dashboard at **`keyring.appleby.cloud`** (note: different host from the API). Holds the encryption key client-side. |
| [`keyring-js`](https://github.com/aidenappl/keyring-js) | The **Node/React equivalent** of this module (`@aidenappl/keyring-js`, `injectEnv()`). Keep behaviour conceptually aligned — same endpoint, same auth, same env-var names. |
| [`keyring-mcp`](https://github.com/aidenappl/keyring-mcp) | MCP server exposing the admin API to Claude Code. Authenticated by a **Forta `frt_` token**, not a Keyring service token — Keyring has no admin credential of its own. |
| [`keyring-actions`](https://github.com/aidenappl/keyring-actions) | GitHub Action that injects secrets into CI. |
| [`forta-api`](https://github.com/aidenappl/forta-api) | Identity provider for Keyring's **admin** auth. Irrelevant to *this* SDK's path — service-token Basic auth does **not** involve Forta. |

### Auth model — service tokens, NOT Forta

This SDK authenticates with a **Keyring service token**: an `access_key_id` + `secret_access_key`
pair, sent as HTTP Basic on `GET /secrets`. That is a completely different credential from the
Forta `frt_` tokens / OAuth cookies used to reach `keyring-api`'s `/admin/*` surface (and used by
`keyring-mcp`). A service using `go-keyring` needs **only** the two service-token env vars; it does
not need, and must not be given, Forta credentials. When debugging a 401/403 from this SDK
(`ErrUnauthorized`), check the **token** (`keyring_list_tokens`, and its grants via
`keyring_list_secret_grants`) — not Forta grants.

### The two-hostname trap

- **API (this SDK talks here):** `https://keys.appleby.cloud` → set as `KEYRING_URL`.
- **Web dashboard (humans):** `https://keyring.appleby.cloud`.

They are easy to swap. `KEYRING_URL` must point at **`keys`**, not `keyring`. Pointing it at the
web host yields HTML and an `ErrMalformedResponse`. (The README's `keyring.example.com` in the
`WithURL` example is illustrative only.)

## Operations

- **Not deployed.** There is no running instance of *this* repo. It ships as a tagged Go module.
- **Consumed by tag.** Existing tags: `v1.0.0`, `v1.0.1`, `v1.0.2`, `v1.1.0`. The Resolve family
  (`resolve.go`) landed for `v1.1.0`. A consumer upgrades with:
  ```bash
  go get github.com/aidenappl/go-keyring@vX.Y.Z   # or `@latest`
  go get -u github.com/aidenappl/go-keyring        # bump to newest
  ```
- **Release pipeline (`.github/workflows/ci.yml`, `Release`):** on a pushed `v*` tag it runs
  lint + `go test -race` + `govulncheck`, validates the tag matches `vX.Y.Z[-suffix]`, generates a
  changelog from git log, and cuts a GitHub Release. On `main` (non-tag) it runs the same checks
  without releasing. PRs run `.github/workflows/pr.yml` (gofmt, module-tidy diff, build, race
  tests).
- **Cutting a release:**
  ```bash
  git tag -a v1.x.y -m "..." && git push origin v1.x.y
  # then confirm the proxy has it:
  curl https://proxy.golang.org/github.com/aidenappl/go-keyring/@v/list
  ```
  The module proxy caches immutably and `sum.golang.org` can lag a fresh tag by seconds to
  minutes — a `go get` immediately after tagging may 500; retry rather than reaching for
  `GONOSUMDB`.
- **Install-path note:** the `ci.yml` release note's install snippet emits
  `go get github.com/aidenappl/go-keyring@<tag>` — matching the module path in `go.mod`. It
  previously carried a spurious `/v1` suffix (only correct at v2+); that has been fixed. Keep it
  without a major-version suffix until the module actually goes to v2.

## Rules & guardrails

- **Never log, echo, or print a secret value.** Only key names. `InjectEnv`'s table and `Get`'s
  "using local env var" notice are name-only by design — keep every new print path value-free.
- **Never add a dependency without a strong reason.** `go.sum` is empty today; a zero-dependency
  secrets SDK is a deliberate security posture. If you must add one, say so loudly and update this
  file and CI.
- **Never retag or move a published version.** The module proxy caches immutably; consumers may
  already hold the old bytes. Cut a new tag instead.
- **Preserve the sentinel-error contract.** Consumers `errors.Is` on `ErrUnauthorized` /
  `ErrUnavailable` / `ErrMalformedResponse`. Don't change what maps to which without updating the
  README table and this file.
- **Preserve env-first precedence** in `Get`/`Lookup` and the `KEYRING_SOURCE=env` short-circuit.
  Tests and CI depend on env winning and on Keyring being skippable — flipping this could make a
  test process reach a real Keyring.
- **Don't turn a "not an error" path into an error.** The whole reason `resolve.go` exists is that
  an unconfigured/unreachable Keyring is tolerated. `MustGet` panicking is intended fail-fast;
  `Resolve` not erroring on an absent Keyring is intended tolerance. Keep them distinct.
- **Keep the 32 MiB response cap and the body-drain-before-close.** They bound memory and allow
  connection reuse.
- **`KEYRING_URL` points at `keys.appleby.cloud`**, not the web host. See the two-hostname trap.

## Verification — always before "done"

```bash
gofmt -w .          # or: gofmt -l .   (must print nothing)
go build ./...
go vet ./...
go test ./...       # or `go test -race ./...` to match CI
```

or `dev check`. **Current status: all four pass clean** — `gofmt -l .` is empty, build and vet are
silent, `go test ./...` is `ok github.com/aidenappl/go-keyring`. CI additionally runs
golangci-lint, `go mod verify` + a tidy diff, `go test -race`, and `govulncheck`; if you add a
dependency or change `go.mod`, run `go mod tidy` and confirm no diff.

Because this module gates startup for real services, a green compile proves less than it looks.
For any behavioural change, verify against a **real consumer**:

```bash
cd ../<a-keyring-consumer> && go get github.com/aidenappl/go-keyring@<version> && go build ./... && go vet ./...
```

**Never report work complete if build, vet, or tests fail. Never report a resolution-behaviour or
auth change complete on a compile alone.**

## Keeping this file updated

Update this AGENTS.md (and `README.md`) in the same change when you:
- **Add/rename/remove an exported function, type, `Option`, or sentinel error** → update the
  *Project structure* / *How code is written* / *Domain* sections and the README's method tables.
- **Change resolution order or precedence** → update the *Precedence summary* table; consumers
  reason about env-vs-Keyring winner from it.
- **Change an env-var name** (`KEYRING_URL`, `KEYRING_ACCESS_KEY_ID`, `KEYRING_SECRET_ACCESS_KEY`,
  `KEYRING_SOURCE`) → update every table that lists them (NAMES only, never values).
- **Change the wire format or the `/secrets` contract** → co-ordinate with `keyring-api` and
  `keyring-js`; note it here.
- **Change the response cap, timeout default, or transport behaviour** → update *Stack &
  dependencies*.
- **Cut a release** → record the version and what changed in *Operations*. (The `/v1`
  install-path drift in `ci.yml` is already fixed; keep the snippet suffix-free until v2.)
- **Add a dependency** → update *Stack & dependencies* and say why the zero-dep posture changed.
