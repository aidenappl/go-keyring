# go-keyring

`go-keyring` is the official Go client for the Keyring API. It is intended for use in Go services that need to retrieve secrets at startup or on demand. All access is token-based — the service holds a `KEYRING_ACCESS_KEY_ID` and `KEYRING_SECRET_ACCESS_KEY` and uses them to fetch only the secrets it has been granted.

Module path: `github.com/aidenappl/go-keyring`

---

## Installation

```bash
go get github.com/aidenappl/go-keyring
```

---

## Authentication

The client authenticates via HTTP Basic Auth:

- **Username:** `KEYRING_ACCESS_KEY_ID`
- **Password:** `KEYRING_SECRET_ACCESS_KEY`

The Keyring API verifies credentials using constant-time comparison before returning secrets.

---

## Configuration

Credentials can be provided as environment variables or via explicit options:

| Environment variable        | Description                                    |
| --------------------------- | ---------------------------------------------- |
| `KEYRING_URL`               | Base URL of the Keyring API, no trailing slash |
| `KEYRING_ACCESS_KEY_ID`     | Token access key ID                            |
| `KEYRING_SECRET_ACCESS_KEY` | Token secret access key                        |

---

## Creating a Client

### `keyring.New(opts ...Option) (*Client, error)`

Reads credentials from environment variables by default. Returns an error if any required value is missing.

```go
// From environment variables
client, err := keyring.New()

// With explicit options
client, err := keyring.New(
    keyring.WithURL("https://keyring.example.com"),
    keyring.WithCredentials(accessKeyID, secretAccessKey),
    keyring.WithTimeout(5*time.Second),
)
```

---

## Methods

### `client.Load(ctx context.Context) (map[string]string, error)`

Fetches all secrets granted to the token and returns them as a `map[string]string` keyed by secret name. Values are decrypted by the API before transmission. Always makes a live HTTP call — cache the returned map yourself if you need repeated access.

```go
secrets, err := client.Load(ctx)
if err != nil {
    log.Fatal("failed to load secrets: ", err)
}

dsn := secrets["DATABASE_DSN"]
```

---

### `client.MustLoad() map[string]string`

Same as `Load` but uses `context.Background()` and panics on error. Intended for `main()` during service startup where a missing secret is fatal.

```go
secrets := client.MustLoad()
```

---

### `client.InjectEnv(ctx context.Context) error`

Calls `Load` and sets each secret as an environment variable via `os.Setenv`. Subsequent code can use `os.Getenv` or any env-reading config library as normal. Prints a sorted table of injected key names to stdout on success (values are never logged).

```go
if err := client.InjectEnv(ctx); err != nil {
    log.Fatal(err)
}

dsn := os.Getenv("DATABASE_DSN")
```

**Example output:**

```
keyring: injected environment variables
┌────────────────────────────────────────────────────┐
│ DATABASE_DSN                       (override)       │
│ STRIPE_API_KEY                                      │
└────────────────────────────────────────────────────┘
```

Keys that already existed in the local environment with a different value are marked `(override)`. Values are never printed.

---

### `client.Get(ctx context.Context, key string) (string, error)`

Fetches all secrets and returns the value for a single key. Returns an error if the key is not present. If the key is already set in the local environment with a different value, a message is printed to stdout noting the override. Prefer calling `Load` once at startup and caching the map when multiple keys are needed.

```go
apiKey, err := client.Get(ctx, "STRIPE_API_KEY")
```

---

### `keyring.Get(ctx context.Context, key string) (string, error)`

Package-level convenience — creates a client from environment variables and returns the value for a single key. Equivalent to `keyring.New()` followed by `client.Get()`.

```go
apiKey, err := keyring.Get(ctx, "STRIPE_API_KEY")
```

---

### `keyring.MustGet(key string) string`

Same as `keyring.Get` but uses `context.Background()` and panics on error. Intended for `main()` where a missing secret is fatal.

```go
apiKey := keyring.MustGet("STRIPE_API_KEY")
```

---

## Typical Usage

### Inject all secrets into the environment at startup

The recommended pattern for most services — call `InjectEnv` once before any other initialisation. All secrets are then available via `os.Getenv` for the lifetime of the process.

```go
package main

import (
    "context"
    "log"
    "os"

    keyring "github.com/aidenappl/go-keyring"
)

func main() {
    client, err := keyring.New()
    if err != nil {
        log.Fatal("keyring: ", err)
    }

    if err := client.InjectEnv(context.Background()); err != nil {
        log.Fatal("keyring: failed to inject secrets: ", err)
    }

    // All secrets are now available as environment variables.
    dsn := os.Getenv("DATABASE_DSN")
    // ... start server using dsn
}
```

### Fetch a single secret inline

Use the package-level helpers when you only need one secret and don't want to manage a client:

```go
// Returns an error
apiKey, err := keyring.Get(ctx, "STRIPE_API_KEY")

// Panics on error — ideal for main() startup
apiKey := keyring.MustGet("STRIPE_API_KEY")
```

If a local environment variable with the same key already exists and has a different value, a notice is printed to stdout:

```
keyring: overriding local env var "STRIPE_API_KEY" with keyring secret
```

### Load all secrets into a map

Use `Load` or `MustLoad` when you need multiple secrets but prefer not to inject them into the process environment:

```go
secrets := client.MustLoad()

dsn := secrets["DATABASE_DSN"]
apiKey := secrets["STRIPE_API_KEY"]
```

---

## Options

| Option                               | Description                                       |
| ------------------------------------ | ------------------------------------------------- |
| `WithURL(url string)`                | Sets the base URL. Trailing slashes are stripped. |
| `WithCredentials(id, secret string)` | Sets credentials explicitly.                      |
| `WithTimeout(d time.Duration)`       | Overrides the default 10-second HTTP timeout.     |

---

## Error Handling

All methods return typed sentinel errors that can be inspected with `errors.Is` / `errors.As`:

| Error                          | Meaning                                                    |
| ------------------------------ | ---------------------------------------------------------- |
| `keyring.ErrUnauthorized`      | Credentials are invalid or the token is inactive (401/403) |
| `keyring.ErrUnavailable`       | The API could not be reached within the timeout            |
| `keyring.ErrMalformedResponse` | The API returned an unexpected or unparseable body         |

```go
secrets, err := client.Load(ctx)
if errors.Is(err, keyring.ErrUnauthorized) {
    log.Fatal("check your KEYRING_ACCESS_KEY_ID and KEYRING_SECRET_ACCESS_KEY")
}
if errors.Is(err, keyring.ErrUnavailable) {
    log.Fatal("keyring API is unreachable")
}
```

---

## Retry & Timeout Behaviour

- Default HTTP timeout: **10 seconds**
- The client does **not** retry automatically — if the Keyring API is unreachable the service should fail fast rather than start with missing secrets
- Override with `keyring.WithTimeout(d time.Duration)`

---

## Security Notes

- Pass credentials via environment variables, never bake them into configuration files or image layers.
- In Kubernetes, store the two credentials as a `Secret` and mount them as env vars.
- The package never caches secrets to disk. `Load` always makes a live HTTP call.
- Secret values are never printed or logged — `InjectEnv` outputs only key names.
- The secret access key is a 40-character URL-safe base64 string. Treat it with the same sensitivity as a private key.
