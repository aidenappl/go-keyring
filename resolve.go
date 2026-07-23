package keyring

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// SourceEnvVar selects where configuration is resolved from. Setting it to
// "env" skips the Keyring API entirely and reads only the process environment.
//
// Services set this in tests and CI so a test process can never pick up
// production secrets from a developer's configured Keyring.
const SourceEnvVar = "KEYRING_SOURCE"

// EnvOnly reports whether Keyring lookups are disabled via SourceEnvVar.
func EnvOnly() bool { return strings.EqualFold(os.Getenv(SourceEnvVar), "env") }

// Lookup resolves a configuration value, reporting whether it was found.
//
// Resolution order:
//
//  1. the process environment (so local development and tests can override, and
//     so a value already injected by InjectEnv is reused without a network call)
//  2. the Keyring API, when it is configured and EnvOnly() is false
//
// Unlike Get, a Keyring that is unreachable or unconfigured is not an error —
// Lookup simply reports the value as not found, which lets a service run purely
// from environment variables.
func Lookup(ctx context.Context, key string) (string, bool) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v, true
	}
	if EnvOnly() {
		return "", false
	}
	c, err := New()
	if err != nil {
		// Keyring is not configured in this environment; env is all we have.
		return "", false
	}
	v, err := c.Get(ctx, key)
	if err != nil || v == "" {
		return "", false
	}
	return v, true
}

// Resolve returns the value for key, or an error naming every source that was
// tried. Use it when a service wants to report a misconfiguration rather than
// panic.
func Resolve(ctx context.Context, key string) (string, error) {
	if v, ok := Lookup(ctx, key); ok {
		return v, nil
	}
	if EnvOnly() {
		return "", fmt.Errorf("keyring: %q not set in the environment (%s=env)", key, SourceEnvVar)
	}
	return "", fmt.Errorf("keyring: %q not found in the environment or Keyring", key)
}

// MustResolve returns the value for key and panics when it is absent from every
// source. Intended for service startup, where missing configuration is fatal.
//
// Prefer this over MustGet: it succeeds when the value is present in the
// environment even if the Keyring API is unreachable or unconfigured, which is
// the normal situation in tests and CI.
func MustResolve(key string) string {
	v, err := Resolve(context.Background(), key)
	if err != nil {
		panic(err)
	}
	return v
}

// ResolveOr returns the value for key, or fallback when it is not set anywhere.
// It never contacts Keyring when the value is already in the environment.
func ResolveOr(ctx context.Context, key, fallback string) string {
	if v, ok := Lookup(ctx, key); ok {
		return v
	}
	return fallback
}
