package keyring

import "errors"

// Sentinel errors returned by Client methods.
var (
	// ErrUnauthorized is returned when the API responds with 401 or 403,
	// indicating the credentials are invalid or the token is inactive.
	ErrUnauthorized = errors.New("keyring: unauthorized — credentials invalid or token inactive")

	// ErrUnavailable is returned when the Keyring API cannot be reached
	// within the configured timeout.
	ErrUnavailable = errors.New("keyring: API unavailable")

	// ErrMalformedResponse is returned when the API returns a response body
	// that cannot be parsed.
	ErrMalformedResponse = errors.New("keyring: malformed response from API")
)
