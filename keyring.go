// Package keyring is the official Go client for the Keyring API.
// It retrieves secrets over HTTP Basic Auth and can inject them into the
// process environment.
package keyring

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// maxResponseBytes caps how many bytes are read from the API response to
// prevent memory exhaustion from unexpectedly large or malicious payloads.
const maxResponseBytes = 32 << 20 // 32 MiB

// Client holds the configuration required to communicate with the Keyring API.
type Client struct {
	url             string
	accessKeyID     string
	secretAccessKey string
	http            *http.Client
}

// Option is a functional option for configuring a Client.
type Option func(*Client)

// WithURL sets the base URL of the Keyring API. Any trailing slash is
// stripped automatically.
func WithURL(url string) Option {
	return func(c *Client) {
		c.url = strings.TrimRight(url, "/")
	}
}

// WithCredentials sets the access key ID and secret access key explicitly,
// overriding any values read from environment variables.
func WithCredentials(accessKeyID, secretAccessKey string) Option {
	return func(c *Client) {
		c.accessKeyID = accessKeyID
		c.secretAccessKey = secretAccessKey
	}
}

// WithTimeout sets the HTTP timeout used for all requests. The default is
// 10 seconds.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.http.Timeout = d
	}
}

// New creates and returns a new Client. Credentials are read from the
// environment variables KEYRING_URL, KEYRING_ACCESS_KEY_ID, and
// KEYRING_SECRET_ACCESS_KEY unless overridden by options.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		url:             strings.TrimRight(os.Getenv("KEYRING_URL"), "/"),
		accessKeyID:     os.Getenv("KEYRING_ACCESS_KEY_ID"),
		secretAccessKey: os.Getenv("KEYRING_SECRET_ACCESS_KEY"),
		http:            &http.Client{Timeout: 10 * time.Second},
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.url == "" {
		return nil, fmt.Errorf("keyring: KEYRING_URL is required (set env var or use WithURL)")
	}
	if c.accessKeyID == "" {
		return nil, fmt.Errorf("keyring: KEYRING_ACCESS_KEY_ID is required (set env var or use WithCredentials)")
	}
	if c.secretAccessKey == "" {
		return nil, fmt.Errorf("keyring: KEYRING_SECRET_ACCESS_KEY is required (set env var or use WithCredentials)")
	}

	return c, nil
}

// secret is the wire format of a single secret returned by the API.
type secret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// secretsResponse is the envelope the API wraps secrets in.
type secretsResponse struct {
	Data []secret `json:"data"`
}

// Load fetches all secrets granted to the token and returns them as a
// map[string]string keyed by each secret's key field. The values are
// decrypted by the API before transmission.
//
// Load always makes a live HTTP call; cache the returned map yourself if you
// need repeated access without repeated network calls.
func (c *Client) Load(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/secrets", nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build request: %w", ErrUnavailable, err)
	}
	req.SetBasicAuth(c.accessKeyID, c.secretAccessKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() {
		// Drain before close so the underlying TCP connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		// handled below
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrUnauthorized
	default:
		return nil, fmt.Errorf("%w: unexpected status %d", ErrMalformedResponse, resp.StatusCode)
	}

	var payload secretsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}

	result := make(map[string]string, len(payload.Data))
	for _, s := range payload.Data {
		result[s.Key] = s.Value
	}
	return result, nil
}

// MustLoad calls Load and panics if an error occurs. It is intended for use
// during service startup where a missing secret is a fatal condition.
func (c *Client) MustLoad() map[string]string {
	secrets, err := c.Load(context.Background())
	if err != nil {
		panic(err)
	}
	return secrets
}

// InjectEnv calls Load and sets each returned secret as an environment
// variable via os.Setenv. Subsequent code can use os.Getenv or any
// env-reading config library as if the variables had been set natively.
// It prints a sorted table of injected key names to stdout. Keys that
// replace an existing local env var are marked (override).
func (c *Client) InjectEnv(ctx context.Context) error {
	secrets, err := c.Load(ctx)
	if err != nil {
		return err
	}

	overridden := make(map[string]bool, len(secrets))
	for k, v := range secrets {
		if existing := os.Getenv(k); existing != "" && existing != v {
			overridden[k] = true
		}
		if err := os.Setenv(k, v); err != nil {
			return fmt.Errorf("keyring: failed to set env var %q: %w", k, err)
		}
	}

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Println("keyring: injected environment variables")
	fmt.Println("┌──────────────────────────────────────────────────┐")
	for _, k := range keys {
		tag := "          "
		if overridden[k] {
			tag = "(override)"
		}
		fmt.Printf("│ %-35s %s │\n", k, tag)
	}
	fmt.Println("└──────────────────────────────────────────────────┘")

	return nil
}

// Get returns the value for key. If the key is already set in the local
// environment, that value is returned immediately without contacting the
// Keyring API and a notice is printed to stdout. Otherwise the secret is
// fetched from the API.
//
// Prefer calling Load once at startup and caching the map when multiple keys
// are needed.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	if local := os.Getenv(key); local != "" {
		fmt.Printf("keyring: using local env var %q (keyring lookup skipped)\n", key)
		return local, nil
	}
	secrets, err := c.Load(ctx)
	if err != nil {
		return "", err
	}
	value, ok := secrets[key]
	if !ok {
		return "", fmt.Errorf("keyring: secret %q not found", key)
	}
	return value, nil
}

// Get is a package-level convenience that creates a Client from environment
// variables and returns the keyring value for key. It is equivalent to:
//
//	client, err := keyring.New()
//	value, err := client.Get(ctx, key)
func Get(ctx context.Context, key string) (string, error) {
	c, err := New()
	if err != nil {
		return "", err
	}
	return c.Get(ctx, key)
}

// MustGet is a package-level convenience that creates a Client from
// environment variables and returns the keyring value for key. It panics on
// any error. Intended for use in main() where a missing secret is fatal.
func MustGet(key string) string {
	value, err := Get(context.Background(), key)
	if err != nil {
		panic(err)
	}
	return value
}

// GetOr returns the keyring value for key, or fallback if the key is absent
// or any error occurs.
func (c *Client) GetOr(ctx context.Context, key, fallback string) string {
	v, err := c.Get(ctx, key)
	if err != nil {
		return fallback
	}
	return v
}

// GetOr is a package-level convenience that creates a Client from environment
// variables and returns the keyring value for key, or fallback if the key is
// absent or any error occurs.
func GetOr(ctx context.Context, key, fallback string) string {
	v, err := Get(ctx, key)
	if err != nil {
		return fallback
	}
	return v
}
