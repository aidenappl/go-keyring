package keyring

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestClient builds a Client pointed at url with fixed credentials. Options
// override any env vars, so a developer's real KEYRING_* environment cannot
// leak into these tests.
func newTestClient(t *testing.T, url string) *Client {
	t.Helper()
	c, err := New(
		WithURL(url),
		WithCredentials("test-id", "test-secret"),
	)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	return c
}

func TestLoad_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/secrets" {
			t.Errorf("path = %q, want /secrets", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":[{"key":"K1","value":"V1"},{"key":"K2","value":"V2"}]}`)
	}))
	defer srv.Close()

	secrets, err := newTestClient(t, srv.URL).Load(context.Background())
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}

	want := map[string]string{"K1": "V1", "K2": "V2"}
	if len(secrets) != len(want) {
		t.Fatalf("Load returned %d secrets, want %d", len(secrets), len(want))
	}
	for k, v := range want {
		if got := secrets[k]; got != v {
			t.Errorf("secrets[%q] = %q, want %q", k, got, v)
		}
	}
}

func TestLoad_SetsBasicAuthHeader(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("test-id:test-secret"))

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()

	if _, err := newTestClient(t, srv.URL).Load(context.Background()); err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

func TestLoad_ErrorMapping(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{}`, wantErr: ErrUnauthorized},
		{name: "forbidden", status: http.StatusForbidden, body: `{}`, wantErr: ErrUnauthorized},
		{name: "server error", status: http.StatusInternalServerError, body: `boom`, wantErr: ErrMalformedResponse},
		{name: "not found status", status: http.StatusNotFound, body: `nope`, wantErr: ErrMalformedResponse},
		{name: "unparseable body", status: http.StatusOK, body: `this is not json`, wantErr: ErrMalformedResponse},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()

			_, err := newTestClient(t, srv.URL).Load(context.Background())
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Load error = %v, want errors.Is(..., %v)", err, tc.wantErr)
			}
		})
	}
}

func TestLoad_NetworkErrorIsUnavailable(t *testing.T) {
	// Start then immediately close a server so the connection is refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := newTestClient(t, url).Load(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("Load error = %v, want errors.Is(..., ErrUnavailable)", err)
	}
}

func TestLoad_TimeoutIsUnavailable(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // hold the request open past the client timeout
	}))
	defer func() {
		close(block)
		srv.Close()
	}()

	c, err := New(
		WithURL(srv.URL),
		WithCredentials("test-id", "test-secret"),
		WithTimeout(20*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}

	if _, err := c.Load(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Load error = %v, want errors.Is(..., ErrUnavailable)", err)
	}
}

func TestNew_ValidatesRequiredFields(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		accessKeyID string
		secretKey   string
		wantInErr   string
	}{
		{name: "missing url", url: "", accessKeyID: "id", secretKey: "secret", wantInErr: "KEYRING_URL"},
		{name: "missing access key id", url: "https://keys.example.com", accessKeyID: "", secretKey: "secret", wantInErr: "KEYRING_ACCESS_KEY_ID"},
		{name: "missing secret key", url: "https://keys.example.com", accessKeyID: "id", secretKey: "", wantInErr: "KEYRING_SECRET_ACCESS_KEY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear the environment so the host machine's real KEYRING_*
			// values cannot satisfy a field we intend to leave empty.
			t.Setenv("KEYRING_URL", tc.url)
			t.Setenv("KEYRING_ACCESS_KEY_ID", tc.accessKeyID)
			t.Setenv("KEYRING_SECRET_ACCESS_KEY", tc.secretKey)

			_, err := New()
			if err == nil {
				t.Fatal("New: expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("New error = %q, want it to mention %q", err.Error(), tc.wantInErr)
			}
		})
	}
}

func TestNew_ValidConfigSucceeds(t *testing.T) {
	t.Setenv("KEYRING_URL", "")
	t.Setenv("KEYRING_ACCESS_KEY_ID", "")
	t.Setenv("KEYRING_SECRET_ACCESS_KEY", "")

	c, err := New(
		WithURL("https://keys.example.com/"),
		WithCredentials("id", "secret"),
	)
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	if c.url != "https://keys.example.com" {
		t.Errorf("url = %q, want trailing slash stripped", c.url)
	}
}

func TestInjectEnv_SetsProcessEnv(t *testing.T) {
	const (
		keyA = "KR_TEST_INJECT_A"
		keyB = "KR_TEST_INJECT_B"
	)
	// InjectEnv calls os.Setenv directly (not t.Setenv), so clean up by hand.
	t.Cleanup(func() {
		_ = os.Unsetenv(keyA)
		_ = os.Unsetenv(keyB)
	})
	_ = os.Unsetenv(keyA)
	_ = os.Unsetenv(keyB)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"data":[{"key":%q,"value":"aaa"},{"key":%q,"value":"bbb"}]}`, keyA, keyB)
	}))
	defer srv.Close()

	if err := newTestClient(t, srv.URL).InjectEnv(context.Background()); err != nil {
		t.Fatalf("InjectEnv: unexpected error: %v", err)
	}

	if got := os.Getenv(keyA); got != "aaa" {
		t.Errorf("os.Getenv(%q) = %q, want %q", keyA, got, "aaa")
	}
	if got := os.Getenv(keyB); got != "bbb" {
		t.Errorf("os.Getenv(%q) = %q, want %q", keyB, got, "bbb")
	}
}

func TestInjectEnv_PropagatesLoadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := newTestClient(t, srv.URL).InjectEnv(context.Background())
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("InjectEnv error = %v, want errors.Is(..., ErrUnauthorized)", err)
	}
}
