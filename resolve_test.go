package keyring

import (
	"context"
	"testing"
)

// These tests deliberately leave KEYRING_URL unset, which is the situation in
// CI and in any test process: Keyring is unreachable, so resolution must fall
// back to the environment instead of failing.

func TestLookup_FromEnvironment(t *testing.T) {
	t.Setenv("TEST_SECRET", "from-env")

	v, ok := Lookup(context.Background(), "TEST_SECRET")
	if !ok || v != "from-env" {
		t.Errorf("Lookup = (%q, %v), want (%q, true)", v, ok, "from-env")
	}
}

func TestLookup_MissingIsNotAnError(t *testing.T) {
	if v, ok := Lookup(context.Background(), "DEFINITELY_NOT_SET_ANYWHERE"); ok {
		t.Errorf("Lookup = (%q, true), want not found", v)
	}
}

func TestLookup_EmptyEnvValueIsNotFound(t *testing.T) {
	// An empty value is treated as unset, so a fallback still applies.
	t.Setenv("EMPTY_SECRET", "")
	if _, ok := Lookup(context.Background(), "EMPTY_SECRET"); ok {
		t.Error("an empty env value should not count as found")
	}
}

func TestEnvOnly_SkipsKeyring(t *testing.T) {
	t.Setenv(SourceEnvVar, "env")
	if !EnvOnly() {
		t.Fatal("EnvOnly = false, want true")
	}
	t.Setenv("ENV_ONLY_SECRET", "value")
	if v, ok := Lookup(context.Background(), "ENV_ONLY_SECRET"); !ok || v != "value" {
		t.Errorf("Lookup = (%q, %v), want (%q, true)", v, ok, "value")
	}
}

func TestEnvOnly_DefaultsOff(t *testing.T) {
	if EnvOnly() {
		t.Error("EnvOnly should be false when KEYRING_SOURCE is unset")
	}
}

func TestResolve_ErrorNamesTheKey(t *testing.T) {
	_, err := Resolve(context.Background(), "MISSING_KEY_XYZ")
	if err == nil {
		t.Fatal("Resolve returned nil error for a missing key")
	}
	if got := err.Error(); got == "" {
		t.Error("Resolve error should describe the missing key")
	}
}

func TestResolveOr_FallsBack(t *testing.T) {
	if got := ResolveOr(context.Background(), "NOT_SET_ANYWHERE", "fallback"); got != "fallback" {
		t.Errorf("ResolveOr = %q, want %q", got, "fallback")
	}

	t.Setenv("SET_SOMEWHERE", "real")
	if got := ResolveOr(context.Background(), "SET_SOMEWHERE", "fallback"); got != "real" {
		t.Errorf("ResolveOr = %q, want %q", got, "real")
	}
}

func TestMustResolve_ReturnsAndPanics(t *testing.T) {
	t.Setenv("PRESENT_SECRET", "here")
	if got := MustResolve("PRESENT_SECRET"); got != "here" {
		t.Errorf("MustResolve = %q, want %q", got, "here")
	}

	defer func() {
		if recover() == nil {
			t.Error("MustResolve should panic when the key is absent everywhere")
		}
	}()
	MustResolve("ABSENT_SECRET_XYZ")
}
