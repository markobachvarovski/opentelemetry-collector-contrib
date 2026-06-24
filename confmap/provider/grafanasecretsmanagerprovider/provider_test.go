// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package grafanasecretsmanagerprovider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const testToken = "test-token"

// newTestServer returns an httptest server that mimics the supervisor's
// loopback secrets endpoint, serving the given name->value map and enforcing
// the bearer token.
func newTestServer(t *testing.T, secrets map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		value, ok := secrets[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(secretResponse{Value: value})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestProvider(t *testing.T, endpoint, token string) (confmap.Provider, *observer.ObservedLogs) {
	t.Helper()
	if endpoint != "" {
		t.Setenv(endpointEnvVar, endpoint)
	}
	if token != "" {
		t.Setenv(tokenEnvVar, token)
	}
	core, logs := observer.New(zapcore.DebugLevel)
	return NewFactory().Create(confmap.ProviderSettings{Logger: zap.New(core)}), logs
}

func TestFetchSecret(t *testing.T) {
	srv := newTestServer(t, map[string]string{"FOO": "BAR"})
	fp, _ := newTestProvider(t, srv.URL, testToken)

	result, err := fp.Retrieve(t.Context(), "grafanasecretsmanager:FOO", nil)
	require.NoError(t, err)
	require.NoError(t, fp.Shutdown(t.Context()))

	value, err := result.AsRaw()
	require.NoError(t, err)
	assert.Equal(t, "BAR", value)
}

func TestFetchSecretIgnoreDefault(t *testing.T) {
	srv := newTestServer(t, map[string]string{"FOO": "BAR"})
	fp, _ := newTestProvider(t, srv.URL, testToken)

	result, err := fp.Retrieve(t.Context(), "grafanasecretsmanager:FOO:-defaultValue", nil)
	require.NoError(t, err)

	value, err := result.AsRaw()
	require.NoError(t, err)
	assert.Equal(t, "BAR", value)
}

func TestFetchSecretNotFoundWithDefault(t *testing.T) {
	srv := newTestServer(t, map[string]string{})
	fp, _ := newTestProvider(t, srv.URL, testToken)

	result, err := fp.Retrieve(t.Context(), "grafanasecretsmanager:MISSING:-defaultValue", nil)
	require.NoError(t, err)

	value, err := result.AsRaw()
	require.NoError(t, err)
	assert.Equal(t, "defaultValue", value)
}

func TestFetchSecretNotFoundNoDefault(t *testing.T) {
	srv := newTestServer(t, map[string]string{})
	fp, _ := newTestProvider(t, srv.URL, testToken)

	_, err := fp.Retrieve(t.Context(), "grafanasecretsmanager:MISSING", nil)
	assert.Error(t, err)
}

func TestEmptyNameWithDefault(t *testing.T) {
	srv := newTestServer(t, map[string]string{})
	fp, _ := newTestProvider(t, srv.URL, testToken)

	result, err := fp.Retrieve(t.Context(), "grafanasecretsmanager::-defaultValue", nil)
	require.NoError(t, err)

	value, err := result.AsRaw()
	require.NoError(t, err)
	assert.Equal(t, "defaultValue", value)
}

func TestEmptyNameNoDefault(t *testing.T) {
	srv := newTestServer(t, map[string]string{})
	fp, _ := newTestProvider(t, srv.URL, testToken)

	_, err := fp.Retrieve(t.Context(), "grafanasecretsmanager:", nil)
	assert.Error(t, err)
}

func TestUnsupportedScheme(t *testing.T) {
	fp, _ := newTestProvider(t, "http://127.0.0.1:0", testToken)
	_, err := fp.Retrieve(t.Context(), "other:FOO", nil)
	assert.Error(t, err)
}

func TestMissingEndpointEnv(t *testing.T) {
	fp, _ := newTestProvider(t, "", testToken)
	_, err := fp.Retrieve(t.Context(), "grafanasecretsmanager:FOO", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), endpointEnvVar)
}

func TestMissingTokenEnv(t *testing.T) {
	fp, _ := newTestProvider(t, "http://127.0.0.1:0", "")
	_, err := fp.Retrieve(t.Context(), "grafanasecretsmanager:FOO", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), tokenEnvVar)
}

func TestBadToken(t *testing.T) {
	srv := newTestServer(t, map[string]string{"FOO": "BAR"})
	fp, _ := newTestProvider(t, srv.URL, "wrong-token")

	_, err := fp.Retrieve(t.Context(), "grafanasecretsmanager:FOO", nil)
	assert.Error(t, err)
}

// TestSecretNotLogged ensures the secret value and the auth token never appear
// in the provider's logs.
func TestSecretNotLogged(t *testing.T) {
	const secret = "super-secret-value"
	srv := newTestServer(t, map[string]string{"FOO": secret})
	fp, logs := newTestProvider(t, srv.URL, testToken)

	// Successful retrieval and a fallback (which logs a warning) to exercise the
	// logging paths.
	_, err := fp.Retrieve(t.Context(), "grafanasecretsmanager:FOO", nil)
	require.NoError(t, err)
	_, err = fp.Retrieve(t.Context(), "grafanasecretsmanager:MISSING:-fallback", nil)
	require.NoError(t, err)

	for _, entry := range logs.All() {
		line := entry.Message
		for k, v := range entry.ContextMap() {
			line += " " + k + "=" + toString(v)
		}
		assert.NotContains(t, line, secret)
		assert.NotContains(t, line, testToken)
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestFactory(t *testing.T) {
	p := NewFactory().Create(confmap.ProviderSettings{Logger: zap.NewNop()})
	_, ok := p.(*provider)
	require.True(t, ok)
	assert.Equal(t, schemeName, p.Scheme())
}
