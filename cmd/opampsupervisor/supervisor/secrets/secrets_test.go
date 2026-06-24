// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newRunningStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(zap.NewNop())
	require.NoError(t, err)
	require.NoError(t, store.Start())
	t.Cleanup(func() { _ = store.Shutdown(context.Background()) })
	return store
}

func get(t *testing.T, endpoint, name, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, endpoint+"/"+name, http.NoBody)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func TestStoreServesSecret(t *testing.T) {
	store := newRunningStore(t)
	store.Set(map[string]string{"FOO": "BAR"})

	resp := get(t, store.Endpoint(), "FOO", store.Token())
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var sv secretValueResponse
	require.NoError(t, json.Unmarshal(body, &sv))
	assert.Equal(t, "BAR", sv.Value)
}

func TestStoreNotFound(t *testing.T) {
	store := newRunningStore(t)
	store.Set(map[string]string{"FOO": "BAR"})

	resp := get(t, store.Endpoint(), "MISSING", store.Token())
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestStoreBadToken(t *testing.T) {
	store := newRunningStore(t)
	store.Set(map[string]string{"FOO": "BAR"})

	resp := get(t, store.Endpoint(), "FOO", "wrong-token")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestStoreMissingToken(t *testing.T) {
	store := newRunningStore(t)
	store.Set(map[string]string{"FOO": "BAR"})

	resp := get(t, store.Endpoint(), "FOO", "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestStoreSetReplaces(t *testing.T) {
	store := newRunningStore(t)
	store.Set(map[string]string{"FOO": "BAR"})
	store.Set(map[string]string{"BAZ": "QUX"})

	resp := get(t, store.Endpoint(), "FOO", store.Token())
	resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	resp = get(t, store.Endpoint(), "BAZ", store.Token())
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTokenIsRandom(t *testing.T) {
	s1, err := NewStore(zap.NewNop())
	require.NoError(t, err)
	s2, err := NewStore(zap.NewNop())
	require.NoError(t, err)
	assert.NotEqual(t, s1.Token(), s2.Token())
	assert.NotEmpty(t, s1.Token())
}

func TestParsePayload(t *testing.T) {
	m, err := ParsePayload([]byte(`{"secrets":{"a":"1","b":"2"}}`))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a": "1", "b": "2"}, m)
}

func TestParsePayloadInvalid(t *testing.T) {
	_, err := ParsePayload([]byte(`not json`))
	assert.Error(t, err)
}
