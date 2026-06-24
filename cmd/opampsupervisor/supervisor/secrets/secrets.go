// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package secrets implements the OpAMP supervisor's secrets broker: an
// in-memory cache of secrets pushed by the OpAMP/Fleet Management server, served
// to the managed collector over a loopback HTTP endpoint. The collector's
// grafanasecretsmanager confmap provider reads secrets from this endpoint so the
// collector never contacts the secrets server directly.
package secrets

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// CapabilityName is the OpAMP custom capability the supervisor advertises so
	// the server knows it may push secrets to this agent. Per the OpAMP spec, a
	// custom capability is "a reverse FQDN with optional version information that
	// uniquely identifies the custom capability". This capability is defined by
	// Grafana Fleet Management, so it uses Grafana's reverse FQDN.
	CapabilityName = "com.grafana.fleetmanagement.secrets.v1"

	// EndpointEnvVar and TokenEnvVar are injected into the collector process so
	// the grafanasecretsmanager confmap provider can reach this broker. Their
	// names must match the provider's expectations.
	EndpointEnvVar = "GRAFANA_SECRETS_MANAGER_ENDPOINT"
	TokenEnvVar    = "GRAFANA_SECRETS_MANAGER_TOKEN"

	readHeaderTimeout = 5 * time.Second
)

// payload is the JSON body of a secrets custom message:
// {"secrets": {"<name>": "<value>", ...}}.
type payload struct {
	Secrets map[string]string `json:"secrets"`
}

// ParsePayload decodes a secrets custom message body into a name->value map.
func ParsePayload(data []byte) (map[string]string, error) {
	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to decode secrets payload: %w", err)
	}
	return p.Secrets, nil
}

// secretValueResponse is the JSON body returned for a single secret lookup.
type secretValueResponse struct {
	Value string `json:"value"`
}

// Store caches secrets in memory and serves them over a loopback HTTP endpoint
// protected by a per-run bearer token. Secrets are never written to disk.
type Store struct {
	logger *zap.Logger

	mu      sync.RWMutex
	secrets map[string]string

	token    string
	listener net.Listener
	server   *http.Server
}

// NewStore creates a Store with a freshly generated bearer token.
func NewStore(logger *zap.Logger) (*Store, error) {
	token, err := generateToken()
	if err != nil {
		return nil, err
	}
	return &Store{
		logger:  logger,
		secrets: map[string]string{},
		token:   token,
	}, nil
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secrets token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Start binds a loopback listener and begins serving. It returns once the
// listener is open; requests are handled in a background goroutine.
func (s *Store) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start secrets server: %w", err)
	}
	s.listener = ln
	s.server = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("Secrets server stopped unexpectedly", zap.Error(err))
		}
	}()
	return nil
}

// Endpoint returns the base URL the collector provider should use.
func (s *Store) Endpoint() string {
	if s.listener == nil {
		return ""
	}
	return "http://" + s.listener.Addr().String()
}

// Token returns the per-run bearer token.
func (s *Store) Token() string {
	return s.token
}

// Set replaces the cached secrets with the given set.
func (s *Store) Set(secrets map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = secrets
}

// Get returns the cached value for a secret name.
func (s *Store) Get(name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.secrets[name]
	return v, ok
}

// ServeHTTP handles GET /{name} requests, returning the secret value as JSON.
func (s *Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Constant-time comparison to avoid leaking the token via timing.
	authz := r.Header.Get("Authorization")
	expected := "Bearer " + s.token
	if subtle.ConstantTimeCompare([]byte(authz), []byte(expected)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	value, ok := s.Get(name)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// Never log the secret value.
	_ = json.NewEncoder(w).Encode(secretValueResponse{Value: value})
}

// Shutdown stops the HTTP server.
func (s *Store) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}
