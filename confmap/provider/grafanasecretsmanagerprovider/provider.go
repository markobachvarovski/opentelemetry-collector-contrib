// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate mdatagen metadata.yaml

package grafanasecretsmanagerprovider // import "github.com/open-telemetry/opentelemetry-collector-contrib/confmap/provider/grafanasecretsmanagerprovider"

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap"
)

const (
	schemeName = "grafanasecretsmanager"

	// endpointEnvVar is the loopback URL of the secrets endpoint exposed by the
	// OpAMP supervisor (e.g. http://127.0.0.1:<port>). The supervisor injects it
	// into the collector process environment.
	endpointEnvVar = "GRAFANA_SECRETS_MANAGER_ENDPOINT"
	// tokenEnvVar is the per-run bearer token used to authenticate to the
	// supervisor's loopback secrets endpoint. Injected by the supervisor. It
	// gates access by other local processes that can reach the loopback port but
	// were not given the token.
	tokenEnvVar = "GRAFANA_SECRETS_MANAGER_TOKEN"

	defaultTimeout = 10 * time.Second
)

// secretResponse is the JSON body returned by the supervisor's secrets endpoint
// for a single secret.
type secretResponse struct {
	Value string `json:"value"`
}

type provider struct {
	client   *http.Client
	endpoint string
	token    string
	logger   *zap.Logger
}

// NewFactory returns a new confmap.ProviderFactory that creates a
// confmap.Provider which reads secrets referenced as
// `${grafanasecretsmanager:<secret_name>}`.
//
// Values are not fetched from a remote server directly. Instead they are read
// from a loopback endpoint exposed by the OpAMP supervisor, which brokers the
// secrets from Grafana Fleet Management. The endpoint and a per-run bearer token
// are provided via the GRAFANA_SECRETS_MANAGER_ENDPOINT and
// GRAFANA_SECRETS_MANAGER_TOKEN environment variables (injected by the
// supervisor) because a confmap provider cannot read the collector
// configuration for its own settings.
//
// A default value can be provided after a `:-` suffix, for example:
// `grafanasecretsmanager:<secret_name>:-default_value`. The default is used
// when the selector is empty or the secret is not found.
func NewFactory() confmap.ProviderFactory {
	return confmap.NewProviderFactory(newProvider)
}

func newProvider(ps confmap.ProviderSettings) confmap.Provider {
	return &provider{logger: ps.Logger}
}

func (p *provider) Retrieve(ctx context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if !strings.HasPrefix(uri, schemeName+":") {
		return nil, fmt.Errorf("%q uri is not supported by %q provider", uri, schemeName)
	}

	spec := strings.TrimPrefix(uri, schemeName+":")
	// split by :- to get the optional default value
	name, defaultValue, hasDefaultValue := strings.Cut(spec, ":-")

	if name == "" {
		if hasDefaultValue {
			p.logger.Warn("secret name is empty, falling back to default value")
			return confmap.NewRetrieved(defaultValue)
		}
		return nil, fmt.Errorf("%q provider requires a non-empty secret name", schemeName)
	}

	if err := p.init(); err != nil {
		return nil, err
	}

	value, found, err := p.fetch(ctx, name)
	if err != nil {
		return nil, err
	}
	if !found {
		if hasDefaultValue {
			p.logger.Warn("secret not found, falling back to default value", zap.String("secret", name))
			return confmap.NewRetrieved(defaultValue)
		}
		return nil, fmt.Errorf("secret %q not found", name)
	}

	return confmap.NewRetrieved(value)
}

// init lazily reads the configuration from the environment and builds the HTTP
// client on the first Retrieve call.
func (p *provider) init() error {
	if p.client != nil {
		return nil
	}

	endpoint, ok := os.LookupEnv(endpointEnvVar)
	if !ok || endpoint == "" {
		return fmt.Errorf("environment variable %q is not set", endpointEnvVar)
	}
	token, ok := os.LookupEnv(tokenEnvVar)
	if !ok || token == "" {
		return fmt.Errorf("environment variable %q is not set", tokenEnvVar)
	}

	p.endpoint = strings.TrimRight(endpoint, "/")
	p.token = token
	p.client = &http.Client{Timeout: defaultTimeout}
	return nil
}

// fetch retrieves a single secret by name from the supervisor's loopback
// endpoint. The returned bool reports whether the secret exists.
func (p *provider) fetch(ctx context.Context, name string) (string, bool, error) {
	reqURL := p.endpoint + "/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return "", false, fmt.Errorf("failed to build request for secret %q: %w", name, err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		// Do not wrap with details that could include the token/URL credentials.
		return "", false, fmt.Errorf("failed to request secret %q: %w", name, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return "", false, fmt.Errorf("failed to read response for secret %q: %w", name, err)
		}
		var sr secretResponse
		if err := json.Unmarshal(body, &sr); err != nil {
			return "", false, fmt.Errorf("failed to decode response for secret %q: %w", name, err)
		}
		return sr.Value, true, nil
	case http.StatusNotFound:
		return "", false, nil
	default:
		// Never log or wrap the response body: it may echo sensitive data.
		return "", false, fmt.Errorf("unexpected status %d retrieving secret %q", resp.StatusCode, name)
	}
}

func (*provider) Scheme() string {
	return schemeName
}

func (p *provider) Shutdown(context.Context) error {
	if p.client != nil {
		p.client.CloseIdleConnections()
	}
	return nil
}
