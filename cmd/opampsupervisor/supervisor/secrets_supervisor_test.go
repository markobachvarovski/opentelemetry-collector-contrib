// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/protobufs"
	serverTypes "github.com/open-telemetry/opamp-go/server/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/cmd/opampsupervisor/supervisor/config"
	"github.com/open-telemetry/opentelemetry-collector-contrib/cmd/opampsupervisor/supervisor/secrets"
)

func newRunningSecretsStore(t *testing.T) *secrets.Store {
	t.Helper()
	store, err := secrets.NewStore(zap.NewNop())
	require.NoError(t, err)
	require.NoError(t, store.Start())
	t.Cleanup(func() { _ = store.Shutdown(context.Background()) })
	return store
}

func TestOnMessageSecretsIntercepted(t *testing.T) {
	store := newRunningSecretsStore(t)
	testUUID := uuid.MustParse("018fee23-4a51-7303-a441-73faed7d9deb")

	forwarded := false
	agentConn := &atomic.Value{}
	agentConn.Store(serverTypes.Connection(&mockConn{
		sendFunc: func(context.Context, *protobufs.ServerToAgent) error {
			forwarded = true
			return nil
		},
	}))

	s := Supervisor{
		telemetrySettings:              newNopTelemetrySettings(),
		pidProvider:                    defaultPIDProvider{},
		config:                         config.Supervisor{Secrets: config.Secrets{Enabled: true}},
		hasNewConfig:                   make(chan struct{}, 1),
		persistentState:                &persistentState{InstanceID: testUUID},
		agentConfigOwnTelemetrySection: &atomic.Value{},
		cfgState:                       &atomic.Value{},
		effectiveConfig:                &atomic.Value{},
		agentConn:                      agentConn,
		customMessageToServer:          make(chan *protobufs.CustomMessage, 10),
		doneChan:                       make(chan struct{}),
		secretsStore:                   store,
	}

	s.onMessage(t.Context(), &types.MessageData{
		CustomMessage: &protobufs.CustomMessage{
			Capability: secrets.CapabilityName,
			Type:       "secrets",
			Data:       []byte(`{"secrets":{"FOO":"BAR"}}`),
		},
	})

	// Secret is cached and the message is NOT forwarded to the collector.
	value, ok := store.Get("FOO")
	require.True(t, ok)
	assert.Equal(t, "BAR", value)
	assert.False(t, forwarded, "secrets message must not be forwarded to the agent")
}

func TestOnMessageNonSecretsForwardedWhenEnabled(t *testing.T) {
	store := newRunningSecretsStore(t)
	testUUID := uuid.MustParse("018fee23-4a51-7303-a441-73faed7d9deb")

	customMessage := &protobufs.CustomMessage{Capability: "teapot", Type: "brew", Data: []byte("chamomile")}
	forwarded := false
	agentConn := &atomic.Value{}
	agentConn.Store(serverTypes.Connection(&mockConn{
		sendFunc: func(_ context.Context, message *protobufs.ServerToAgent) error {
			require.Equal(t, customMessage, message.CustomMessage)
			forwarded = true
			return nil
		},
	}))

	s := Supervisor{
		telemetrySettings:              newNopTelemetrySettings(),
		pidProvider:                    defaultPIDProvider{},
		config:                         config.Supervisor{Secrets: config.Secrets{Enabled: true}},
		hasNewConfig:                   make(chan struct{}, 1),
		persistentState:                &persistentState{InstanceID: testUUID},
		agentConfigOwnTelemetrySection: &atomic.Value{},
		cfgState:                       &atomic.Value{},
		effectiveConfig:                &atomic.Value{},
		agentConn:                      agentConn,
		customMessageToServer:          make(chan *protobufs.CustomMessage, 10),
		doneChan:                       make(chan struct{}),
		secretsStore:                   store,
	}

	s.onMessage(t.Context(), &types.MessageData{CustomMessage: customMessage})

	assert.True(t, forwarded, "non-secrets custom message should still be forwarded")
	_, ok := store.Get("teapot")
	assert.False(t, ok, "non-secrets message must not populate the secrets cache")
}

func TestSetCustomCapabilitiesMergesSecrets(t *testing.T) {
	var captured *protobufs.CustomCapabilities
	mockClient := mockOpAMPClient{
		setCustomCapabilitiesFunc: func(caps *protobufs.CustomCapabilities) error {
			captured = caps
			return nil
		},
	}

	t.Run("enabled merges with agent capabilities", func(t *testing.T) {
		captured = nil
		s := Supervisor{
			telemetrySettings: newNopTelemetrySettings(),
			config:            config.Supervisor{Secrets: config.Secrets{Enabled: true}},
			opampClient:       &mockClient,
		}
		require.NoError(t, s.setCustomCapabilities(&protobufs.CustomCapabilities{Capabilities: []string{"teapot"}}))
		require.NotNil(t, captured)
		assert.Contains(t, captured.Capabilities, "teapot")
		assert.Contains(t, captured.Capabilities, secrets.CapabilityName)
	})

	t.Run("enabled with nil agent capabilities sets only secrets", func(t *testing.T) {
		captured = nil
		s := Supervisor{
			telemetrySettings: newNopTelemetrySettings(),
			config:            config.Supervisor{Secrets: config.Secrets{Enabled: true}},
			opampClient:       &mockClient,
		}
		require.NoError(t, s.setCustomCapabilities(nil))
		require.NotNil(t, captured)
		assert.Equal(t, []string{secrets.CapabilityName}, captured.Capabilities)
	})

	t.Run("disabled leaves agent capabilities untouched", func(t *testing.T) {
		captured = nil
		s := Supervisor{
			telemetrySettings: newNopTelemetrySettings(),
			config:            config.Supervisor{Secrets: config.Secrets{Enabled: false}},
			opampClient:       &mockClient,
		}
		require.NoError(t, s.setCustomCapabilities(&protobufs.CustomCapabilities{Capabilities: []string{"teapot"}}))
		require.NotNil(t, captured)
		assert.Equal(t, []string{"teapot"}, captured.Capabilities)
		assert.NotContains(t, captured.Capabilities, secrets.CapabilityName)
	})
}
