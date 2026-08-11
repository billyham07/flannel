// Copyright 2026 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudflaremesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
)

const warpStatusPollInterval = 500 * time.Millisecond

type commandExecutor interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type osCommandExecutor struct{}

func (osCommandExecutor) Run(ctx context.Context, name string, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

type warpClient struct {
	cliPath      string
	cliArgs      []string
	stateFile    string
	connectWait  time.Duration
	pollInterval time.Duration
	executor     commandExecutor
}

type warpState struct {
	ConnectorID   string `json:"connector_id"`
	ConnectorName string `json:"connector_name"`
}

func newWARPClient(cfg *runtimeConfig) *warpClient {
	return &warpClient{
		cliPath:      cfg.WARPCLI,
		cliArgs:      append([]string(nil), cfg.WARPCLIArgs...),
		stateFile:    cfg.StateFile,
		connectWait:  cfg.ConnectWait,
		pollInterval: warpStatusPollInterval,
		executor:     osCommandExecutor{},
	}
}

func (w *warpClient) EnsureRegisteredAndConnected(ctx context.Context, connector *meshapi.ConnectorCredentials, adoptExisting bool) error {
	if connector == nil || connector.ID == "" || connector.Token == "" {
		return errors.New("Cloudflare Mesh connector ID and token are required")
	}

	state, stateErr := w.readState()
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return stateErr
	}
	if state != nil && state.ConnectorID != connector.ID {
		return fmt.Errorf("WARP state belongs to connector %s, refusing to replace it with %s", state.ConnectorID, connector.ID)
	}

	status, statusErr := w.status(ctx)
	registered := statusErr == nil && warpStatusIsRegistered(status)
	if state == nil && registered {
		if !adoptExisting {
			return errors.New("WARP is already registered but has no flannel connector state; set AdoptExistingRegistration to adopt it")
		}
		if err := w.writeState(&warpState{ConnectorID: connector.ID, ConnectorName: connector.Name}); err != nil {
			return err
		}
		state = &warpState{ConnectorID: connector.ID, ConnectorName: connector.Name}
	}

	if !registered {
		output, err := w.run(ctx, "--accept-tos", "connector", "new", connector.Token)
		if err != nil {
			output = strings.ReplaceAll(output, connector.Token, "[REDACTED]")
			return fmt.Errorf("register WARP connector %s: %w: %s", connector.ID, err, output)
		}
		if err := w.writeState(&warpState{ConnectorID: connector.ID, ConnectorName: connector.Name}); err != nil {
			return err
		}
	}

	if _, err := w.run(ctx, "--accept-tos", "connect"); err != nil {
		return fmt.Errorf("connect Cloudflare One Client: %w", err)
	}
	return w.waitConnected(ctx)
}

func (w *warpClient) waitConnected(ctx context.Context) error {
	waitCtx, cancel := context.WithTimeout(ctx, w.connectWait)
	defer cancel()

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()
	for {
		status, err := w.status(waitCtx)
		if err == nil && warpStatusIsConnected(status) {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("wait for Cloudflare One Client connection: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (w *warpClient) status(ctx context.Context) (string, error) {
	return w.run(ctx, "--accept-tos", "status")
}

func (w *warpClient) run(ctx context.Context, args ...string) (string, error) {
	commandArgs := append(append([]string(nil), w.cliArgs...), args...)
	return w.executor.Run(ctx, w.cliPath, commandArgs...)
}

func warpStatusIsRegistered(status string) bool {
	lower := strings.ToLower(status)
	return strings.Contains(lower, "status update:") &&
		!strings.Contains(lower, "registration missing") &&
		!strings.Contains(lower, "not registered")
}

func warpStatusIsConnected(status string) bool {
	return strings.Contains(strings.ToLower(status), "status update: connected")
}

func (w *warpClient) readState() (*warpState, error) {
	contents, err := os.ReadFile(w.stateFile)
	if err != nil {
		return nil, err
	}
	var state warpState
	if err := json.Unmarshal(contents, &state); err != nil {
		return nil, fmt.Errorf("decode WARP state file %q: %w", w.stateFile, err)
	}
	if state.ConnectorID == "" {
		return nil, fmt.Errorf("WARP state file %q has no connector ID", w.stateFile)
	}
	return &state, nil
}

func (w *warpClient) writeState(state *warpState) error {
	dir := filepath.Dir(w.stateFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create WARP state directory %q: %w", dir, err)
	}
	temp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return fmt.Errorf("create temporary WARP state file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return fmt.Errorf("protect temporary WARP state file: %w", err)
	}
	if err := json.NewEncoder(temp).Encode(state); err != nil {
		temp.Close()
		return fmt.Errorf("encode WARP state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary WARP state file: %w", err)
	}
	if err := os.Rename(tempName, w.stateFile); err != nil {
		return fmt.Errorf("commit WARP state file %q: %w", w.stateFile, err)
	}
	return nil
}
