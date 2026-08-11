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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
)

type recordedCommand struct {
	name string
	args []string
}

type fakeCommandExecutor struct {
	commands []recordedCommand
	statuses []string
}

func (f *fakeCommandExecutor) Run(_ context.Context, name string, args ...string) (string, error) {
	f.commands = append(f.commands, recordedCommand{name: name, args: append([]string(nil), args...)})
	if len(args) > 0 && args[len(args)-1] == "status" {
		if len(f.statuses) == 0 {
			return "Registration Missing", errors.New("not registered")
		}
		status := f.statuses[0]
		f.statuses = f.statuses[1:]
		return status, nil
	}
	return "", nil
}

func TestWARPRegistersAndConnects(t *testing.T) {
	executor := &fakeCommandExecutor{statuses: []string{
		"Registration Missing",
		"Status update: Connecting",
		"Status update: Connected\nNetwork: healthy",
	}}
	client := &warpClient{
		cliPath:      "warp-cli",
		stateFile:    filepath.Join(t.TempDir(), "state.json"),
		connectWait:  time.Second,
		pollInterval: time.Millisecond,
		executor:     executor,
	}
	connector := &meshapi.ConnectorCredentials{ID: "connector-1", Name: "node-a", Token: "token-1"}
	if err := client.EnsureRegisteredAndConnected(context.Background(), connector, false); err != nil {
		t.Fatal(err)
	}

	wantRegistration := []string{"--accept-tos", "connector", "new", "token-1"}
	if !hasCommand(executor.commands, wantRegistration) {
		t.Fatalf("registration command not executed: %#v", executor.commands)
	}
	state, err := client.readState()
	if err != nil {
		t.Fatal(err)
	}
	if state.ConnectorID != "connector-1" {
		t.Fatalf("unexpected state: %#v", state)
	}
	info, err := os.Stat(client.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("state file is too permissive: %o", info.Mode().Perm())
	}
}

func TestWARPRefusesUntrackedRegistration(t *testing.T) {
	executor := &fakeCommandExecutor{statuses: []string{"Status update: Connected"}}
	client := &warpClient{
		cliPath:      "warp-cli",
		stateFile:    filepath.Join(t.TempDir(), "state.json"),
		connectWait:  time.Second,
		pollInterval: time.Millisecond,
		executor:     executor,
	}
	err := client.EnsureRegisteredAndConnected(context.Background(), &meshapi.ConnectorCredentials{
		ID: "connector-1", Name: "node-a", Token: "token-1",
	}, false)
	if err == nil {
		t.Fatal("expected adoption error")
	}
}

func TestWARPPreservesDifferentConnectorState(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	client := &warpClient{stateFile: stateFile, executor: &fakeCommandExecutor{}}
	if err := client.writeState(&warpState{ConnectorID: "old"}); err != nil {
		t.Fatal(err)
	}
	err := client.EnsureRegisteredAndConnected(context.Background(), &meshapi.ConnectorCredentials{
		ID: "new", Name: "node-a", Token: "token-1",
	}, false)
	if err == nil {
		t.Fatal("expected connector mismatch error")
	}
}

func hasCommand(commands []recordedCommand, args []string) bool {
	for _, command := range commands {
		if reflect.DeepEqual(command.args, args) {
			return true
		}
	}
	return false
}
