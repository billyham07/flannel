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

//go:build !windows

package cloudflaremesh

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
)

func TestConnectorAccountID(t *testing.T) {
	want := "0123456789abcdef0123456789abcdef"
	raw, err := hex.DecodeString(want)
	if err != nil {
		t.Fatal(err)
	}
	for name, account := range map[string]string{
		"raw account bytes": base64.RawStdEncoding.EncodeToString(raw),
		"ASCII account ID":  base64.StdEncoding.EncodeToString([]byte(want)),
		"direct account ID": want,
	} {
		t.Run(name, func(t *testing.T) {
			envelope, err := json.Marshal(map[string]string{"a": account, "t": "unused", "s": "unused"})
			if err != nil {
				t.Fatal(err)
			}
			token := base64.RawStdEncoding.EncodeToString(envelope)
			got, err := connectorAccountID(token)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("account ID = %q, want %q", got, want)
			}
		})
	}
}

func TestConnectorAccountIDRejectsMalformedToken(t *testing.T) {
	if _, err := connectorAccountID("not-base64"); err == nil {
		t.Fatal("expected malformed connector token to fail")
	}
}

func TestDeviceRegistrationID(t *testing.T) {
	for input, want := range map[string]string{
		"t.019fffbd-6df8-13a3-9edb-1d80019bfa41": "019fffbd-6df8-13a3-9edb-1d80019bfa41",
		"019fffa4-03ff-180d-9919-0f72ab793e70":   "019fffa4-03ff-180d-9919-0f72ab793e70",
	} {
		if got := deviceRegistrationID(input); got != want {
			t.Fatalf("deviceRegistrationID(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestConnectorChangeReenrollsInsteadOfReturningReadError(t *testing.T) {
	for name, connectorID := range map[string]string{
		"connector changed":   "old-connector",
		"legacy state schema": "new-connector",
	} {
		t.Run(name, func(t *testing.T) {
			stateFile := filepath.Join(t.TempDir(), "state.json")
			state, err := json.Marshal(persistedRegistration{ConnectorID: connectorID})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(stateFile, state, 0600); err != nil {
				t.Fatal(err)
			}

			_, _, err = loadOrEnroll(context.Background(), &runtimeConfig{config: config{StateFile: stateFile}}, &meshapi.ConnectorCredentials{
				ID: "new-connector", Token: "not-base64",
			})
			if err == nil || !strings.Contains(err.Error(), "connector token has no account") {
				t.Fatalf("state replacement did not enter enrollment path: %v", err)
			}
		})
	}
}
