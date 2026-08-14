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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
)

func TestConnectorAccountID(t *testing.T) {
	want := "57f79fc9b5dbb4ef54cec951504333b3"
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

func TestRegistrationRefreshError(t *testing.T) {
	if err := registrationRefreshError(200); err != nil {
		t.Fatalf("200 should refresh cleanly, got %v", err)
	}
	for _, status := range []int{401, 403, 404, 410} {
		if err := registrationRefreshError(status); !errors.Is(err, errRegistrationGone) {
			t.Fatalf("HTTP %d should report the registration as gone, got %v", status, err)
		}
	}
	// A transient server-side fault must not be mistaken for deletion, or a
	// Cloudflare blip would burn a new registration and a new Mesh IP.
	for _, status := range []int{429, 500, 502, 503} {
		if err := registrationRefreshError(status); err == nil || errors.Is(err, errRegistrationGone) {
			t.Fatalf("HTTP %d should be a plain failure, got %v", status, err)
		}
	}
}

// Deleting a registration from the Cloudflare dashboard must not stop the node
// from starting: it re-enrols instead.
func TestDeletedRegistrationTriggersReenrollment(t *testing.T) {
	var refreshed, enrolled int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/reg/"):
			refreshed++
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/warp_connector"):
			enrolled++
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer server.Close()

	restoreDevice, restoreZeroTrust := deviceAPIBase, zeroTrustAPIBase
	deviceAPIBase, zeroTrustAPIBase = server.URL, server.URL
	defer func() { deviceAPIBase, zeroTrustAPIBase = restoreDevice, restoreZeroTrust }()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(t.TempDir(), "state.json")
	state := persistedRegistration{
		ConnectorID: "connector-1",
		PrivateKey:  base64.StdEncoding.EncodeToString(der),
	}
	state.Registration.ID = "t.dead-registration"
	state.Registration.Token = "dead-token"
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}

	account, err := json.Marshal(map[string]string{"a": "57f79fc9b5dbb4ef54cec951504333b3"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &runtimeConfig{config: config{StateFile: stateFile, NodeName: "node-a"}, ConnectWait: 5 * time.Second}
	_, _, err = loadOrEnroll(context.Background(), cfg, &meshapi.ConnectorCredentials{
		ID: "connector-1", Name: "flannel-test-node-a", Token: base64.RawStdEncoding.EncodeToString(account),
	})

	if refreshed != 1 {
		t.Fatalf("refresh attempts = %d, want 1", refreshed)
	}
	// Enrollment is reached, which is the point; it then fails because this
	// fake Cloudflare rejects it, and that error is what surfaces.
	if enrolled != 1 {
		t.Fatalf("enrollment attempts = %d, want 1 after a deleted registration", enrolled)
	}
	if err == nil || errors.Is(err, errRegistrationGone) {
		t.Fatalf("expected the enrollment failure to surface, got %v", err)
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
