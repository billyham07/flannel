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
	"errors"
	"strings"
	"testing"
)

func TestLegacyWARPFirewallDeleteError(t *testing.T) {
	exitErr := errors.New("exit status 1")
	for name, tc := range map[string]struct {
		output  string
		wantErr bool
	}{
		"missing table is idempotent": {output: "Error: Could not process rule: No such file or directory"},
		"alternate missing message":   {output: "table does not exist"},
		"real failure is returned":    {output: "Operation not permitted", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			err := legacyWARPFirewallDeleteError([]byte(tc.output), exitErr)
			if tc.wantErr && (err == nil || !strings.Contains(err.Error(), tc.output)) {
				t.Fatalf("expected diagnostic error containing %q, got %v", tc.output, err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected idempotent success, got %v", err)
			}
		})
	}
}
