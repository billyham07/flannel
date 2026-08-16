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
	"os"
	"strings"

	log "k8s.io/klog/v2"
)

// Cloudflare's device API only enrols clients whose build it recognises, so
// this backend presents the fingerprint of a known-good WARP for Linux release.
// When Cloudflare retires that build, enrollment starts failing with a 4xx and
// the only fix is a newer fingerprint -- which would otherwise mean waiting for
// a new flannel image. Each value can therefore be overridden through the
// environment, so a cluster can be unblocked by editing the DaemonSet.
const (
	defaultClientVersion   = "l-2026.7.974.2"
	defaultDeviceVersion   = "2026.7.974.2"
	defaultRegistrationAPI = "v0a974"

	clientVersionEnv   = "CLOUDFLARE_MESH_CLIENT_VERSION"
	deviceVersionEnv   = "CLOUDFLARE_MESH_DEVICE_VERSION"
	registrationAPIEnv = "CLOUDFLARE_MESH_REGISTRATION_API"
)

// compatFingerprint is the set of values Cloudflare matches this client
// against: the CF-Client-Version header, the version reported in device-state
// updates, and the registration API path segment.
type compatFingerprint struct {
	ClientVersion   string
	DeviceVersion   string
	RegistrationAPI string
}

// compat resolves the fingerprint currently in force. It reads the environment
// on every call, which only ever happens on control-plane requests, never on
// the packet path.
func compat() compatFingerprint {
	return compatFingerprint{
		ClientVersion:   envOrDefault(clientVersionEnv, defaultClientVersion),
		DeviceVersion:   envOrDefault(deviceVersionEnv, defaultDeviceVersion),
		RegistrationAPI: envOrDefault(registrationAPIEnv, defaultRegistrationAPI),
	}
}

// logCompatOverrides records any fingerprint override at startup. An override
// is an emergency measure, so it must be visible in the logs of a node that is
// running with one.
func logCompatOverrides() {
	for _, override := range []struct{ name, value, fallback string }{
		{clientVersionEnv, envOrDefault(clientVersionEnv, defaultClientVersion), defaultClientVersion},
		{deviceVersionEnv, envOrDefault(deviceVersionEnv, defaultDeviceVersion), defaultDeviceVersion},
		{registrationAPIEnv, envOrDefault(registrationAPIEnv, defaultRegistrationAPI), defaultRegistrationAPI},
	} {
		if override.value != override.fallback {
			log.Infof("cloudflare-mesh: %s overrides the built-in compatibility value with %q (default %q)",
				override.name, override.value, override.fallback)
		}
	}
}

// compatHint explains, for a Cloudflare rejection that looks like a client
// compatibility problem, which values are in play and how to change them.
func (c compatFingerprint) compatHint() string {
	return "this is usually a stale native client fingerprint rather than a problem with the cluster" +
		" (client version " + c.ClientVersion + ", device version " + c.DeviceVersion +
		", registration API " + c.RegistrationAPI + "); override with " +
		clientVersionEnv + ", " + deviceVersionEnv + " or " + registrationAPIEnv
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
