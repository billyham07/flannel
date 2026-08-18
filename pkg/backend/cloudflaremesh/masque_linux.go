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

// The CONNECT-IP framing and Cloudflare interoperability details in this file
// were derived from github.com/Diniboy1123/usque (MIT license). The lifecycle,
// persistence, routing and bounded reconnect supervisor are flannel-specific.
package cloudflaremesh

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
	log "k8s.io/klog/v2"
)

// Base URLs are variables so tests can point them at a local server.
var (
	deviceAPIBase    = "https://api.devices.cloudflare.com"
	zeroTrustAPIBase = "https://zero-trust-client.cloudflareclient.com"
)

// errRegistrationGone reports that Cloudflare no longer knows about this
// node's registration -- deleted from the dashboard, or reclaimed by the
// operator's registration GC. It is recoverable: the node enrols again.
var errRegistrationGone = errors.New("registration no longer exists at Cloudflare")

// sessionHealthyAfter is how long a MASQUE session has to stay up before the
// reconnect supervisor treats it as healthy and drops back to the shortest
// retry delay.
const sessionHealthyAfter = 2 * time.Minute

const (
	connectSNI = "zt-masque.cloudflareclient.com"
	connectURI = "https://cloudflareaccess.com"
	gatewayID  = "03000200-0400-0500-0006-000700080009"
)

type cloudflareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type registrationEnvelope struct {
	Success bool              `json:"success"`
	Result  meshRegistration  `json:"result"`
	Errors  []cloudflareError `json:"errors"`
}

type meshRegistration struct {
	ID          string `json:"id"`
	Token       string `json:"token,omitempty"`
	IsConnector bool   `json:"is_connector"`
	Account     struct {
		ID           string `json:"id"`
		AccountType  string `json:"account_type"`
		Organization string `json:"organization"`
	} `json:"account"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4    string `json:"v4"`
				V6    string `json:"v6"`
				Host  string `json:"host"`
				Ports []int  `json:"ports"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
	Policy struct {
		ID string `json:"policy_id"`
	} `json:"policy"`
}

type persistedRegistration struct {
	ConnectorID  string           `json:"connector_id"`
	PrivateKey   string           `json:"private_key"`
	Registration meshRegistration `json:"registration"`
}

type registrationPayload struct {
	Type               string `json:"type"`
	Model              string `json:"model"`
	Name               string `json:"name"`
	Key                string `json:"key"`
	TOS                string `json:"tos"`
	GatewayDeviceID    string `json:"gateway_device_id"`
	OSVersion          string `json:"os_version"`
	SerialNumber       string `json:"serial_number"`
	WarpConnectorToken string `json:"warp_connector_token"`
	KeyType            string `json:"key_type"`
	TunnelType         string `json:"tunnel_type"`
}

type registrationUpdate struct {
	Key        string `json:"key"`
	KeyType    string `json:"key_type"`
	TunnelType string `json:"tunnel_type"`
	Name       string `json:"name,omitempty"`
}

type deviceStatePayload struct {
	Timestamp          string         `json:"timestamp"`
	AccountID          string         `json:"account_id"`
	Status             string         `json:"status"`
	Mode               string         `json:"mode"`
	AlwaysOn           bool           `json:"always_on"`
	RegistrationID     string         `json:"reg_id"`
	DOHSubdomain       string         `json:"doh_subdomain"`
	SwitchLocked       bool           `json:"switch_locked"`
	ClientVersion      string         `json:"client_version"`
	ClientPlatform     string         `json:"client_platform"`
	WarpMetal          string         `json:"warp_metal"`
	WarpColo           string         `json:"warp_colo"`
	HandshakeLatencyMS *int           `json:"handshake_latency_ms"`
	EstimatedLoss      *float64       `json:"estimated_loss"`
	TunnelType         string         `json:"tunnel_type"`
	Interfaces         []any          `json:"interfaces"`
	Firewalls          map[string]any `json:"firewalls"`
	ProfileID          string         `json:"profile_id,omitempty"`
}

type nativeTransport struct {
	iface        *water.Interface
	registration meshRegistration
	privateKey   *ecdsa.PrivateKey
	cfg          *runtimeConfig
	ready        chan struct{}
	readyOnce    sync.Once
	cancel       context.CancelFunc
	done         chan struct{}
	closeOnce    sync.Once
}

func startNativeTransport(ctx context.Context, cfg *runtimeConfig, connector *meshapi.ConnectorCredentials) (*nativeTransport, error) {
	state, key, err := loadOrEnroll(ctx, cfg, connector)
	if err != nil {
		return nil, err
	}
	meshNetwork, err := parseCIDR(cfg.MeshCIDR)
	if err != nil {
		return nil, err
	}
	meshIP := net.ParseIP(state.Config.Interface.Addresses.V4)
	if meshIP == nil || !meshNetwork.Contains(meshIP) {
		return nil, fmt.Errorf("Cloudflare returned connector IPv4 %q outside MeshCIDR %s", state.Config.Interface.Addresses.V4, meshNetwork)
	}
	dev, err := water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{Name: cfg.InterfaceName}})
	if err != nil {
		return nil, fmt.Errorf("create %s TUN: %w", cfg.InterfaceName, err)
	}
	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("find native Mesh TUN: %w", err)
	}
	if err := netlink.LinkSetMTU(link, cfg.MTU); err != nil {
		dev.Close()
		return nil, fmt.Errorf("set native Mesh MTU: %w", err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: meshIP.To4(), Mask: net.CIDRMask(32, 32)}}
	if err := netlink.AddrReplace(link, addr); err != nil {
		dev.Close()
		return nil, fmt.Errorf("set native Mesh address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring native Mesh TUN up: %w", err)
	}
	// The session supervisor runs on its own cancellable context so Close can
	// stop it even while the caller's context is still live, which is what the
	// failure paths below and a backend teardown both need.
	sessionCtx, cancel := context.WithCancel(ctx)
	t := &nativeTransport{
		iface: dev, registration: state, privateKey: key, cfg: cfg,
		ready: make(chan struct{}), cancel: cancel, done: make(chan struct{}),
	}
	go t.run(sessionCtx)
	timer := time.NewTimer(cfg.ConnectWait)
	defer timer.Stop()
	select {
	case <-t.ready:
		return t, nil
	case <-ctx.Done():
		t.Close()
		return nil, ctx.Err()
	case <-timer.C:
		t.Close()
		return nil, fmt.Errorf("connect native MASQUE tunnel: timed out after %s", cfg.ConnectWait)
	}
}

// Close stops the reconnect supervisor and destroys the TUN device. It is
// idempotent and waits for the supervisor to return, so callers can rely on
// the interface being gone once it does.
func (t *nativeTransport) Close() {
	t.closeOnce.Do(func() {
		select {
		case <-t.ready:
			// Best effort: without this Cloudflare keeps showing the connector
			// as connected until its own session timeout expires.
			reportCtx, cancelReport := context.WithTimeout(context.Background(), 5*time.Second)
			if err := t.reportDeviceState(reportCtx, "Disconnected", "masque"); err != nil {
				log.Warningf("cloudflare-mesh: final device-state report failed: %v", err)
			}
			cancelReport()
		default:
		}

		t.cancel()
		// Unblocks the TUN reader, which cannot observe context cancellation
		// while it is parked in Read.
		_ = t.iface.Close()
	})
	<-t.done
}

func loadOrEnroll(ctx context.Context, cfg *runtimeConfig, connector *meshapi.ConnectorCredentials) (meshRegistration, *ecdsa.PrivateKey, error) {
	if connector == nil || connector.ID == "" || strings.TrimSpace(connector.Token) == "" {
		return meshRegistration{}, nil, errors.New("native Mesh connector credentials are incomplete")
	}
	name := registrationName(cfg, connector)
	// superseded is the registration this node is about to abandon. Cloudflare
	// keeps abandoned registrations forever, and each one holds a Mesh virtual
	// IP, so it has to be deleted before the replacement is enrolled.
	var superseded *meshRegistration
	contents, err := os.ReadFile(cfg.StateFile)
	if err == nil {
		var state persistedRegistration
		if err := json.Unmarshal(contents, &state); err != nil {
			return meshRegistration{}, nil, fmt.Errorf("decode native Mesh state: %w", err)
		}
		if state.ConnectorID != connector.ID {
			log.Infof("cloudflare-mesh: connector changed from %s to %s; replacing native registration", state.ConnectorID, connector.ID)
			superseded = &state.Registration
		} else if state.PrivateKey == "" || state.Registration.ID == "" || state.Registration.Token == "" {
			log.Infof("cloudflare-mesh: replacing legacy or incomplete state for connector %s", connector.ID)
			superseded = &state.Registration
		} else {
			der, err := base64.StdEncoding.DecodeString(state.PrivateKey)
			if err != nil {
				log.Warningf("cloudflare-mesh: replacing state with invalid private key for connector %s: %v", connector.ID, err)
				superseded = &state.Registration
			} else if key, err := x509.ParseECPrivateKey(der); err != nil {
				log.Warningf("cloudflare-mesh: replacing state with invalid private key for connector %s: %v", connector.ID, err)
				superseded = &state.Registration
			} else {
				publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
				if err != nil {
					return meshRegistration{}, nil, err
				}
				client := &http.Client{Timeout: cfg.ConnectWait}
				refreshed, err := refreshRegistration(ctx, client, state.Registration, publicDER, name)
				switch {
				case err == nil:
					state.Registration = refreshed
					if err := writePrivateJSON(cfg.StateFile, &state); err != nil {
						return meshRegistration{}, nil, err
					}
					return refreshed, key, nil
				case errors.Is(err, errRegistrationGone):
					// Enrol again rather than refusing to start. superseded is
					// deliberately left nil: there is nothing to delete, and
					// the stale token would not authorise the call anyway.
					log.Infof("cloudflare-mesh: registration %s is gone at Cloudflare; enrolling a replacement: %v",
						state.Registration.ID, err)
				default:
					return meshRegistration{}, nil, err
				}
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return meshRegistration{}, nil, fmt.Errorf("read native Mesh state: %w", err)
	}
	if superseded != nil {
		// Best effort only. If it fails the operator's registration GC still
		// reclaims the virtual IP on its next sweep, so a dead control-plane
		// endpoint must not stop this node from coming up.
		if err := deleteRegistration(ctx, &http.Client{Timeout: cfg.ConnectWait}, *superseded); err != nil {
			log.Warningf("cloudflare-mesh: could not delete superseded registration %s: %v", superseded.ID, err)
		} else {
			log.Infof("cloudflare-mesh: deleted superseded registration %s", superseded.ID)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return meshRegistration{}, nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return meshRegistration{}, nil, err
	}
	accountID, err := connectorAccountID(connector.Token)
	if err != nil {
		return meshRegistration{}, nil, err
	}
	payload := registrationPayload{
		Type: "linux", Model: "WO4 Default string", Name: name,
		Key: base64.StdEncoding.EncodeToString(publicDER), TOS: time.Now().UTC().Format(time.RFC3339Nano),
		GatewayDeviceID: gatewayID, OSVersion: "6.12.74", SerialNumber: "Default string",
		WarpConnectorToken: connector.Token, KeyType: "secp256r1", TunnelType: "masque",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return meshRegistration{}, nil, err
	}
	endpoint := deviceAPIBase + "/v1/accounts/" + accountID + "/warp_connector"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return meshRegistration{}, nil, err
	}
	req.Header.Set("CF-Client-Version", compat().ClientVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "WARP for Linux")
	client := &http.Client{Timeout: cfg.ConnectWait}
	resp, err := client.Do(req)
	if err != nil {
		return meshRegistration{}, nil, fmt.Errorf("enroll native Mesh connector: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return meshRegistration{}, nil, err
	}
	var envelope registrationEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return meshRegistration{}, nil, fmt.Errorf("decode connector enrollment HTTP %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || !envelope.Success || !envelope.Result.IsConnector || envelope.Result.Account.AccountType != "team" {
		return meshRegistration{}, nil, enrollmentRejected(resp.StatusCode, envelope)
	}
	if strings.TrimSpace(envelope.Result.Token) == "" {
		return meshRegistration{}, nil, errors.New("Cloudflare connector enrollment returned no device token")
	}
	refreshed, err := refreshRegistration(ctx, client, envelope.Result, publicDER, name)
	if err != nil {
		return meshRegistration{}, nil, err
	}
	envelope.Result = refreshed
	privateDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return meshRegistration{}, nil, err
	}
	state := persistedRegistration{ConnectorID: connector.ID, PrivateKey: base64.StdEncoding.EncodeToString(privateDER), Registration: envelope.Result}
	if err := writePrivateJSON(cfg.StateFile, &state); err != nil {
		return meshRegistration{}, nil, err
	}
	return envelope.Result, key, nil
}

func refreshRegistration(ctx context.Context, client *http.Client, registration meshRegistration, publicDER []byte, nodeName string) (meshRegistration, error) {
	payload := registrationUpdate{
		Key:        base64.StdEncoding.EncodeToString(publicDER),
		KeyType:    "secp256r1",
		TunnelType: "masque",
		Name:       nodeName,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return meshRegistration{}, err
	}
	endpoint := zeroTrustAPIBase + "/" + compat().RegistrationAPI + "/reg/" + registration.ID
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(body))
	if err != nil {
		return meshRegistration{}, err
	}
	setDeviceAPIHeaders(req, registration.Token)
	resp, err := client.Do(req)
	if err != nil {
		return meshRegistration{}, fmt.Errorf("refresh native Mesh registration: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return meshRegistration{}, err
	}
	if err := registrationRefreshError(resp.StatusCode, raw); err != nil {
		return meshRegistration{}, err
	}
	var refreshed meshRegistration
	if err := json.Unmarshal(raw, &refreshed); err != nil {
		return meshRegistration{}, fmt.Errorf("decode refreshed native Mesh registration: %w", err)
	}
	if refreshed.ID == "" || len(refreshed.Config.Peers) == 0 || refreshed.Policy.ID == "" {
		return meshRegistration{}, errors.New("refreshed native Mesh registration is incomplete")
	}
	// The PATCH response intentionally omits the bearer token.
	refreshed.Token = registration.Token
	return refreshed, nil
}

// registrationName is what this node shows up as in the Cloudflare device
// list. It reuses the operator's connector name rather than the bare hostname
// on purpose: the operator garbage-collects registrations by that prefix, and
// a bare hostname could collide with a real user device that must never be
// deleted. Existing registrations are renamed in place by refreshRegistration
// on the next start, so no re-enrolment is needed.
func registrationName(cfg *runtimeConfig, connector *meshapi.ConnectorCredentials) string {
	if connector != nil && strings.TrimSpace(connector.Name) != "" {
		return connector.Name
	}
	return cfg.NodeName
}

// deleteRegistration releases a registration and its Mesh virtual IP. It is
// the counterpart of the PATCH in refreshRegistration and uses the device's
// own bearer token, so it works without the account API token.
func deleteRegistration(ctx context.Context, client *http.Client, registration meshRegistration) error {
	if registration.ID == "" || strings.TrimSpace(registration.Token) == "" {
		return errors.New("registration is incomplete")
	}
	endpoint := zeroTrustAPIBase + "/" + compat().RegistrationAPI + "/reg/" + registration.ID
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	setDeviceAPIHeaders(req, registration.Token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	// A registration deleted out of band is the outcome we wanted anyway.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return nil
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// registrationRefreshError classifies a PATCH /reg/{id} response. A
// registration that has been deleted answers for the device token as well as
// the record, so 401 and 403 mean the same thing here as 404: this node's
// identity is gone and has to be re-established.
func registrationRefreshError(statusCode int, body []byte) error {
	switch statusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound, http.StatusGone, http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w (HTTP %d)%s", errRegistrationGone, statusCode, cloudflareErrorDetail(body))
	default:
		return fmt.Errorf("refresh native Mesh registration: HTTP %d%s", statusCode, cloudflareErrorDetail(body))
	}
}

// enrollmentRejected builds the error for a refused connector enrollment.
// Cloudflare's errors[] entries are the only actionable part of the response,
// and a 4xx here is far more often the native client fingerprint going stale
// than anything to do with this cluster, so the error says so and names the
// overrides that can fix it without a new image.
func enrollmentRejected(statusCode int, envelope registrationEnvelope) error {
	message := fmt.Sprintf("Cloudflare rejected native connector enrollment: HTTP %d connector=%t account=%q%s",
		statusCode, envelope.Result.IsConnector, envelope.Result.Account.AccountType, formatCloudflareErrors(envelope.Errors))
	if statusCode >= http.StatusBadRequest && statusCode < http.StatusInternalServerError {
		message += "; " + compat().compatHint()
	}
	return errors.New(message)
}

// cloudflareErrorDetail extracts errors[] from a response body that may or may
// not be a Cloudflare envelope. A body that is not one yields no detail rather
// than an error: the status code alone is still a usable diagnosis.
func cloudflareErrorDetail(body []byte) string {
	var envelope struct {
		Errors []cloudflareError `json:"errors"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return ""
	}
	return formatCloudflareErrors(envelope.Errors)
}

func formatCloudflareErrors(cloudflareErrors []cloudflareError) string {
	parts := make([]string, 0, len(cloudflareErrors))
	for _, item := range cloudflareErrors {
		switch {
		case item.Message == "":
			parts = append(parts, fmt.Sprintf("code %d", item.Code))
		case item.Code == 0:
			parts = append(parts, item.Message)
		default:
			parts = append(parts, fmt.Sprintf("%d: %s", item.Code, item.Message))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return ": " + strings.Join(parts, "; ")
}

func deviceRegistrationID(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "t.")
}

func setDeviceAPIHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("CF-Client-Version", compat().ClientVersion)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "WARP for Linux")
}

func (t *nativeTransport) reportDeviceState(ctx context.Context, status, tunnelType string) error {
	accountID := t.registration.Account.ID
	if accountID == "" || t.registration.ID == "" || t.registration.Token == "" {
		return errors.New("native Mesh registration cannot report device state")
	}
	payload := deviceStatePayload{
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		AccountID:      accountID,
		Status:         status,
		Mode:           "warp+doh",
		AlwaysOn:       true,
		RegistrationID: deviceRegistrationID(t.registration.ID),
		DOHSubdomain:   accountID + ".cloudflare-gateway.com",
		ClientVersion:  compat().DeviceVersion,
		ClientPlatform: "linux",
		WarpMetal:      "none",
		WarpColo:       "none",
		TunnelType:     tunnelType,
		Interfaces:     []any{},
		Firewalls:      map[string]any{},
		ProfileID:      t.registration.Policy.ID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := zeroTrustAPIBase + "/v0/accounts/" + accountID + "/reg/" + deviceRegistrationID(t.registration.ID) + "/devicestate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	setDeviceAPIHeaders(req, t.registration.Token)
	client := &http.Client{Timeout: t.cfg.ConnectWait}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("report native Mesh device state %s: %w", status, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("report native Mesh device state %s: HTTP %d", status, resp.StatusCode)
	}
	return nil
}

func connectorAccountID(token string) (string, error) {
	decode := func(value string) ([]byte, error) {
		for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
			if b, err := encoding.DecodeString(value); err == nil {
				return b, nil
			}
		}
		return nil, errors.New("invalid base64")
	}
	raw, err := decode(strings.TrimSpace(token))
	if err != nil {
		return "", fmt.Errorf("decode connector token: %w", err)
	}
	var fields struct {
		Account string `json:"a"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil || fields.Account == "" {
		return "", errors.New("connector token has no account")
	}
	if len(fields.Account) == 32 {
		if _, err := hex.DecodeString(fields.Account); err == nil {
			return fields.Account, nil
		}
	}
	account, err := decode(fields.Account)
	if err != nil {
		return "", fmt.Errorf("decode connector account: %w", err)
	}
	if len(account) == 16 {
		return hex.EncodeToString(account), nil
	}
	value := string(account)
	if len(value) == 32 {
		if _, err := hex.DecodeString(value); err == nil {
			return strings.ToLower(value), nil
		}
	}
	return "", fmt.Errorf("connector token account has invalid encoding (decoded length %d)", len(account))
}

func writePrivateJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mesh-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := json.NewEncoder(tmp).Encode(value); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (t *nativeTransport) meshIP() net.IP {
	return net.ParseIP(t.registration.Config.Interface.Addresses.V4).To4()
}

func (t *nativeTransport) run(ctx context.Context) {
	// close(done) is deferred first so it runs last: Close blocks on it and
	// must not observe the supervisor as finished before the TUN is gone.
	defer close(t.done)
	defer t.iface.Close()
	// Buffers are recycled rather than allocated per packet; see tunBufferPool
	// for the ownership rules the reader and the writer pump both follow.
	pool := newTUNBufferPool(tunBufferPoolSize, t.cfg.MTU)
	outbound := make(chan []byte, outboundQueueDepth)
	go func() {
		for {
			buf, ok := pool.get(ctx)
			if !ok {
				return
			}
			n, err := t.iface.Read(buf[tunHeadroom:])
			if err != nil {
				pool.put(buf)
				close(outbound)
				return
			}
			select {
			case outbound <- buf[:tunHeadroom+n]:
			case <-ctx.Done():
				pool.put(buf)
				return
			}
		}
	}()
	delay := time.Second
	if err := t.reportDeviceState(ctx, "Connecting", "masque"); err != nil {
		log.Warningf("cloudflare-mesh: initial device-state report failed: %v", err)
	}
	for ctx.Err() == nil {
		started := time.Now()
		err := t.runSession(ctx, outbound, pool)
		if ctx.Err() != nil {
			break
		}
		// A session that carried traffic for a while is evidence the endpoint
		// is healthy, so the next blip should reconnect immediately rather
		// than inherit the backoff a long-past outage left behind.
		if time.Since(started) >= sessionHealthyAfter {
			delay = time.Second
		}
		log.Warningf("cloudflare-mesh: MASQUE session lost: %v; reconnecting in %s", err, delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func (t *nativeTransport) runSession(ctx context.Context, outbound <-chan []byte, pool *tunBufferPool) error {
	if len(t.registration.Config.Peers) == 0 {
		return errors.New("registration has no MASQUE peer")
	}
	peer := t.registration.Config.Peers[0]
	peerKey, err := parseEndpointKey(peer.PublicKey)
	if err != nil {
		return err
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(0), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour)}, &x509.Certificate{}, &t.privateKey.PublicKey, t.privateKey)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: t.privateKey}},
		ServerName:   connectSNI, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("MASQUE peer sent no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			key, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok || !key.Equal(peerKey) {
				return errors.New("MASQUE peer public key mismatch")
			}
			return nil
		},
	}
	host := peer.Endpoint.V4
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	endpointIP := net.ParseIP(host)
	if endpointIP == nil {
		return fmt.Errorf("invalid MASQUE endpoint %q", peer.Endpoint.V4)
	}
	endpoint := &net.UDPAddr{IP: endpointIP, Port: 443}
	tunnelType := "masque"
	ipConn, response, closeSession, err := dialHTTP3(ctx, tlsConfig, endpoint, t.cfg.KeepaliveEvery, t.cfg.MTU)
	if err != nil {
		return err
	}
	defer closeSession()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("CONNECT-IP returned %s", response.Status)
	}
	if err := t.reportDeviceState(ctx, "Connected", tunnelType); err != nil {
		return err
	}
	t.readyOnce.Do(func() { close(t.ready) })
	log.Infof("cloudflare-mesh: native CONNECT-IP connected over %s to %s", tunnelType, endpoint)
	sessionCtx, cancelSession := context.WithCancel(ctx)
	errCh := make(chan error, 3)
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		for {
			select {
			case <-sessionCtx.Done():
				errCh <- sessionCtx.Err()
				return
			case packet, ok := <-outbound:
				if !ok {
					errCh <- io.EOF
					return
				}
				// quic-go copies the datagram payload before SendDatagram
				// returns, and the ICMP reply is freshly composed, so the
				// buffer is free again the moment this call comes back.
				icmp, err := ipConn.WritePacketBuffer(packet, tunHeadroom, len(packet)-tunHeadroom)
				if err == nil && len(icmp) > 0 {
					_, err = t.iface.Write(icmp)
				}
				pool.put(packet)
				if err != nil {
					errCh <- err
					return
				}
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-ticker.C:
				if err := t.reportDeviceState(sessionCtx, "Connected", tunnelType); err != nil {
					log.Warningf("cloudflare-mesh: periodic device-state report failed: %v", err)
				}
			}
		}
	}()
	go func() {
		defer pumps.Done()
		for {
			packet, err := ipConn.ReadPacketZeroCopy(true)
			if err != nil {
				errCh <- err
				return
			}
			if _, err := t.iface.Write(packet); err != nil {
				errCh <- err
				return
			}
		}
	}()
	sessionErr := <-errCh
	cancelSession()
	_ = ipConn.Close()
	pumps.Wait()
	return sessionErr
}

func dialHTTP3(ctx context.Context, tlsConfig *tls.Config, endpoint *net.UDPAddr, keepalive time.Duration, mtu int) (*connectip.Conn, *http.Response, func(), error) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, nil, func() {}, err
	}
	qtr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	qconn, err := qtr.Dial(ctx, endpoint, tlsConfig, &quic.Config{
		EnableDatagrams:   true,
		KeepAlivePeriod:   keepalive,
		InitialPacketSize: quicInitialPacketSize(mtu),
	})
	if err != nil {
		_ = qtr.Close()
		_ = udpConn.Close()
		return nil, nil, func() {}, err
	}
	h3 := &http3.Transport{EnableDatagrams: true, DisableCompression: true, AdditionalSettings: map[uint64]uint64{0x276: 1}}
	hconn := h3.NewClientConn(qconn)
	ipConn, response, err := connectip.Dial(ctx, hconn, uritemplate.MustNew(connectURI), "cf-connect-ip", http.Header{"User-Agent": []string{""}}, true)
	if err != nil {
		_ = h3.Close()
		_ = qconn.CloseWithError(0, "connect-ip dial failed")
		_ = qtr.Close()
		_ = udpConn.Close()
		return nil, nil, func() {}, err
	}
	cleanup := func() {
		_ = ipConn.Close()
		_ = h3.Close()
		_ = qconn.CloseWithError(0, "reconnect")
		_ = qtr.Close()
		_ = udpConn.Close()
	}
	return ipConn, response, cleanup, nil
}

func parseEndpointKey(value string) (*ecdsa.PublicKey, error) {
	der := []byte(nil)
	if block, _ := pem.Decode([]byte(value)); block != nil {
		der = block.Bytes
	} else if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		der = decoded
	}
	if len(der) == 0 {
		return nil, errors.New("decode MASQUE peer public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("MASQUE peer key is not ECDSA")
	}
	return key, nil
}
