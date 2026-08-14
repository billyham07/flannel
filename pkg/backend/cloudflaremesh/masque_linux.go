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

const (
	deviceAPIBase = "https://api.devices.cloudflare.com"
	connectSNI    = "zt-masque.cloudflareclient.com"
	connectURI    = "https://cloudflareaccess.com"
	clientVersion = "l-2026.6.880.0"
	gatewayID     = "03000200-0400-0500-0006-000700080009"
)

type registrationEnvelope struct {
	Success bool             `json:"success"`
	Result  meshRegistration `json:"result"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

type meshRegistration struct {
	ID          string `json:"id"`
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

type nativeTransport struct {
	iface        *water.Interface
	registration meshRegistration
	privateKey   *ecdsa.PrivateKey
	cfg          *runtimeConfig
	ready        chan struct{}
	readyOnce    sync.Once
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
	t := &nativeTransport{iface: dev, registration: state, privateKey: key, cfg: cfg, ready: make(chan struct{})}
	go t.run(ctx)
	timer := time.NewTimer(cfg.ConnectWait)
	defer timer.Stop()
	select {
	case <-t.ready:
		return t, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		_ = dev.Close()
		return nil, fmt.Errorf("connect native MASQUE tunnel: timed out after %s", cfg.ConnectWait)
	}
}

func loadOrEnroll(ctx context.Context, cfg *runtimeConfig, connector *meshapi.ConnectorCredentials) (meshRegistration, *ecdsa.PrivateKey, error) {
	if connector == nil || connector.ID == "" || strings.TrimSpace(connector.Token) == "" {
		return meshRegistration{}, nil, errors.New("native Mesh connector credentials are incomplete")
	}
	contents, err := os.ReadFile(cfg.StateFile)
	if err == nil {
		var state persistedRegistration
		if err := json.Unmarshal(contents, &state); err != nil {
			return meshRegistration{}, nil, fmt.Errorf("decode native Mesh state: %w", err)
		}
		if state.ConnectorID != connector.ID {
			log.Infof("cloudflare-mesh: connector changed from %s to %s; replacing native registration", state.ConnectorID, connector.ID)
		} else if state.PrivateKey == "" || state.Registration.ID == "" {
			log.Infof("cloudflare-mesh: replacing legacy or incomplete state for connector %s", connector.ID)
		} else {
			der, err := base64.StdEncoding.DecodeString(state.PrivateKey)
			if err != nil {
				log.Warningf("cloudflare-mesh: replacing state with invalid private key for connector %s: %v", connector.ID, err)
			} else if key, err := x509.ParseECPrivateKey(der); err != nil {
				log.Warningf("cloudflare-mesh: replacing state with invalid private key for connector %s: %v", connector.ID, err)
			} else {
				return state.Registration, key, nil
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return meshRegistration{}, nil, fmt.Errorf("read native Mesh state: %w", err)
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
		Type: "linux", Model: "WO4 Default string", Name: cfg.NodeName,
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
	req.Header.Set("CF-Client-Version", clientVersion)
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
		return meshRegistration{}, nil, fmt.Errorf("Cloudflare rejected native connector enrollment: HTTP %d connector=%t account=%q", resp.StatusCode, envelope.Result.IsConnector, envelope.Result.Account.AccountType)
	}
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
	defer t.iface.Close()
	outbound := make(chan []byte, 256)
	go func() {
		for {
			buf := make([]byte, t.cfg.MTU+1)
			n, err := t.iface.Read(buf[1:])
			if err != nil {
				close(outbound)
				return
			}
			select {
			case outbound <- buf[:n+1]:
			case <-ctx.Done():
				return
			}
		}
	}()
	delay := time.Second
	for ctx.Err() == nil {
		err := t.runSession(ctx, outbound)
		if ctx.Err() != nil {
			break
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

func (t *nativeTransport) runSession(ctx context.Context, outbound <-chan []byte) error {
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
	endpoint := &net.UDPAddr{IP: net.ParseIP(host), Port: 443}
	if endpoint.IP == nil {
		return fmt.Errorf("invalid MASQUE endpoint %q", peer.Endpoint.V4)
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return err
	}
	defer udpConn.Close()
	qtr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	defer qtr.Close()
	qconn, err := qtr.Dial(ctx, endpoint, tlsConfig, &quic.Config{EnableDatagrams: true, KeepAlivePeriod: t.cfg.KeepaliveEvery})
	if err != nil {
		return err
	}
	defer qconn.CloseWithError(0, "reconnect")
	h3 := &http3.Transport{EnableDatagrams: true, DisableCompression: true, AdditionalSettings: map[uint64]uint64{0x276: 1}}
	defer h3.Close()
	hconn := h3.NewClientConn(qconn)
	ipConn, response, err := connectip.Dial(ctx, hconn, uritemplate.MustNew(connectURI), "cf-connect-ip", http.Header{"User-Agent": []string{""}}, true)
	if err != nil {
		return err
	}
	defer ipConn.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("CONNECT-IP returned %s", response.Status)
	}
	t.readyOnce.Do(func() { close(t.ready) })
	log.Infof("cloudflare-mesh: native MASQUE connected to %s", endpoint)
	sessionCtx, cancelSession := context.WithCancel(ctx)
	errCh := make(chan error, 2)
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
				icmp, err := ipConn.WritePacketBuffer(packet, 1, len(packet)-1)
				if err != nil {
					errCh <- err
					return
				}
				if len(icmp) > 0 {
					if _, err := t.iface.Write(icmp); err != nil {
						errCh <- err
						return
					}
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
