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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxAPIResponseSize      = 2 << 20
	defaultAPIClientTimeout = 30 * time.Second
	// The registrations endpoint rejects per_page above 100, unlike the
	// connector and route endpoints which accept 1000.
	registrationPageSize = 100
	maxRegistrationPages = 200
)

type ConnectorCredentials struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

type Route struct {
	ID        string          `json:"id"`
	Network   string          `json:"network"`
	TunnelID  string          `json:"tunnel_id"`
	Comment   string          `json:"comment"`
	DeletedAt json.RawMessage `json:"deleted_at"`
}

// DeviceRegistration is one WARP registration. flanneld creates one per node
// when it enrols; nothing else in the system reclaims them, so a registration
// that outlives its node keeps holding a Mesh virtual IP.
type DeviceRegistration struct {
	ID          string          `json:"id"`
	VirtualIPv4 string          `json:"virtual_ipv4"`
	CreatedAt   time.Time       `json:"created_at"`
	DeletedAt   json.RawMessage `json:"deleted_at"`
	Device      struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"device"`
}

func (r *DeviceRegistration) Name() string { return r.Device.Name }

type API interface {
	EnsureConnector(ctx context.Context, connectorID, name string, ha bool) (*ConnectorCredentials, error)
	ListConnectors(ctx context.Context) ([]ConnectorCredentials, error)
	DeleteConnector(ctx context.Context, connectorID string) error
	EnsureRoute(ctx context.Context, connectorID, network, comment string) (*Route, error)
	ListRoutes(ctx context.Context, connectorID string) ([]Route, error)
	DeleteRoute(ctx context.Context, routeID string) error
	ListDeviceRegistrations(ctx context.Context) ([]DeviceRegistration, error)
	DeleteDeviceRegistration(ctx context.Context, registrationID string) error
}

type Client struct {
	baseURL   *url.URL
	accountID string
	token     string
	http      *http.Client
}

type apiEnvelope struct {
	Success    bool            `json:"success"`
	Result     json.RawMessage `json:"result"`
	Errors     []apiError      `json:"errors"`
	ResultInfo struct {
		Cursor  string `json:"cursor"`
		Cursors struct {
			After string `json:"after"`
		} `json:"cursors"`
	} `json:"result_info"`
}

// nextCursor reports the cursor for the following page, if any. Cloudflare
// spells it both ways depending on the endpoint.
func (e *apiEnvelope) nextCursor() string {
	if e.ResultInfo.Cursor != "" {
		return e.ResultInfo.Cursor
	}
	return e.ResultInfo.Cursors.After
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewClient(baseURL, accountID, token string, client *http.Client) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse Cloudflare API base URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("unsupported Cloudflare API URL scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, errors.New("Cloudflare API base URL must include a host")
	}
	if client == nil {
		client = &http.Client{Timeout: defaultAPIClientTimeout}
	}
	return &Client{
		baseURL:   parsed,
		accountID: accountID,
		token:     token,
		http:      client,
	}, nil
}

func (c *Client) EnsureConnector(ctx context.Context, connectorID, name string, ha bool) (*ConnectorCredentials, error) {
	if connectorID != "" {
		token, err := c.getConnectorToken(ctx, connectorID)
		if err != nil {
			return nil, err
		}
		return &ConnectorCredentials{ID: connectorID, Name: name, Token: token}, nil
	}

	connectors, err := c.ListConnectors(ctx)
	if err != nil {
		return nil, err
	}

	var found *ConnectorCredentials
	for i := range connectors {
		if connectors[i].Name != name {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("multiple Cloudflare Mesh nodes are named %q", name)
		}
		copy := connectors[i]
		found = &copy
	}
	if found == nil {
		return c.createConnector(ctx, name, ha)
	}

	token, err := c.getConnectorToken(ctx, found.ID)
	if err != nil {
		return nil, err
	}
	found.Token = token
	return found, nil
}

func (c *Client) EnsureRoute(ctx context.Context, connectorID, network, comment string) (*Route, error) {
	routes, err := c.ListRoutes(ctx, connectorID)
	if err != nil {
		return nil, err
	}
	for i := range routes {
		if routes[i].Network == network && routes[i].TunnelID == connectorID && !isDeleted(routes[i].DeletedAt) {
			if routes[i].Comment != comment {
				updated, err := c.updateRouteComment(ctx, &routes[i], comment)
				if err != nil {
					return nil, err
				}
				return updated, nil
			}
			return &routes[i], nil
		}
	}

	body := struct {
		Network  string `json:"network"`
		TunnelID string `json:"tunnel_id"`
		Comment  string `json:"comment,omitempty"`
	}{Network: network, TunnelID: connectorID, Comment: comment}
	var route Route
	if _, err := c.do(ctx, http.MethodPost, c.accountPath("teamnet/routes"), nil, body, &route); err != nil {
		return nil, fmt.Errorf("create Cloudflare route %s for connector %s: %w", network, connectorID, err)
	}
	return &route, nil
}

func (c *Client) updateRouteComment(ctx context.Context, route *Route, comment string) (*Route, error) {
	body := struct {
		Network string `json:"network"`
		Comment string `json:"comment"`
	}{Network: route.Network, Comment: comment}
	var updated Route
	path := c.accountPath("teamnet/routes/" + url.PathEscape(route.ID))
	if _, err := c.do(ctx, http.MethodPatch, path, nil, body, &updated); err != nil {
		return nil, fmt.Errorf("update ownership comment for Cloudflare route %s: %w", route.ID, err)
	}
	return &updated, nil
}

func (c *Client) DeleteRoute(ctx context.Context, routeID string) error {
	path := c.accountPath("teamnet/routes/" + url.PathEscape(routeID))
	if _, err := c.do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
		return fmt.Errorf("delete Cloudflare route %s: %w", routeID, err)
	}
	return nil
}

func (c *Client) ListConnectors(ctx context.Context) ([]ConnectorCredentials, error) {
	query := url.Values{"per_page": []string{"1000"}}
	var connectors []ConnectorCredentials
	if _, err := c.do(ctx, http.MethodGet, c.accountPath("warp_connector"), query, nil, &connectors); err != nil {
		return nil, fmt.Errorf("list Cloudflare Mesh nodes: %w", err)
	}
	return connectors, nil
}

func (c *Client) DeleteConnector(ctx context.Context, connectorID string) error {
	path := c.accountPath("warp_connector/" + url.PathEscape(connectorID))
	if _, err := c.do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
		return fmt.Errorf("delete Cloudflare Mesh node %s: %w", connectorID, err)
	}
	return nil
}

func (c *Client) createConnector(ctx context.Context, name string, ha bool) (*ConnectorCredentials, error) {
	body := struct {
		Name string `json:"name"`
		HA   bool   `json:"ha"`
	}{Name: name, HA: ha}
	var connector ConnectorCredentials
	if _, err := c.do(ctx, http.MethodPost, c.accountPath("warp_connector"), nil, body, &connector); err != nil {
		return nil, fmt.Errorf("create Cloudflare Mesh node %q: %w", name, err)
	}
	if connector.ID == "" {
		return nil, fmt.Errorf("Cloudflare created Mesh node %q without an ID", name)
	}
	if connector.Token == "" {
		token, err := c.getConnectorToken(ctx, connector.ID)
		if err != nil {
			return nil, err
		}
		connector.Token = token
	}
	return &connector, nil
}

func (c *Client) getConnectorToken(ctx context.Context, connectorID string) (string, error) {
	path := c.accountPath("warp_connector/" + url.PathEscape(connectorID) + "/token")
	var raw json.RawMessage
	if _, err := c.do(ctx, http.MethodGet, path, nil, nil, &raw); err != nil {
		return "", fmt.Errorf("get token for Cloudflare Mesh node %s: %w", connectorID, err)
	}

	var token string
	if err := json.Unmarshal(raw, &token); err == nil && token != "" {
		return token, nil
	}
	var object struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &object); err != nil || object.Token == "" {
		return "", fmt.Errorf("Cloudflare returned an empty token for Mesh node %s", connectorID)
	}
	return object.Token, nil
}

func (c *Client) ListRoutes(ctx context.Context, connectorID string) ([]Route, error) {
	query := url.Values{
		"per_page":   []string{"1000"},
		"tun_types":  []string{"warp_connector"},
		"is_deleted": []string{"false"},
	}
	if connectorID != "" {
		query.Set("tunnel_id", connectorID)
	}
	var routes []Route
	if _, err := c.do(ctx, http.MethodGet, c.accountPath("teamnet/routes"), query, nil, &routes); err != nil {
		return nil, fmt.Errorf("list Cloudflare routes for connector %s: %w", connectorID, err)
	}
	return routes, nil
}

// ListDeviceRegistrations returns every active WARP registration on the
// account. Unlike the other list endpoints this one is paginated by cursor,
// because the registrations we are hunting for are exactly the ones that have
// accumulated.
func (c *Client) ListDeviceRegistrations(ctx context.Context) ([]DeviceRegistration, error) {
	var all []DeviceRegistration
	cursor := ""
	for page := 0; page < maxRegistrationPages; page++ {
		query := url.Values{"per_page": []string{strconv.Itoa(registrationPageSize)}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		var registrations []DeviceRegistration
		envelope, err := c.do(ctx, http.MethodGet, c.accountPath("devices/registrations"), query, nil, &registrations)
		if err != nil {
			return nil, fmt.Errorf("list Cloudflare device registrations: %w", err)
		}
		all = append(all, registrations...)
		cursor = envelope.nextCursor()
		if cursor == "" || len(registrations) == 0 {
			return all, nil
		}
	}
	return nil, fmt.Errorf("list Cloudflare device registrations: more than %d pages", maxRegistrationPages)
}

func (c *Client) DeleteDeviceRegistration(ctx context.Context, registrationID string) error {
	path := c.accountPath("devices/registrations/" + url.PathEscape(registrationID))
	if _, err := c.do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
		return fmt.Errorf("delete Cloudflare device registration %s: %w", registrationID, err)
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, result any) (*apiEnvelope, error) {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/" + strings.TrimLeft(path, "/")
	endpoint.RawQuery = query.Encode()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "flannel-cloudflare-mesh")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("decode HTTP %d response: %w", resp.StatusCode, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !envelope.Success {
		return nil, fmt.Errorf("Cloudflare API HTTP %d: %s", resp.StatusCode, formatAPIErrors(envelope.Errors))
	}
	if result == nil {
		return &envelope, nil
	}
	if raw, ok := result.(*json.RawMessage); ok {
		*raw = append((*raw)[:0], envelope.Result...)
		return &envelope, nil
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return nil, fmt.Errorf("decode Cloudflare API result: %w", err)
	}
	return &envelope, nil
}

func (c *Client) accountPath(resource string) string {
	return "accounts/" + url.PathEscape(c.accountID) + "/" + strings.TrimLeft(resource, "/")
}

func formatAPIErrors(apiErrors []apiError) string {
	if len(apiErrors) == 0 {
		return "request failed without an error message"
	}
	parts := make([]string, 0, len(apiErrors))
	for _, apiErr := range apiErrors {
		parts = append(parts, fmt.Sprintf("%d: %s", apiErr.Code, apiErr.Message))
	}
	return strings.Join(parts, "; ")
}

func isDeleted(value json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(value))
	return trimmed != "" && trimmed != "null"
}
