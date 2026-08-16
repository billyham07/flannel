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
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
)

func TestEnsureConnectorCreatesMissingNode(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/accounts/account/warp_connector", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("unexpected authorization header")
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"success":true,"result":[]}`)
		case http.MethodPost:
			fmt.Fprint(w, `{"success":true,"result":{"id":"connector-1","name":"node-a","token":"enroll-token"}}`)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := NewClient(server.URL, "account", "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	connector, err := client.EnsureConnector(context.Background(), "", "node-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if connector.ID != "connector-1" || connector.Token != "enroll-token" {
		t.Fatalf("unexpected connector: %#v", connector)
	}
}

func TestNewClientUsesBoundedDefaultHTTPClient(t *testing.T) {
	client, err := NewClient("https://api.cloudflare.com/client/v4", "account", "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.http.Timeout != defaultAPIClientTimeout {
		t.Fatalf("default HTTP timeout = %s, want %s", client.http.Timeout, defaultAPIClientTimeout)
	}
}

func TestEnsureConnectorReusesNodeAndGetsToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/accounts/account/warp_connector", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"success":true,"result":[{"id":"connector-1","name":"node-a"}]}`)
	})
	mux.HandleFunc("/accounts/account/warp_connector/connector-1/token", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"success":true,"result":"existing-token"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := NewClient(server.URL, "account", "secret", server.Client())
	connector, err := client.EnsureConnector(context.Background(), "", "node-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if connector.Token != "existing-token" {
		t.Fatalf("unexpected token %q", connector.Token)
	}
}

func TestEnsureRouteIsIdempotent(t *testing.T) {
	createCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/accounts/account/teamnet/routes", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("tun_types"); r.Method == http.MethodGet && got != "warp_connector" {
			t.Fatalf("unexpected tun_types %q", got)
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"success":true,"result":[{"id":"route-1","network":"10.10.1.0/24","tunnel_id":"connector-1","deleted_at":null}]}`)
		case http.MethodPost:
			createCalls++
			fmt.Fprint(w, `{"success":true,"result":{"id":"route-2","network":"10.10.1.0/24","tunnel_id":"connector-1"}}`)
		}
	})
	mux.HandleFunc("/accounts/account/teamnet/routes/route-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":{"id":"route-1","network":"10.10.1.0/24","tunnel_id":"connector-1","comment":"managed"}}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := NewClient(server.URL, "account", "secret", server.Client())
	route, err := client.EnsureRoute(context.Background(), "connector-1", "10.10.1.0/24", "managed")
	if err != nil {
		t.Fatal(err)
	}
	if route.ID != "route-1" || createCalls != 0 {
		t.Fatalf("route was not reused: route=%#v creates=%d", route, createCalls)
	}
}

// The registrations endpoint rejects per_page above 100 -- unlike every other
// endpoint this client talks to -- so paging has to be real, not a single
// oversized request.
func TestListDeviceRegistrationsPagesWithinTheServerLimit(t *testing.T) {
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		perPage, err := strconv.Atoi(r.URL.Query().Get("per_page"))
		if err != nil || perPage < 1 || perPage > 100 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":2750,"message":"invalid query parameter 'per_page': must be between 1 and 100"}]}`)
			return
		}
		cursor := r.URL.Query().Get("cursor")
		pages = append(pages, cursor)
		switch cursor {
		case "":
			fmt.Fprint(w, `{"success":true,"result":[{"id":"a","virtual_ipv4":"100.96.0.1","device":{"name":"one"}}],"result_info":{"cursor":"next"}}`)
		default:
			fmt.Fprint(w, `{"success":true,"result":[{"id":"b","virtual_ipv4":"100.96.0.2","device":{"name":"two"}}],"result_info":{"cursor":""}}`)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "account", "token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	registrations, err := client.ListDeviceRegistrations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 2 || registrations[0].ID != "a" || registrations[1].ID != "b" {
		t.Fatalf("registrations = %+v, want both pages in order", registrations)
	}
	if registrations[1].Name() != "two" {
		t.Fatalf("device name = %q, want %q", registrations[1].Name(), "two")
	}
	if want := []string{"", "next"}; !reflect.DeepEqual(pages, want) {
		t.Fatalf("cursors requested = %v, want %v", pages, want)
	}
}

func TestAPIErrorIncludesCloudflareMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"authentication error"}]}`)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, "account", "bad", server.Client())
	_, err := client.EnsureConnector(context.Background(), "", "node-a", false)
	if err == nil || err.Error() != "list Cloudflare Mesh nodes: Cloudflare API HTTP 403: 10000: authentication error" {
		t.Fatalf("unexpected error: %v", err)
	}
}
