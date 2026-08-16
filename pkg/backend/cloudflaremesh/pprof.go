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
	"net"
	"net/http"
	"net/http/pprof"
	"sync"
	"time"

	log "k8s.io/klog/v2"
)

// pprofAddrEnv turns on a pprof listener at the given address, for example
// "127.0.0.1:6060". The dataplane runs entirely inside flanneld, so a CPU or
// allocation regression in it can only be attributed from inside this process;
// without pprof the best available evidence is a GC trace, which says how much
// garbage there is but not where it comes from.
//
// It is off unless the variable is set, and the listener carries the pprof
// handlers only. Bind it to the loopback address unless the node's network is
// trusted: profiles are not sensitive in themselves, but the endpoint is an
// easy way to make a busy process busier.
const pprofAddrEnv = "CLOUDFLARE_MESH_PPROF_ADDR"

var pprofOnce sync.Once

func startPprofIfRequested() {
	addr := envOrDefault(pprofAddrEnv, "")
	if addr == "" {
		return
	}
	pprofOnce.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Errorf("cloudflare-mesh: %s=%q could not be served: %v", pprofAddrEnv, addr, err)
			return
		}
		log.Infof("cloudflare-mesh: serving pprof on %s", listener.Addr())
		// ReadHeaderTimeout only; a CPU or trace profile is a deliberately long
		// response and must not be cut off by a write deadline.
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				log.Errorf("cloudflare-mesh: pprof listener stopped: %v", err)
			}
		}()
	})
}
