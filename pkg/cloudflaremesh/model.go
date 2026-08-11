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
	"crypto/sha256"
	"fmt"
)

const (
	BackendName             = "cloudflare-mesh"
	DefaultAnnotationPrefix = "flannel.alpha.coreos.com"
	SecretConnectorIDKey    = "connector-id"
	SecretConnectorNameKey  = "connector-name"
	SecretConnectorTokenKey = "connector-token"
	ManagedByLabel          = "app.kubernetes.io/managed-by"
	ManagedByOperator       = "cloudflare-mesh-operator"
)

type LeaseData struct {
	ConnectorID string `json:"connectorID"`
	MeshIP      string `json:"meshIP"`
}

func NodeSecretName(prefix, nodeName string) string {
	return boundedName(prefix+nodeName, 253)
}

func ConnectorName(prefix, clusterName, nodeName string) string {
	return boundedName(prefix+clusterName+"-"+nodeName, 64)
}

func RouteComment(clusterName, nodeName, network string) string {
	return boundedName(fmt.Sprintf("flannel:%s:%s:%s", clusterName, nodeName, network), 100)
}

func RouteCommentPrefix(clusterName string) string {
	return fmt.Sprintf("flannel:%s:", clusterName)
}

func boundedName(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(value)))[:12]
	return value[:limit-len(digest)-1] + "-" + digest
}
