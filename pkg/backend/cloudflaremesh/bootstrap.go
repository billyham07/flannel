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
	"time"

	meshapi "github.com/flannel-io/flannel/pkg/cloudflaremesh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func waitForOperatorCredentials(ctx context.Context, cfg *runtimeConfig) (*meshapi.ConnectorCredentials, error) {
	restConfig, err := operatorRESTConfig(cfg.Kubeconfig)
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client for cloudflare-mesh bootstrap: %w", err)
	}

	secretName := meshapi.NodeSecretName(cfg.OperatorSecretPrefix, cfg.NodeName)
	var credentials *meshapi.ConnectorCredentials
	err = wait.PollUntilContextTimeout(ctx, wait.Jitter(time.Second, 0.1), cfg.BootstrapWait, true, func(ctx context.Context) (bool, error) {
		secret, err := client.CoreV1().Secrets(cfg.OperatorNamespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		id := string(secret.Data[meshapi.SecretConnectorIDKey])
		name := string(secret.Data[meshapi.SecretConnectorNameKey])
		token := string(secret.Data[meshapi.SecretConnectorTokenKey])
		if id == "" || name == "" || token == "" {
			return false, nil
		}
		credentials = &meshapi.ConnectorCredentials{ID: id, Name: name, Token: token}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("wait for operator bootstrap Secret %s/%s: %w", cfg.OperatorNamespace, secretName, err)
	}
	return credentials, nil
}

func operatorRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("load bootstrap kubeconfig: %w", err)
		}
		return cfg, nil
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster bootstrap config: %w", err)
	}
	return cfg, nil
}
