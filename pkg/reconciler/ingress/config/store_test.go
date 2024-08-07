/*
Copyright 2018 The Knative Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	logtesting "knative.dev/pkg/logging/testing"

	network "knative.dev/networking/pkg"
	netconfig "knative.dev/networking/pkg/config"
	. "knative.dev/pkg/configmap/testing"
)

func TestStoreLoadWithContext(t *testing.T) {
	store := NewStore(logtesting.TestLogger(t))

	istioConfig := ConfigMapFromTestFile(t, IstioConfigName)
	networkConfig := ConfigMapFromTestFile(t, netconfig.ConfigMapName)
	store.OnConfigChanged(istioConfig)
	store.OnConfigChanged(networkConfig)
	config := FromContext(store.ToContext(context.Background()))

	expectedIstio, _ := NewIstioFromConfigMap(istioConfig)
	if diff := cmp.Diff(expectedIstio, config.Istio); diff != "" {
		t.Error("Unexpected istio config (-want, +got):", diff)
	}

	expectNetworkConfig, _ := network.NewConfigFromConfigMap(networkConfig)
	if diff := cmp.Diff(expectNetworkConfig, config.Network); diff != "" {
		t.Error("Unexpected TLS mode (-want, +got):", diff)
	}
}

func TestStoreImmutableConfig(t *testing.T) {
	store := NewStore(logtesting.TestLogger(t))

	store.OnConfigChanged(ConfigMapFromTestFile(t, IstioConfigName))
	store.OnConfigChanged(ConfigMapFromTestFile(t, netconfig.ConfigMapName))

	config := store.Load()

	config.Istio.IngressGateways = []Gateway{{Name: "mutated", ServiceURL: "mutated"}}
	config.Network.HTTPProtocol = netconfig.HTTPRedirected

	newConfig := store.Load()

	if newConfig.Istio.IngressGateways[0].Name == "mutated" {
		t.Error("Istio config is not immutable")
	}
	if newConfig.Network.HTTPProtocol == netconfig.HTTPRedirected {
		t.Error("Network config is not immuable")
	}
}
