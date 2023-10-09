package resources

import (
	"context"
	"fmt"
	"testing"

	istioapi "istio.io/api/networking/v1beta1"
	istioclient "istio.io/client-go/pkg/apis/networking/v1beta1"
	knnetapi "knative.dev/networking/pkg/apis/networking/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/google/go-cmp/cmp"
	"knative.dev/net-istio/pkg/reconciler/ingress/config"
)

func TestRemoveKIngressFromGateway(t *testing.T) {
	cases := []struct {
		name             string
		originalHosts    []string
		inputHost        string
		expectedHosts    []string
		expectedDeletion bool
	}{
		{
			name:             "Gateway without the host that should be removed",
			originalHosts:    []string{"host1", "host2"},
			inputHost:        "host3",
			expectedHosts:    nil,
			expectedDeletion: false,
		},
		{
			name:             "Gateway with the host that should be removed",
			originalHosts:    []string{"host1", "host2"},
			inputHost:        "host1",
			expectedHosts:    []string{"host2"},
			expectedDeletion: false,
		},
		{
			name:             "Gateway with the host that should be removed, but is the only host available",
			originalHosts:    []string{"host1"},
			inputHost:        "host1",
			expectedHosts:    nil,
			expectedDeletion: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kingresses := "["
			for _, host := range c.originalHosts {
				if len(kingresses) > 1 {
					kingresses += ","
				}
				kingresses += fmt.Sprintf(`{"namespace":"customer-namespace","name":%q}`, host)
			}
			kingresses += "]"

			originalGateway := &istioclient.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gw",
					Namespace: config.IstioNamespace,
					Annotations: map[string]string{
						annotationKeyKIngresses: kingresses,
					},
					Labels: map[string]string{
						labelKeyDomainMappingGateway: labelValueDomainMappingGateway,
					},
				},
				Spec: istioapi.Gateway{
					Servers: []*istioapi.Server{{
						Hosts: c.originalHosts,
						Port: &istioapi.Port{
							Name:     "https",
							Number:   443,
							Protocol: "HTTPS",
						},
						Tls: &istioapi.ServerTLSSettings{
							Mode:              istioapi.ServerTLSSettings_SIMPLE,
							ServerCertificate: corev1.TLSCertKey,
							PrivateKey:        corev1.TLSPrivateKeyKey,
							CredentialName:    "hash",
						},
					}, {
						Hosts: c.originalHosts,
						Port: &istioapi.Port{
							Name:     "http",
							Number:   80,
							Protocol: "HTTP",
						},
						Tls: &istioapi.ServerTLSSettings{
							HttpsRedirect: true,
						},
					}},
				},
			}

			kingress := &knnetapi.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "customer-namespace",
					Name:      c.inputHost,
				},
			}
			returnedGateway, returnedDeletionRequested, err := RemoveKIngressFromGateway(originalGateway, kingress)
			if err != nil {
				t.Error("Got error", err)
				return
			}

			if returnedDeletionRequested != c.expectedDeletion {
				t.Errorf("Unexpected deletionRequested. Expected: %v, got: %v", c.expectedDeletion, returnedDeletionRequested)
			}

			if returnedGateway == nil {
				if len(c.expectedHosts) > 0 {
					t.Error("Unexpected nil for returned gateway")
				}
			} else {
				if len(c.expectedHosts) == 0 {
					t.Error("Expected nil for returned gateway")
				}

				if diff := cmp.Diff(c.expectedHosts, returnedGateway.Spec.Servers[0].Hosts, defaultGatewayCmpOpts); diff != "" {
					t.Error("Unexpected servers (-want, +got):", diff)
				}

				kingresses := "["
				for _, host := range c.expectedHosts {
					if len(kingresses) > 1 {
						kingresses += ","
					}
					kingresses += fmt.Sprintf(`{"namespace":"customer-namespace","name":%q}`, host)
				}
				kingresses += "]"

				if kingresses != returnedGateway.Annotations[annotationKeyKIngresses] {
					t.Errorf("Unexpected KIngresses annotation, expected: %s, got: %s", kingresses, returnedGateway.Annotations[annotationKeyKIngresses])
				}
			}
		})
	}
}

func TestEnsureGatewayCoversKIngress(t *testing.T) {
	cases := []struct {
		name           string
		Hosts          []string
		inputHost      string
		expectedHosts  []string
		gatewayChanged bool
	}{
		{
			name:           "Gateway contains the host",
			Hosts:          []string{"host1", "host2"},
			inputHost:      "host1",
			expectedHosts:  nil,
			gatewayChanged: false,
		},
		{
			name:           "Gateway does not contains host",
			Hosts:          []string{"host1", "host2"},
			inputHost:      "host3",
			expectedHosts:  []string{"host1", "host2", "host3"},
			gatewayChanged: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kingresses := "["
			for _, host := range c.Hosts {
				if len(kingresses) > 1 {
					kingresses += ","
				}
				kingresses += fmt.Sprintf(`{"namespace":"customer-namespace","name":%q}`, host)
			}
			kingresses += "]"

			originalGateway := &istioclient.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gw",
					Namespace: config.IstioNamespace,
					Annotations: map[string]string{
						annotationKeyKIngresses: kingresses,
					},
					Labels: map[string]string{
						labelKeyDomainMappingGateway: labelValueDomainMappingGateway,
					},
				},
				Spec: istioapi.Gateway{
					Servers: []*istioapi.Server{{
						Hosts: c.Hosts,
						Port: &istioapi.Port{
							Name:     "https",
							Number:   443,
							Protocol: "HTTPS",
						},
						Tls: &istioapi.ServerTLSSettings{
							Mode:              istioapi.ServerTLSSettings_SIMPLE,
							ServerCertificate: corev1.TLSCertKey,
							PrivateKey:        corev1.TLSPrivateKeyKey,
							CredentialName:    "hash",
						},
					}, {
						Hosts: c.Hosts,
						Port: &istioapi.Port{
							Name:     "http",
							Number:   80,
							Protocol: "HTTP",
						},
						Tls: &istioapi.ServerTLSSettings{
							HttpsRedirect: true,
						},
					}},
				},
			}

			kingress := &knnetapi.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "customer-namespace",
					Name:      c.inputHost,
				},
			}

			returnedGateway, returnedStatus, err := EnsureGatewayCoversKIngress(originalGateway, kingress)
			if err != nil {
				t.Error("Got error", err)
				return
			}

			if returnedStatus != c.gatewayChanged {
				t.Errorf("Unexpected returnedStatus, Expected: %v, got: %v", c.gatewayChanged, returnedStatus)
			}

			if returnedStatus == true {
				if returnedGateway == nil {
					t.Error("Unexpected nil for returned gateway")
				} else {
					if diff := cmp.Diff(c.expectedHosts, returnedGateway.Spec.Servers[0].Hosts, defaultGatewayCmpOpts); diff != "" {
						t.Error("Unexpected servers (-want, +got):", diff)
					}

					kingresses := "["
					for _, host := range c.expectedHosts {
						if len(kingresses) > 1 {
							kingresses += ","
						}
						kingresses += fmt.Sprintf(`{"namespace":"customer-namespace","name":%q}`, host)
					}
					kingresses += "]"

					if kingresses != returnedGateway.Annotations[annotationKeyKIngresses] {
						t.Errorf("Unexpected KIngresses annotation, expected: %s, got: %s", kingresses, returnedGateway.Annotations[annotationKeyKIngresses])
					}
				}
			}
		})
	}
}

func TestMakeGateway(t *testing.T) {
	serviceLister := &fakeServiceLister{
		services: []*corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: config.IstioNamespace,
				Name:      "gateway",
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"gwt": "istio",
				},
			},
		}},
	}

	kingress := &knnetapi.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "customer-namespace",
			Name:      "abc",
		},
	}

	ctx := config.ToContext(context.Background(), &config.Config{
		Istio: &config.Istio{
			IngressGateways: []config.Gateway{{
				Name:       "gateway",
				Namespace:  config.IstioNamespace,
				ServiceURL: "gateway.istio-system.svc.cluster.local",
			}},
		},
	})

	certificateHash := "2152137217362176376"

	returnedGateway, err := MakeGateway(ctx, serviceLister, certificateHash, kingress)

	if err != nil {
		t.Error("Got error", err)
		return
	}

	expectedGateway := &istioclient.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      returnedGateway.Name,
			Namespace: config.IstioNamespace,
			Annotations: map[string]string{
				annotationKeyKIngresses: `[{"namespace":"customer-namespace","name":"abc"}]`,
			},
			Labels: map[string]string{
				labelKeyDomainMappingGateway: labelValueDomainMappingGateway,
				labelKeyCertificateHash:      certificateHash,
			},
		},
		TypeMeta: metav1.TypeMeta{
			APIVersion: GatewayGroupVersionKind.GroupVersion().String(),
			Kind:       GatewayGroupVersionKind.Kind,
		},
		Spec: istioapi.Gateway{
			Selector: map[string]string{
				"gwt": "istio",
			},
			Servers: []*istioapi.Server{{
				Hosts: []string{
					"abc",
				},
				Port: &istioapi.Port{
					Name:     "https",
					Number:   443,
					Protocol: "HTTPS",
				},
				Tls: &istioapi.ServerTLSSettings{
					Mode:              istioapi.ServerTLSSettings_SIMPLE,
					ServerCertificate: corev1.TLSCertKey,
					PrivateKey:        corev1.TLSPrivateKeyKey,
					CredentialName:    certificateHash,
				},
			}, {
				Hosts: []string{
					"abc",
				},
				Port: &istioapi.Port{
					Name:     "http",
					Number:   80,
					Protocol: "HTTP",
				},
				Tls: &istioapi.ServerTLSSettings{
					HttpsRedirect: true,
				},
			}},
		},
	}

	if diff := cmp.Diff(expectedGateway, returnedGateway, defaultGatewayCmpOpts); diff != "" {
		t.Error("Unexpected Gateway (-want, +got):", diff)
	}
}

func TestFindGatewaysByCertificateHash(t *testing.T) {
	gatewayLister := &fakeGatewayLister{
		gateways: []*istioclient.Gateway{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: config.IstioNamespace,
					Name:      "gateway1",
					Labels: map[string]string{
						labelKeyCertificateHash: "abcd",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: config.IstioNamespace,
					Name:      "gateway2",
					Labels: map[string]string{
						labelKeyCertificateHash: "efgh",
					},
				},
			},
		},
	}

	filteredGateways, err := FindGatewaysByCertificateHash(gatewayLister, "abcd")

	if err != nil {
		t.Error("Got error", err)
		return
	}

	if len(filteredGateways) != 1 {
		t.Errorf("Filtered Gateway not correct %v", filteredGateways)
		return
	}

	if filteredGateways[0].ObjectMeta.Name != "gateway1" {
		t.Error("Unexpected Gateway")
		return
	}

}

func TestFindGatewaysByHost(t *testing.T) {
	gatewayLister := &fakeGatewayLister{
		gateways: []*istioclient.Gateway{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: config.IstioNamespace,
					Name:      "gateway1",
					Labels: map[string]string{
						labelKeyDomainMappingGateway: labelValueDomainMappingGateway,
					},
				},
				Spec: istioapi.Gateway{
					Servers: []*istioapi.Server{{
						Hosts: []string{"abc", "def"},
						Port: &istioapi.Port{
							Number:   80,
							Protocol: "HTTP",
						},
					}},
					Selector: map[string]string{
						"gwt": "istio",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: config.IstioNamespace,
					Name:      "gateway2",
					Labels: map[string]string{
						labelKeyDomainMappingGateway: labelValueDomainMappingGateway,
					},
				},
				Spec: istioapi.Gateway{
					Servers: []*istioapi.Server{{
						Hosts: []string{"def"},
						Port: &istioapi.Port{
							Number:   80,
							Protocol: "HTTP",
						},
					}},
					Selector: map[string]string{
						"gwt": "istio",
					},
				},
			},
		},
	}

	host := "abc"

	filteredGateways, err := FindGatewaysByHost(gatewayLister, host)

	if err != nil {
		t.Error("Got error", err)
		return
	}

	if len(filteredGateways) != 1 {
		t.Errorf("Filtered Gateway not correct %v", filteredGateways)
		return
	}

	if filteredGateways[0].ObjectMeta.Name != "gateway1" {
		t.Error("Unexpected Gateway")
		return
	}
}

func TestFindGatewaysByKIngress(t *testing.T) {
	gatewayLister := &fakeGatewayLister{
		gateways: []*istioclient.Gateway{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: config.IstioNamespace,
					Name:      "gateway1",
					Annotations: map[string]string{
						annotationKeyKIngresses: `[{"namespace":"user-namespace","name":"abc"}]`,
					},
					Labels: map[string]string{
						labelKeyDomainMappingGateway: labelValueDomainMappingGateway,
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: config.IstioNamespace,
					Name:      "gateway2",
					Annotations: map[string]string{
						annotationKeyKIngresses: `[{"namespace":"user-namespace-2","name":"abc"},{"namespace":"user-namespace","name":"def"}]`,
					},
					Labels: map[string]string{
						labelKeyDomainMappingGateway: labelValueDomainMappingGateway,
					},
				},
			},
		},
	}

	filteredGateways, err := FindGatewaysByKIngress(gatewayLister, &knnetapi.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "user-namespace",
			Name:      "abc",
		},
	})

	if err != nil {
		t.Error("Got error", err)
		return
	}

	if len(filteredGateways) != 1 {
		t.Errorf("Filtered Gateway not correct %v", filteredGateways)
		return
	}

	if filteredGateways[0].ObjectMeta.Name != "gateway1" {
		t.Error("Unexpected Gateway")
		return
	}
}

func TestGetCertificateHash(t *testing.T) {
	_, err := GetCertificateHash(&istioclient.Gateway{})
	if err == nil {
		t.Error("Expected to get error")
		return
	}

	certificateHash, err := GetCertificateHash(&istioclient.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				labelKeyCertificateHash: "abcd",
			},
		},
	})

	if err != nil {
		t.Error("Got error", err)
		return
	}

	if certificateHash != "abcd" {
		t.Error("certificateHash is not returned")
	}
}

func TestIsGatewayForCertificate(t *testing.T) {
	gateway := &istioclient.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				labelKeyCertificateHash: "abc",
			},
		},
	}

	is := IsGatewayForCertificate(gateway, "abc")
	if !is {
		t.Error("Should have returned true")
		return
	}

	is = IsGatewayForCertificate(gateway, "def")
	if is {
		t.Error("Should have returned false")
		return
	}
}

func TestUpdateGatewayForNewCertificate(t *testing.T) {
	gateway := &istioclient.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				labelKeyCertificateHash: "abc",
			},
		},
		Spec: istioapi.Gateway{
			Servers: []*istioapi.Server{{
				Tls: &istioapi.ServerTLSSettings{
					CredentialName: "abc",
				},
			}},
		},
	}

	updatedGateway := UpdateGatewayForNewCertificate(gateway, "def")

	expectedGateway := &istioclient.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				labelKeyCertificateHash: "def",
			},
		},
		Spec: istioapi.Gateway{
			Servers: []*istioapi.Server{{
				Tls: &istioapi.ServerTLSSettings{
					CredentialName: "def",
				},
			}},
		},
	}

	if diff := cmp.Diff(expectedGateway, updatedGateway, defaultGatewayCmpOpts); diff != "" {
		t.Error("Unexpected Gateway (-want, +got):", diff)
	}
}

func TestAreAllKIngressesReferencingCertificate(t *testing.T) {
	secret1, err := GenerateCertificate([]string{"abc"}, "secret1", "user-namespace")
	if err != nil {
		t.Error("Got error", err)
		return
	}

	secret2, err := GenerateCertificate([]string{"abc"}, "secret2", "user-namespace")
	if err != nil {
		t.Error("Got error", err)
		return
	}

	secretLister := &fakeSecretLister{
		secrets: []*corev1.Secret{secret1, secret2},
	}

	certificateHash, err := CalculateCertificateHash(secret1)
	if err != nil {
		t.Error("Got error", err)
		return
	}

	ingressLister := &fakeIngressLister{
		ingresses: []*knnetapi.Ingress{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "user-namespace",
				Name:      "kingress1",
			},
			Spec: knnetapi.IngressSpec{
				TLS: []knnetapi.IngressTLS{{
					SecretName: secret1.Name,
				}},
			},
		}, {
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "user-namespace",
				Name:      "kingress2",
			},
			Spec: knnetapi.IngressSpec{
				TLS: []knnetapi.IngressTLS{{
					SecretName: secret1.Name,
				}},
			},
		}, {
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "user-namespace",
				Name:      "kingress3",
			},
			Spec: knnetapi.IngressSpec{
				TLS: []knnetapi.IngressTLS{{
					SecretName: secret2.Name,
				}},
			},
		}},
	}

	gateway := &istioclient.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				annotationKeyKIngresses: `[{"namespace":"user-namespace","name":"kingress1"},{"namespace":"user-namespace","name":"kingress2"}]`,
			},
			Labels: map[string]string{
				labelKeyCertificateHash: certificateHash,
			},
		},
		Spec: istioapi.Gateway{
			Servers: []*istioapi.Server{{
				Tls: &istioapi.ServerTLSSettings{
					CredentialName: certificateHash,
				},
			}},
		},
	}

	are, err := AreAllKIngressesReferencingCertificate(ingressLister, secretLister, gateway, certificateHash)
	if err != nil {
		t.Error("Got error", err)
		return
	}

	if !are {
		t.Error("Should have returned true")
		return
	}

	gateway = &istioclient.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				annotationKeyKIngresses: `[{"namespace":"user-namespace","name":"kingress1"},{"namespace":"user-namespace","name":"kingress3"}]`,
			},
			Labels: map[string]string{
				labelKeyCertificateHash: certificateHash,
			},
		},
		Spec: istioapi.Gateway{
			Servers: []*istioapi.Server{{
				Tls: &istioapi.ServerTLSSettings{
					CredentialName: certificateHash,
				},
			}},
		},
	}

	are, err = AreAllKIngressesReferencingCertificate(ingressLister, secretLister, gateway, certificateHash)
	if err != nil {
		t.Error("Got error", err)
		return
	}

	if are {
		t.Error("Should have returned false")
		return
	}
}

func TestIsGatewayContainingHost(t *testing.T) {
	gateway := &istioclient.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				labelKeyCertificateHash: "abc",
			},
		},
		Spec: istioapi.Gateway{
			Servers: []*istioapi.Server{{
				Tls: &istioapi.ServerTLSSettings{
					CredentialName: "abc",
				},
				Hosts: []string{
					"testHost", "testHost2",
				},
			}},
		},
	}

	gatewayContainsHost := IsGatewayContainingHost(gateway, "testHost")
	if !gatewayContainsHost {
		t.Error("gateway contains host should be true")
	}

	gatewayContainsHost = IsGatewayContainingHost(gateway, "notContainedHost")
	if gatewayContainsHost {
		t.Error("gateway contains host should be false")
	}

}
