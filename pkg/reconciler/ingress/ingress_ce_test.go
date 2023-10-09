package ingress

import (
	"context"
	"log"
	"strings"
	"testing"

	istioapi "istio.io/api/networking/v1beta1"
	istioclient "istio.io/client-go/pkg/apis/networking/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgotesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
	fakeistioclient "knative.dev/net-istio/pkg/client/istio/injection/client/fake"
	"knative.dev/net-istio/pkg/reconciler/ingress/config"
	"knative.dev/net-istio/pkg/reconciler/ingress/resources"
	reconcilertesting "knative.dev/net-istio/pkg/reconciler/testing"
	"knative.dev/networking/pkg/apis/networking"
	knnetapi "knative.dev/networking/pkg/apis/networking/v1alpha1"
	knnetlisters "knative.dev/networking/pkg/client/listers/networking/v1alpha1"
	netconfig "knative.dev/networking/pkg/config"
	fakestatusmanager "knative.dev/networking/pkg/testing/status"
	fakekubeclient "knative.dev/pkg/client/injection/kube/client/fake"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/logging"
	logtesting "knative.dev/pkg/logging/testing"
	pkgnet "knative.dev/pkg/network"
	rtesting "knative.dev/pkg/reconciler/testing"
	"knative.dev/pkg/system"
)

func TestFindKIngresses(t *testing.T) {

	secret := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "abc",
			Namespace: "default",
		},
	}

	ingressLister := &fakeIngressLister{
		ingresses: []*knnetapi.Ingress{
			{
				ObjectMeta: v1.ObjectMeta{
					Name:      "ingress1",
					Namespace: "default",
					OwnerReferences: []v1.OwnerReference{
						{
							Kind: "DomainMapping",
						},
					},
				},
				Spec: knnetapi.IngressSpec{
					TLS: []knnetapi.IngressTLS{
						{
							SecretName:      "abc",
							SecretNamespace: "default",
						},
					},
				},
			},
			{
				ObjectMeta: v1.ObjectMeta{
					Name:      "ingress2",
					Namespace: "default",
					OwnerReferences: []v1.OwnerReference{
						{
							Kind: "DomainMapping",
						},
					},
				},
				Spec: knnetapi.IngressSpec{
					TLS: []knnetapi.IngressTLS{
						{
							SecretName:      "def",
							SecretNamespace: "default",
						},
					},
				},
			},
			{
				ObjectMeta: v1.ObjectMeta{
					Name:      "ingress3",
					Namespace: "default",
					OwnerReferences: []v1.OwnerReference{
						{
							Kind: "NotDomainMapping",
						},
					},
				},
				Spec: knnetapi.IngressSpec{
					TLS: []knnetapi.IngressTLS{
						{
							SecretName:      "abc",
							SecretNamespace: "default",
						},
					},
				},
			},
		},
	}

	returnedIngress, err := FindKIngresses(ingressLister, secret)

	if err != nil {
		t.Error("unexpected error", err)
		return
	}

	if len(returnedIngress) != 1 {
		t.Errorf("ingress length expected 1 but got %v", len(returnedIngress))
		return
	}

	if returnedIngress[0].ObjectMeta.Name != "ingress1" {
		t.Errorf("wrong ingress returned %v", returnedIngress)
		return
	}
}

// TestReconcileIngress_DomainMappingHostInMultipleGateways verifies that a KIngress of a DomainMapping, whose host is
// still part of an old Gateway (e.g. because removing it failed with a conflict after it was added to the new Gateway),
// is repaired instead of being reported as up-to-date or as an error.
func TestReconcileIngress_DomainMappingHostInMultipleGateways(t *testing.T) {
	const (
		dmHost    = "dm1.example.com"
		otherHost = "dm2.example.com"
		oldHash   = "old-certificate-hash"
	)

	tests := []struct {
		name                  string
		otherHostInOldGateway bool
	}{{
		name:                  "old Gateway still serves other hosts, only the host is removed from it",
		otherHostInOldGateway: true,
	}, {
		name:                  "old Gateway only serves the host, it and its Secret are deleted",
		otherHostInOldGateway: false,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := logging.WithLogger(context.Background(), logtesting.TestLogger(t))
			ctx = controller.WithEventRecorder(ctx, record.NewFakeRecorder(100))
			ctx = config.ToContext(ctx, &config.Config{
				Istio: &config.Istio{
					IngressGateways: []config.Gateway{{
						Namespace:  system.Namespace(),
						Name:       config.KnativeIngressGateway,
						ServiceURL: pkgnet.GetServiceHostname("istio-ingressgateway", "istio-system"),
					}},
				},
				Network: &netconfig.Config{},
			})

			origin := originSecret(testNS, "dm-secret")
			newHash, err := resources.CalculateCertificateHash(ctx, origin)
			if err != nil {
				t.Fatal("unexpected error calculating certificate hash:", err)
			}

			dmIngress := domainMappingIngress(dmHost)
			otherIngress := domainMappingIngress(otherHost)

			svcListers := reconcilertesting.NewListers([]runtime.Object{ingressService})
			svcLister := svcListers.GetK8sServiceLister()

			// The new Gateway already contains the host, the old one still does as well.
			newGateway, err := resources.MakeGateway(ctx, svcLister, newHash, dmIngress, istioapi.ServerTLSSettings_SIMPLE)
			if err != nil {
				t.Fatal("unexpected error making new Gateway:", err)
			}
			newGateway.Name = "new-gateway"

			oldGateway, err := resources.MakeGateway(ctx, svcLister, oldHash, dmIngress, istioapi.ServerTLSSettings_SIMPLE)
			if err != nil {
				t.Fatal("unexpected error making old Gateway:", err)
			}
			oldGateway.Name = "old-gateway"
			if tc.otherHostInOldGateway {
				oldGateway, _, err = resources.EnsureGatewayCoversKIngress(oldGateway, otherIngress)
				if err != nil {
					t.Fatal("unexpected error extending old Gateway:", err)
				}
			}

			objects := []runtime.Object{
				origin,
				resources.MakeMirrorSecret(ctx, origin, newHash),
				resources.MakeMirrorSecret(ctx, origin, oldHash),
				ingressService,
				newGateway,
				oldGateway,
			}
			listers := reconcilertesting.NewListers(objects)

			ctx, istioClient := fakeistioclient.With(ctx, listers.GetIstioObjects()...)
			ctx, kubeClient := fakekubeclient.With(ctx, listers.GetKubeObjects()...)
			// Gateways use a custom resource name, so they have to be created explicitly.
			for _, gw := range []*istioclient.Gateway{newGateway, oldGateway} {
				if _, err := istioClient.NetworkingV1beta1().Gateways(gw.Namespace).Create(ctx, gw, v1.CreateOptions{}); err != nil {
					t.Fatal("unexpected error creating Gateway:", err)
				}
			}
			istioClient.ClearActions()
			kubeClient.ClearActions()

			r := &Reconciler{
				kubeclient:           kubeClient,
				istioClientSet:       istioClient,
				virtualServiceLister: listers.GetVirtualServiceLister(),
				gatewayLister:        listers.GetGatewayLister(),
				secretLister:         listers.GetSecretLister(),
				svcLister:            listers.GetK8sServiceLister(),
				ingressLister:        listers.GetIngressLister(),
				tracker:              &rtesting.NullTracker{},
				statusManager: &fakestatusmanager.FakeStatusManager{
					FakeIsReady: func(context.Context, *knnetapi.Ingress) (bool, error) {
						return true, nil
					},
				},
			}

			if err := r.reconcileIngress(ctx, dmIngress); err != nil {
				t.Fatal("unexpected error reconciling Ingress:", err)
			}

			var updatedGateways []*istioclient.Gateway
			var deletedGateways []string
			for _, action := range istioClient.Actions() {
				if action.GetResource().Resource != "gateways" {
					continue
				}
				switch a := action.(type) {
				case clientgotesting.UpdateAction:
					updatedGateways = append(updatedGateways, a.GetObject().(*istioclient.Gateway))
				case clientgotesting.DeleteAction:
					deletedGateways = append(deletedGateways, a.GetName())
				}
			}
			var deletedSecrets []string
			for _, action := range kubeClient.Actions() {
				if a, ok := action.(clientgotesting.DeleteAction); ok && a.GetResource().Resource == "secrets" {
					deletedSecrets = append(deletedSecrets, a.GetName())
				}
			}

			if tc.otherHostInOldGateway {
				if len(deletedGateways) != 0 {
					t.Errorf("expected no Gateway to be deleted, but got %v", deletedGateways)
				}
				if len(deletedSecrets) != 0 {
					t.Errorf("expected no Secret to be deleted, but got %v", deletedSecrets)
				}
				if len(updatedGateways) != 1 {
					t.Fatalf("expected exactly one Gateway update, but got %d", len(updatedGateways))
				}
				updated := updatedGateways[0]
				if updated.Name != oldGateway.Name {
					t.Errorf("expected update of Gateway %q, but got %q", oldGateway.Name, updated.Name)
				}
				for _, server := range updated.Spec.Servers {
					if len(server.Hosts) != 1 || server.Hosts[0] != otherHost {
						t.Errorf("expected only host %q in old Gateway server %q, but got %v", otherHost, server.Port.Name, server.Hosts)
					}
				}
				if strings.Contains(updated.Annotations["codeengine.cloud.ibm.com/kingresses"], dmHost) {
					t.Errorf("expected KIngress %q to be removed from the KIngresses annotation, but got %q", dmHost, updated.Annotations["codeengine.cloud.ibm.com/kingresses"])
				}
				return
			}

			if len(updatedGateways) != 0 {
				t.Errorf("expected no Gateway to be updated, but got %d updates", len(updatedGateways))
			}
			if len(deletedGateways) != 1 || deletedGateways[0] != oldGateway.Name {
				t.Errorf("expected Gateway %q to be deleted, but got %v", oldGateway.Name, deletedGateways)
			}
			if len(deletedSecrets) != 1 || deletedSecrets[0] != oldHash {
				t.Errorf("expected Secret %q to be deleted, but got %v", oldHash, deletedSecrets)
			}
		})
	}
}

func domainMappingIngress(host string) *knnetapi.Ingress {
	return &knnetapi.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Name:      host,
			Namespace: testNS,
			Labels: map[string]string{
				resources.RouteLabelKey:          "test-route",
				resources.RouteNamespaceLabelKey: testNS,
			},
			Annotations:     map[string]string{networking.IngressClassAnnotationKey: netconfig.IstioIngressClassName},
			ResourceVersion: "v1",
			OwnerReferences: []v1.OwnerReference{{Kind: "DomainMapping"}},
		},
		Spec: knnetapi.IngressSpec{
			HTTPOption: knnetapi.HTTPOptionEnabled,
			TLS: []knnetapi.IngressTLS{{
				Hosts:           []string{host},
				SecretName:      "dm-secret",
				SecretNamespace: testNS,
			}},
			Rules: []knnetapi.IngressRule{{
				Hosts:      []string{host},
				Visibility: knnetapi.IngressVisibilityExternalIP,
				HTTP: &knnetapi.HTTPIngressRuleValue{
					Paths: []knnetapi.HTTPIngressPath{{
						Splits: []knnetapi.IngressBackendSplit{{
							IngressBackend: knnetapi.IngressBackend{
								ServiceNamespace: testNS,
								ServiceName:      "test-service",
								ServicePort:      intstr.FromInt(80),
							},
							Percent: 100,
						}},
					}},
				},
			}},
		},
	}
}

type fakeIngressLister struct {
	ingresses []*knnetapi.Ingress
	fails     bool
}

func (l *fakeIngressLister) Ingresses(namespace string) knnetlisters.IngressNamespaceLister {
	if l.fails {
		return &fakeIngressNamespaceLister{fails: true}
	}

	var matches []*knnetapi.Ingress
	for _, ingress := range l.ingresses {
		if ingress.Namespace == namespace {
			matches = append(matches, ingress)
		}
	}
	return &fakeIngressNamespaceLister{
		ingresses: matches,
	}
}

func (l *fakeIngressLister) List(_ labels.Selector) ([]*knnetapi.Ingress, error) {
	log.Panic("not implemented")
	return nil, nil
}

type fakeIngressNamespaceLister struct {
	ingresses []*knnetapi.Ingress
	fails     bool
}

func (l *fakeIngressNamespaceLister) List(_ labels.Selector) ([]*knnetapi.Ingress, error) {
	return l.ingresses, nil
}

func (l *fakeIngressNamespaceLister) Get(name string) (*knnetapi.Ingress, error) {
	for _, ingress := range l.ingresses {
		if ingress.Name == name {
			return ingress, nil
		}
	}
	return nil, apierrs.NewNotFound(knnetapi.Resource("Ingress"), name)
}
