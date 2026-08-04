package ingress

import (
	"log"
	"testing"

	"istio.io/api/networking/v1alpha3"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	knnetapi "knative.dev/networking/pkg/apis/networking/v1alpha1"
	knnetlisters "knative.dev/networking/pkg/client/listers/networking/v1alpha1"
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

func TestGetTlsModeIngress(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "abc",
			Namespace: "default",
		},
		Data: map[string][]byte{"ca.crt": {}},
	}
	ingress := &knnetapi.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Name:      "ingress1",
			Namespace: "default",
			Annotations: map[string]string{
				annotationTlsMode: tlsModeMutual,
			},
		},
	}
	mode, err := getTlsMode(ingress, secret)
	if err != nil {
		t.Error("unexpected error", err)
		return
	}
	if mode != v1alpha3.ServerTLSSettings_MUTUAL {
		t.Errorf("wrong TLS mode returned %v", mode)
		return
	}
}

func TestGetTlsModeSecret(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "abc",
			Namespace: "default",
			Annotations: map[string]string{
				annotationTlsMode: tlsModeMutual,
			},
		},
		Data: map[string][]byte{"ca.crt": {}},
	}
	ingress := &knnetapi.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Name:      "ingress1",
			Namespace: "default",
		},
	}
	mode, err := getTlsMode(ingress, secret)
	if err != nil {
		t.Error("unexpected error", err)
		return
	}
	if mode != v1alpha3.ServerTLSSettings_MUTUAL {
		t.Errorf("wrong TLS mode returned %v", mode)
		return
	}
}

func TestGetTlsModeNoCA(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "abc",
			Namespace: "default",
			Annotations: map[string]string{
				annotationTlsMode: tlsModeMutual,
			},
		},
	}
	ingress := &knnetapi.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Name:      "ingress1",
			Namespace: "default",
		},
	}
	_, err := getTlsMode(ingress, secret)
	if err == nil {
		t.Error("expected error, got none")
		return
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
