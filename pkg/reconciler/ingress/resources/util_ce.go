package resources

import (
	"errors"
	"log"

	istioclient "istio.io/client-go/pkg/apis/networking/v1beta1"
	istiolisters "knative.dev/net-istio/pkg/client/istio/listers/networking/v1beta1"
	knnetapi "knative.dev/networking/pkg/apis/networking/v1alpha1"
	knnetlisters "knative.dev/networking/pkg/client/listers/networking/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

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

type fakeServiceLister struct {
	services []*corev1.Service
	fails    bool
}

func (l *fakeServiceLister) List(selector labels.Selector) ([]*corev1.Service, error) {
	if l.fails {
		return nil, errors.New("failed to get Services")
	}
	results := []*corev1.Service{}
	for _, svc := range l.services {
		if selector.Matches(labels.Set(svc.Labels)) {
			results = append(results, svc)
		}
	}
	return results, nil
}

func (l *fakeServiceLister) Services(namespace string) corev1listers.ServiceNamespaceLister {
	if l.fails {
		return &fakeServiceNamespaceLister{fails: true}
	}

	var matches []*corev1.Service
	for _, service := range l.services {
		if service.Namespace == namespace {
			matches = append(matches, service)
		}
	}
	return &fakeServiceNamespaceLister{
		services: matches,
	}
}

func (l *fakeServiceLister) GetPodServices(_ *corev1.Pod) ([]*corev1.Service, error) {
	log.Panic("not implemented")
	return nil, nil
}

type fakeServiceNamespaceLister struct {
	services []*corev1.Service
	fails    bool
}

func (l *fakeServiceNamespaceLister) List(_ labels.Selector) ([]*corev1.Service, error) {
	return l.services, nil
}

func (l *fakeServiceNamespaceLister) Get(name string) (*corev1.Service, error) {
	for _, svc := range l.services {
		if svc.Name == name {
			return svc, nil
		}
	}
	return nil, apierrs.NewNotFound(corev1.Resource("Service"), name)
}

type fakeSecretLister struct {
	secrets []*corev1.Secret
	fails   bool
}

func (l *fakeSecretLister) List(selector labels.Selector) ([]*corev1.Secret, error) {
	if l.fails {
		return nil, errors.New("failed to get Secrets")
	}
	results := []*corev1.Secret{}
	for _, svc := range l.secrets {
		if selector.Matches(labels.Set(svc.Labels)) {
			results = append(results, svc)
		}
	}
	return results, nil
}

func (l *fakeSecretLister) Secrets(namespace string) corev1listers.SecretNamespaceLister {
	if l.fails {
		return &fakeSecretNamespaceLister{fails: true}
	}

	var matches []*corev1.Secret
	for _, secret := range l.secrets {
		if secret.Namespace == namespace {
			matches = append(matches, secret)
		}
	}
	return &fakeSecretNamespaceLister{
		secrets: matches,
	}
}

type fakeSecretNamespaceLister struct {
	secrets []*corev1.Secret
	fails   bool
}

func (l *fakeSecretNamespaceLister) List(_ labels.Selector) ([]*corev1.Secret, error) {
	return l.secrets, nil
}

func (l *fakeSecretNamespaceLister) Get(name string) (*corev1.Secret, error) {
	for _, svc := range l.secrets {
		if svc.Name == name {
			return svc, nil
		}
	}
	return nil, apierrs.NewNotFound(corev1.Resource("Secret"), name)
}

type fakeGatewayLister struct {
	gateways []*istioclient.Gateway
	fails    bool
}

func (l *fakeGatewayLister) Gateways(namespace string) istiolisters.GatewayNamespaceLister {
	if l.fails {
		return &fakeGatewayNamespaceLister{fails: true}
	}

	var matches []*istioclient.Gateway
	for _, gateway := range l.gateways {
		if gateway.Namespace == namespace {
			matches = append(matches, gateway)
		}
	}
	return &fakeGatewayNamespaceLister{
		gateways: matches,
	}
}

func (l *fakeGatewayLister) List(_ labels.Selector) ([]*istioclient.Gateway, error) {
	log.Panic("not implemented")
	return nil, nil
}

type fakeGatewayNamespaceLister struct {
	gateways []*istioclient.Gateway
	fails    bool
}

func (l *fakeGatewayNamespaceLister) List(selector labels.Selector) ([]*istioclient.Gateway, error) {
	if selector == nil {
		return l.gateways, nil
	}
	filteredGateways := []*istioclient.Gateway{}
	for _, gateway := range l.gateways {
		if selector.Matches(labels.Set(gateway.Labels)) {
			filteredGateways = append(filteredGateways, gateway)
		}
	}
	return filteredGateways, nil
}

func (l *fakeGatewayNamespaceLister) Get(_ string) (*istioclient.Gateway, error) {
	log.Panic("not implemented")
	return nil, nil
}
