package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	istioapi "istio.io/api/networking/v1beta1"
	istioclient "istio.io/client-go/pkg/apis/networking/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	corev1listers "k8s.io/client-go/listers/core/v1"
	istiolisters "knative.dev/net-istio/pkg/client/istio/listers/networking/v1beta1"
	"knative.dev/net-istio/pkg/reconciler/ingress/config"
	knnetapi "knative.dev/networking/pkg/apis/networking/v1alpha1"
	knnetlisters "knative.dev/networking/pkg/client/listers/networking/v1alpha1"
)

const (
	annotationKeyKIngresses        = "codeengine.cloud.ibm.com/kingresses"
	labelKeyDomainMappingGateway   = "codeengine.cloud.ibm.com/domain-mapping-gateway"
	labelValueDomainMappingGateway = "true"
	labelKeyCertificateHash        = "codeengine.cloud.ibm.com/certificate-hash"
)

var (
	GatewayGroupVersionKind = istioclient.SchemeGroupVersion.WithKind("Gateway")
)

type namespacedName struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// RemoveKIngressFromGateway removes a host from a Gateway or "asks" for deletion
// The function returns:
// - a modified Gateway and false when the existing Gateway requires an update
// - nil and true indicating that it can be deleted
// - nil and false indicating that no update is necessary
func RemoveKIngressFromGateway(gateway *istioclient.Gateway, kingress *knnetapi.Ingress) (*istioclient.Gateway, bool, error) {
	gatewayIndex := -1
	for i, existingHost := range gateway.Spec.Servers[0].Hosts {
		if existingHost == kingress.Name {
			gatewayIndex = i
			break
		}
	}

	// Gateway does not contain host
	if gatewayIndex == -1 {
		return nil, false, nil
	}

	// Gateway contains only this host, it should get deleted
	hostsLength := len(gateway.Spec.Servers[0].Hosts)
	if hostsLength == 1 {
		return nil, true, nil
	}

	// Gateway contains multiple hosts, remove it
	modifiedGateway := gateway.DeepCopy()
	modifiedGateway.Spec.Servers[0].Hosts[gatewayIndex] = modifiedGateway.Spec.Servers[0].Hosts[hostsLength-1]
	modifiedGateway.Spec.Servers[0].Hosts = modifiedGateway.Spec.Servers[0].Hosts[:hostsLength-1]
	modifiedGateway.Spec.Servers[1].Hosts = modifiedGateway.Spec.Servers[0].Hosts

	// also remove it from the KIngresses annotation
	kingressesNamespacedNames, err := extractSourceKIngresses(gateway)
	if err != nil {
		return nil, false, err
	}
	kingressIndex := -1
	for i, kingressNamespacedName := range kingressesNamespacedNames {
		if kingressNamespacedName.Name == kingress.Name && kingressNamespacedName.Namespace == kingress.Namespace {
			kingressIndex = i
			break
		}
	}
	if kingressIndex == -1 {
		return nil, false, fmt.Errorf("did not find KIngress %s/%s in KIngresses list of Gateway %s", kingress.Namespace, kingress.Name, gateway.Name)
	}
	kingressesNamespacedNamesLength := len(kingressesNamespacedNames)
	kingressesNamespacedNames[kingressIndex] = kingressesNamespacedNames[kingressesNamespacedNamesLength-1]
	kingressesNamespacedNames = kingressesNamespacedNames[:kingressesNamespacedNamesLength-1]
	kingressesNamespacedNamesJSON, err := json.Marshal(kingressesNamespacedNames)
	if err != nil {
		return nil, false, err
	}
	modifiedGateway.Annotations[annotationKeyKIngresses] = string(kingressesNamespacedNamesJSON)

	return modifiedGateway, false, nil
}

// Check if Gateway is containing host
// - true if host is contained in gateway
// - false if host is not contained in gateway
func IsGatewayContainingHost(gateway *istioclient.Gateway, hostName string) bool {
	// it is enough the check the first server because all get the same hosts
	for _, existingHost := range gateway.Spec.Servers[0].Hosts {
		if existingHost == hostName {
			return true
		}
	}
	return false
}

// EnsureGatewayCoversKIngress takes a Gateway and ensures it contains the host of a provided KIngress. It returns:
// - nil and false if the Gateway already contains the provided host
// - a modified clone of the Gateway and true when the host had to be added
func EnsureGatewayCoversKIngress(gateway *istioclient.Gateway, kingress *knnetapi.Ingress) (*istioclient.Gateway, bool, error) {
	if IsGatewayContainingHost(gateway, kingress.Name) {
		return nil, false, nil
	}

	// clone the gateway and add the host
	modifiedGateway := gateway.DeepCopy()
	for i := range modifiedGateway.Spec.Servers {
		modifiedGateway.Spec.Servers[i].Hosts = append(modifiedGateway.Spec.Servers[i].Hosts, kingress.Name)
	}

	// update the KIngress annotation
	kingressesNamespacedNames, err := extractSourceKIngresses(gateway)
	if err != nil {
		return nil, false, err
	}
	kingressesNamespacedNames = append(kingressesNamespacedNames, namespacedName{
		Namespace: kingress.Namespace,
		Name:      kingress.Name,
	})
	kingressesNamespacedNamesJSON, err := json.Marshal(kingressesNamespacedNames)
	if err != nil {
		return nil, false, err
	}
	modifiedGateway.Annotations[annotationKeyKIngresses] = string(kingressesNamespacedNamesJSON)

	return modifiedGateway, true, err
}

// MakeGateway creates a Gateway object for a certificate hash and KIngress
func MakeGateway(ctx context.Context, svcLister corev1listers.ServiceLister, certificateHash string, kingress *knnetapi.Ingress) (*istioclient.Gateway, error) {
	gatewayServices, err := getGatewayServices(ctx, svcLister)
	if err != nil {
		return nil, err
	}

	// We only have one ingress deployment
	if len(gatewayServices) != 1 {
		return nil, fmt.Errorf("expected exactly one Gateway Service, but got %d", len(gatewayServices))
	}

	kingressesNamespacedNames := []namespacedName{{
		Namespace: kingress.Namespace,
		Name:      kingress.Name,
	}}

	kingressesNamespacedNamesJSON, err := json.Marshal(kingressesNamespacedNames)
	if err != nil {
		return nil, err
	}

	return &istioclient.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      uuid.New().String(),
			Namespace: config.IstioNamespace,
			Annotations: map[string]string{
				annotationKeyKIngresses: string(kingressesNamespacedNamesJSON),
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
			Selector: gatewayServices[0].Spec.Selector,
			Servers: []*istioapi.Server{{
				Hosts: []string{
					kingress.Name,
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
					kingress.Name,
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
	}, nil
}

// FindGatewaysByHost looks for existing Gateway that map a host
func FindGatewaysByHost(gatewayLister istiolisters.GatewayLister, host string) ([]*istioclient.Gateway, error) {
	req, err := labels.NewRequirement(labelKeyDomainMappingGateway, selection.Equals, []string{labelValueDomainMappingGateway})
	if err != nil {
		return nil, err
	}

	selector := labels.NewSelector()
	selector = selector.Add(*req)

	gateways, err := gatewayLister.Gateways(config.IstioNamespace).List(selector)
	if err != nil {
		return nil, err
	}

	var filteredGateways []*istioclient.Gateway

	for _, gateway := range gateways {
		if IsGatewayContainingHost(gateway, host) {
			filteredGateways = append(filteredGateways, gateway)
		}
	}

	return filteredGateways, nil
}

// FindGatewaysByKIngress looks for existing Gateway that are created for a KIngress
func FindGatewaysByKIngress(gatewayLister istiolisters.GatewayLister, kingress *knnetapi.Ingress) ([]*istioclient.Gateway, error) {
	req, err := labels.NewRequirement(labelKeyDomainMappingGateway, selection.Equals, []string{labelValueDomainMappingGateway})
	if err != nil {
		return nil, err
	}

	selector := labels.NewSelector()
	selector = selector.Add(*req)

	gateways, err := gatewayLister.Gateways(config.IstioNamespace).List(selector)
	if err != nil {
		return nil, err
	}

	var filteredGateways []*istioclient.Gateway

	for _, gateway := range gateways {
		kingressesNamespacedNames, err := extractSourceKIngresses(gateway)
		if err != nil {
			return nil, err
		}

		for _, kingressNamespacedName := range kingressesNamespacedNames {
			if kingressNamespacedName.Namespace == kingress.Namespace && kingressNamespacedName.Name == kingress.Name {
				filteredGateways = append(filteredGateways, gateway)
				break
			}
		}
	}

	return filteredGateways, nil
}

// FindGatewaysByCertificateHash looks all gateways with certificate
func FindGatewaysByCertificateHash(gatewayLister istiolisters.GatewayLister, certificateHash string) ([]*istioclient.Gateway, error) {
	req, err := labels.NewRequirement(labelKeyCertificateHash, selection.Equals, []string{certificateHash})
	if err != nil {
		return nil, err
	}

	selector := labels.NewSelector()
	selector = selector.Add(*req)

	return gatewayLister.Gateways(config.IstioNamespace).List(selector)
}

// IsGatewayForCertificate checks whether a Gateway is for a certificateHash
func IsGatewayForCertificate(gateway *istioclient.Gateway, certificateHash string) bool {
	return gateway.Labels[labelKeyCertificateHash] == certificateHash
}

// UpdateGatewayForNewCertificate updates a Gateway to point to a new certificate
func UpdateGatewayForNewCertificate(gateway *istioclient.Gateway, certificateHash string) *istioclient.Gateway {
	modifiedGateway := gateway.DeepCopy()

	modifiedGateway.Labels[labelKeyCertificateHash] = certificateHash

	for i := range modifiedGateway.Spec.Servers {
		if modifiedGateway.Spec.Servers[i].Tls != nil {
			modifiedGateway.Spec.Servers[i].Tls.CredentialName = certificateHash
		}
	}

	return modifiedGateway
}

func extractSourceKIngresses(gateway *istioclient.Gateway) ([]namespacedName, error) {
	kingresses, found := gateway.Annotations[annotationKeyKIngresses]
	if !found {
		return nil, fmt.Errorf("cannot read KIngress information from Gateway %s because annotation is missing", gateway.Name)
	}

	var kingressesNamespacedNames []namespacedName
	err := json.Unmarshal([]byte(kingresses), &kingressesNamespacedNames)
	return kingressesNamespacedNames, err
}

// AreAllKIngressesReferencingCertificate checks if the KIngresses that are using a Gateway are all pointing to a Secret with a common certificateHash
func AreAllKIngressesReferencingCertificate(ingressLister knnetlisters.IngressLister, secretLister corev1listers.SecretLister, gateway *istioclient.Gateway, certificateHash string) (bool, error) {
	kingressesNamespacedNames, err := extractSourceKIngresses(gateway)
	if err != nil {
		return false, err
	}

	for _, kingressNamespacedName := range kingressesNamespacedNames {
		kingress, err := ingressLister.Ingresses(kingressNamespacedName.Namespace).Get(kingressNamespacedName.Name)
		if err != nil {
			return false, err
		}

		if len(kingress.Spec.TLS) != 1 {
			return false, fmt.Errorf("KIngress %s/%s is not containing exactly one TLS entry, it contains %d", kingress.Namespace, kingress.Name, len(kingress.Spec.TLS))
		}

		secretName := kingress.Spec.TLS[0].SecretName
		secret, err := secretLister.Secrets(kingressNamespacedName.Namespace).Get(secretName)
		if err != nil {
			return false, err
		}

		secretCertificateHash, err := CalculateCertificateHash(secret)
		if err != nil {
			return false, err
		}

		if certificateHash != secretCertificateHash {
			return false, nil
		}
	}

	return true, nil
}

// GetCertificateHash returns the certificateHash from a Gateway
func GetCertificateHash(gateway *istioclient.Gateway) (string, error) {
	certificateHash, found := gateway.Labels[labelKeyCertificateHash]
	if !found {
		return "", fmt.Errorf("cannot read certificate hash from Gateway %s because label is missing", gateway.Name)
	}
	return certificateHash, nil
}
