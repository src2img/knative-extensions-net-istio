package resources

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"knative.dev/net-istio/pkg/reconciler/ingress/config"
)

const (
	labelKeyDomainMappingSecret   = "codeengine.cloud.ibm.com/domain-mapping-secret"
	labelValueDomainMappingSecret = "true"
)

// CalculateCertificateHash creates the hash of the certificate of the TLS Secret
func CalculateCertificateHash(secret *corev1.Secret) (string, error) {
	certBlock, _ := pem.Decode(secret.Data[corev1.TLSCertKey])
	if certBlock == nil {
		return "", errors.New("failed to decode certificate")
	}
	certSha224 := sha256.Sum224(certBlock.Bytes)
	var certFingerprint bytes.Buffer
	for _, f := range certSha224 {
		fmt.Fprintf(&certFingerprint, "%02x", f)
	}

	return certFingerprint.String(), nil
}

// MakeMirrorSecret creates a Secret object that mirrors a TLS Secret
func MakeMirrorSecret(originSecret *corev1.Secret, certificateHash string) *corev1.Secret {
	return makeSecret(originSecret, certificateHash, config.IstioNamespace, map[string]string{
		labelKeyDomainMappingSecret: labelValueDomainMappingSecret,
	}, map[string]string{})
}
