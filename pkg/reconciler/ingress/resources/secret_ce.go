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
	secret := correctSecretFormat(originSecret)
	return makeSecret(secret, certificateHash, config.IstioNamespace, map[string]string{
		labelKeyDomainMappingSecret: labelValueDomainMappingSecret,
	}, map[string]string{})
}

func decodeAndEncodePEMBlocks(data []byte) []byte {
	var encodedData []byte
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block != nil {
			encodedBlock := pem.EncodeToMemory(block)
			encodedData = append(encodedData, encodedBlock...)
		}
		data = rest
	}
	return encodedData
}

func correctSecretFormat(originSecret *corev1.Secret) *corev1.Secret {
	certificateData := originSecret.Data[corev1.TLSCertKey]
	privateKeyData := originSecret.Data[corev1.TLSPrivateKeyKey]

	encodedCertificate := decodeAndEncodePEMBlocks(certificateData)
	encodedPrivateKey := decodeAndEncodePEMBlocks(privateKeyData)

	secret := originSecret.DeepCopy()
	secret.Data[corev1.TLSCertKey] = encodedCertificate
	secret.Data[corev1.TLSPrivateKeyKey] = encodedPrivateKey

	return secret
}
