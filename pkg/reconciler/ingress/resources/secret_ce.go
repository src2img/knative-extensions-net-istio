package resources

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"knative.dev/net-istio/pkg/reconciler/ingress/config"
	"knative.dev/pkg/logging"
)

const (
	labelKeyDomainMappingSecret   = "codeengine.cloud.ibm.com/domain-mapping-secret"
	labelValueDomainMappingSecret = "true"
	CaSecretKey                   = "ca.crt"
)

// CalculateCertificateHash creates the hash of the certificate of the TLS Secret
func CalculateCertificateHash(ctx context.Context, secret *corev1.Secret) (string, error) {
	combinedCerts := decodeAndEncodePEMBlocks(ctx, secret.Name, secret.Namespace, secret.Data[corev1.TLSCertKey])

	caCerts, found := secret.Data[CaSecretKey]
	if found {
		decodedCaCerts := decodeAndEncodePEMBlocks(ctx, secret.Name, secret.Namespace, caCerts)
		combinedCerts = append(combinedCerts, decodedCaCerts...)
	}

	certSha224 := sha256.Sum224(combinedCerts)
	var certFingerprint bytes.Buffer
	for _, f := range certSha224 {
		fmt.Fprintf(&certFingerprint, "%02x", f)
	}

	return certFingerprint.String(), nil
}

// MakeMirrorSecret creates a Secret object that mirrors a TLS Secret
func MakeMirrorSecret(ctx context.Context, originSecret *corev1.Secret, certificateHash string) *corev1.Secret {
	return makeSecret(
		correctSecretFormat(ctx, originSecret),
		certificateHash,
		config.IstioNamespace,
		map[string]string{
			labelKeyDomainMappingSecret: labelValueDomainMappingSecret,
		},
		map[string]string{},
	)
}

func decodeAndEncodePEMBlocks(ctx context.Context, name string, namespace string, data []byte) (encodedData []byte) {
	rest := data
	for i := 0; len(strings.TrimSpace(string(rest))) > 0; i++ {
		var pemBlock *pem.Block
		pemBlock, rest = pem.Decode(rest)

		// In case the PEM decode fails to decode a block, the result will be nil. This should
		// not happen, but if it does, we return the data as-is and log the incident.
		if pemBlock == nil {
			logging.FromContext(ctx).Errorf("failed to decode PEM block at index %d in secret %s/%s, returning secret data as-is", i, namespace, name)
			return data
		}

		encodedBlock := pem.EncodeToMemory(pemBlock)
		encodedData = append(encodedData, encodedBlock...)
	}

	return encodedData
}

func correctSecretFormat(ctx context.Context, originSecret *corev1.Secret) *corev1.Secret {

	certificateData := originSecret.Data[corev1.TLSCertKey]
	privateKeyData := originSecret.Data[corev1.TLSPrivateKeyKey]

	secret := originSecret.DeepCopy()

	encodedCertificate := decodeAndEncodePEMBlocks(ctx, originSecret.Name, originSecret.Namespace, certificateData)
	encodedPrivateKey := decodeAndEncodePEMBlocks(ctx, originSecret.Name, originSecret.Namespace, privateKeyData)

	secret.Data[corev1.TLSCertKey] = encodedCertificate
	secret.Data[corev1.TLSPrivateKeyKey] = encodedPrivateKey

	caCertificateData, found := originSecret.Data[CaSecretKey]
	if found {
		secret.Data[CaSecretKey] = decodeAndEncodePEMBlocks(ctx, originSecret.Name, originSecret.Namespace, caCertificateData)
	}

	return secret
}
