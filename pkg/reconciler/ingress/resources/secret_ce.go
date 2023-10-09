package resources

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"knative.dev/net-istio/pkg/reconciler/ingress/config"
	"knative.dev/pkg/logging"
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

func correctSecretFormat(ctx context.Context, originSecret *corev1.Secret) *corev1.Secret {
	var decodeAndEncodePEMBlocks = func(data []byte) (encodedData []byte) {
		rest := data
		for i := 0; len(strings.TrimSpace(string(rest))) > 0; i++ {
			var pemBlock *pem.Block
			pemBlock, rest = pem.Decode(rest)

			// In case the PEM decode fails to decode a block, the result will be nil. This should
			// not happen, but if it does, we return the data as-is and log the incident.
			if pemBlock == nil {
				logging.FromContext(ctx).Errorf("failed to decode PEM block at index %d in secret %s/%s, returning secret data as-is", i, originSecret.Namespace, originSecret.Name)
				return data
			}

			encodedBlock := pem.EncodeToMemory(pemBlock)
			encodedData = append(encodedData, encodedBlock...)
		}

		return encodedData
	}

	certificateData := originSecret.Data[corev1.TLSCertKey]
	privateKeyData := originSecret.Data[corev1.TLSPrivateKeyKey]

	encodedCertificate := decodeAndEncodePEMBlocks(certificateData)
	encodedPrivateKey := decodeAndEncodePEMBlocks(privateKeyData)

	secret := originSecret.DeepCopy()
	secret.Data[corev1.TLSCertKey] = encodedCertificate
	secret.Data[corev1.TLSPrivateKeyKey] = encodedPrivateKey

	return secret
}
