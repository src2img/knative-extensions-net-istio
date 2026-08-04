package ingress

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	istiov1beta1 "istio.io/api/networking/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"knative.dev/net-istio/pkg/reconciler/ingress/resources"
	"knative.dev/networking/pkg/apis/networking/v1alpha1"
	knnetapi "knative.dev/networking/pkg/apis/networking/v1alpha1"
	knnetlisters "knative.dev/networking/pkg/client/listers/networking/v1alpha1"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/system"
)

const (
	annotationTlsMode = "codeengine.cloud.ibm.com/tls-mode"
	tlsModeMutual     = "mutual"
)

// FindKIngresses looks for all KIngresses that are owned by a DomainMapping and reference a TLS Secret in the same namespace
func FindKIngresses(ingressLister knnetlisters.IngressLister, secret *corev1.Secret) ([]*knnetapi.Ingress, error) {
	var ingresses []*knnetapi.Ingress

	allIngresses, err := ingressLister.Ingresses(secret.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	for _, candidate := range allIngresses {
		if isOwnedByDomainMapping(candidate) {
			for _, tls := range candidate.Spec.TLS {
				if tls.SecretName == secret.Name {
					ingresses = append(ingresses, candidate)
					break
				}
			}
		}
	}

	return ingresses, nil
}

func isCleanupOfOldGatewaysEnabled() bool {
	return os.Getenv("DOMAINMAPPING_OLD_GATEWAY_CLEANUP_ENABLED") != "false"
}

func isOwnedByDomainMapping(ing *knnetapi.Ingress) bool {
	if len(ing.OwnerReferences) == 0 {
		return false
	}

	return ing.OwnerReferences[0].Kind == "DomainMapping"
}

func lockCertificate(ctx context.Context, client kubernetes.Interface, certificateHash string, ing *knnetapi.Ingress) (func(), error) {
	logger := logging.FromContext(ctx)

	existingLease, err := client.CoordinationV1().Leases(system.Namespace()).Get(ctx, certificateHash, metav1.GetOptions{})
	if err == nil && existingLease.Spec.HolderIdentity != nil && (existingLease.Spec.AcquireTime == nil || existingLease.Spec.AcquireTime.Time.Add(30*time.Second).Before(time.Now())) {
		// The lock is 30 seconds old, we manually delete it. It will not automatically be released because we will only wait to get the lock for two seconds.
		// The only way to force-release it is therefore by deleting it explicitly.
		if err = client.CoordinationV1().Leases(system.Namespace()).Delete(ctx, certificateHash, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{
				UID:             &existingLease.UID,
				ResourceVersion: &existingLease.ResourceVersion,
			},
		}); err != nil {
			if !apierrs.IsNotFound(err) {
				return nil, err
			}
		} else if existingLease.Spec.HolderIdentity != nil {
			logger.Debugf("Force-released lock held by Ingress %s for %s", *existingLease.Spec.HolderIdentity, certificateHash)
		}
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      certificateHash,
			Namespace: system.Namespace(),
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: fmt.Sprintf("%s/%s", ing.Namespace, ing.Name),
		},
	}

	leaderChan := make(chan bool)
	leaderElector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     150 * time.Millisecond,
		ReleaseOnCancel: true,
		Name:            certificateHash,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				logger.Debugf("Ingress %s/%s acquired lock for %s", ing.Namespace, ing.Name, certificateHash)
				leaderChan <- true
			},
			OnStoppedLeading: func() {
				logger.Debugf("Ingress %s/%s lost lock for %s", ing.Namespace, ing.Name, certificateHash)
			},
			OnNewLeader: func(identity string) {},
		},
	})
	if err != nil {
		return nil, err
	}
	leaderCtx, cancelLeader := context.WithCancel(ctx)

	logger.Debugf("Ingress %s/%s is attempting to acquire lock for %s", ing.Namespace, ing.Name, certificateHash)
	go leaderElector.Run(leaderCtx)

	select {
	case <-leaderChan:
		// good
	case <-time.After(2 * time.Second):
		cancelLeader()
		return nil, fmt.Errorf("unable to acquire lock %s within 2s for %s/%s", certificateHash, ing.Namespace, ing.Name)
	}

	return func() {
		logger.Debugf("Ingress %s/%s is releasing lock for %s", ing.Namespace, ing.Name, certificateHash)
		cancelLeader()
	}, nil
}

func isUnableToAcquireLock(err error) bool {
	return strings.HasPrefix(err.Error(), "unable to acquire lock")
}

func containsCaCrt(secret *corev1.Secret) bool {
	_, found := secret.Data[resources.CaSecretKey]
	return found
}

// TODO: remove looking this up on the secret once UX support is there
func getTlsMode(ing *v1alpha1.Ingress, secret *corev1.Secret) (istiov1beta1.ServerTLSSettings_TLSmode, error) {
	mode, found := ing.Annotations[annotationTlsMode]
	if found && strings.ToLower(mode) == tlsModeMutual { // only mutual supported
		var err error
		if !containsCaCrt(secret) {
			err = errors.New("secret contains no ca bundle")
		}
		return istiov1beta1.ServerTLSSettings_MUTUAL, err
	}
	mode, found = secret.Annotations[annotationTlsMode]
	if found && strings.ToLower(mode) == tlsModeMutual { // only mutual supported
		var err error
		if !containsCaCrt(secret) {
			err = errors.New("secret contains no ca bundle")
		}
		return istiov1beta1.ServerTLSSettings_MUTUAL, err
	}
	return istiov1beta1.ServerTLSSettings_SIMPLE, nil
}
