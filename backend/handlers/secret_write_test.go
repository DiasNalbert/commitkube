package handlers

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Editing a Secret an operator owns is the trap worth catching: the change
// appears to work and is reverted on the next refresh, hours later, with
// nothing tying the two events together.
func TestExternalSecretOwnerIsDetected(t *testing.T) {
	owned := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "db-credentials",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ExternalSecret", Name: "db-credentials-es"},
			},
		},
	}
	if got := externalSecretOwner(owned); got != "db-credentials-es" {
		t.Errorf("owner reference not detected, got %q", got)
	}

	annotated := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "api-token",
			Annotations: map[string]string{"reconcile.external-secrets.io/managed": "true"},
		},
	}
	if externalSecretOwner(annotated) == "" {
		t.Error("the managed annotation was not detected")
	}

	plain := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "plain"}}
	if got := externalSecretOwner(plain); got != "" {
		t.Errorf("an unmanaged Secret was reported as managed by %q", got)
	}

	// An owner reference to something else is not an operator taking over.
	otherOwner := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api"}},
		},
	}
	if externalSecretOwner(otherOwner) != "" {
		t.Error("a Deployment owner was mistaken for an ExternalSecret")
	}
}

// Editing a ServiceAccount token by hand does not rotate anything; it breaks
// whatever was using it, and the failure surfaces somewhere else entirely.
func TestSystemSecretTypesAreRefused(t *testing.T) {
	for _, typ := range []corev1.SecretType{
		corev1.SecretTypeServiceAccountToken,
		"bootstrap.kubernetes.io/token",
		"helm.sh/release.v1",
	} {
		if !systemSecretTypes[typ] {
			t.Errorf("%s is editable, and editing it breaks the thing using it", typ)
		}
	}

	for _, typ := range []corev1.SecretType{
		corev1.SecretTypeOpaque,
		corev1.SecretTypeDockerConfigJson,
		corev1.SecretTypeTLS,
	} {
		if systemSecretTypes[typ] {
			t.Errorf("%s is refused, but it is exactly the kind someone needs to edit", typ)
		}
	}
}
