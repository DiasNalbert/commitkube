package handlers

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestPod(ownerKind, ownerName string, controller bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "some-pod",
			Namespace: "prod",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: ownerKind, Name: ownerName, Controller: &controller},
			},
		},
	}
}
