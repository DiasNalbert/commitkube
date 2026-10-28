package handlers

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func rsOf(name, deploy, rev string, replicas int32) *appsv1.ReplicaSet {
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "rpas", Annotations: map[string]string{revisionAnnotation: rev}},
		Spec: appsv1.ReplicaSetSpec{Replicas: &replicas}}
	if deploy != "" {
		rs.OwnerReferences = []metav1.OwnerReference{{Kind: "Deployment", Name: deploy}}
	}
	return rs
}

// What a delete or a scale will really do depends on this: a retired
// revision is cleanup, the current one takes the service's pods with it.
func TestClassifyReplicaSet(t *testing.T) {
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "rpas", Annotations: map[string]string{revisionAnnotation: "7"}}}
	typed := fake.NewSimpleClientset(d)
	ctx := context.Background()
	cases := []struct {
		rs   *appsv1.ReplicaSet
		want string
	}{
		{rsOf("api-old", "api", "6", 0), "retired"},
		{rsOf("api-new", "api", "7", 2), "current"},
		{rsOf("api-idle", "api", "7", 0), "current"},    // a Deployment scaled to zero: still its revision
		{rsOf("api-rolling", "api", "6", 1), "current"}, // mid-rollout, still serving
		{rsOf("orphan", "gone", "3", 1), "standalone"},  // its Deployment was deleted
		{rsOf("plain", "", "", 1), "standalone"},
	}
	for _, c := range cases {
		if got := classifyReplicaSet(ctx, typed, c.rs); got.Kind != c.want {
			t.Errorf("%s: %s, want %s", c.rs.Name, got.Kind, c.want)
		}
	}
}
